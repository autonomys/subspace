//! Miscellaneous utilities for networking.

pub mod multihash;
pub mod piece_provider;
pub(crate) mod prometheus;
#[cfg(test)]
mod tests;
pub(crate) mod unique_record_binary_heap;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Notify;
use tracing::warn;

/// This test is successful only for global IP addresses and DNS names.
pub(crate) fn is_global_address_or_dns(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_global(),
        Some(Protocol::Ip6(ip)) => ip.is_global(),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => true,
        _ => false,
    }
}

// Generic collection batching helper.
#[derive(Clone)]
pub(crate) struct CollectionBatcher<T: Clone> {
    last_batch_number: usize,
    batch_size: NonZeroUsize,
    _marker: PhantomData<T>,
}

impl<T: Clone> CollectionBatcher<T> {
    /// Constructor
    pub fn new(batch_size: NonZeroUsize) -> Self {
        Self {
            batch_size,
            last_batch_number: 0,
            _marker: PhantomData,
        }
    }

    /// Sets the last batch number to zero.
    pub fn reset(&mut self) {
        self.last_batch_number = 0;
    }

    /// Extract the next batch from the collection
    pub fn next_batch(&mut self, collection: Vec<T>) -> Vec<T> {
        // Collection is empty or less than batch size.
        if collection.is_empty() || collection.len() < self.batch_size.get() {
            return collection;
        }

        let skip_number = {
            let skip_number = self.last_batch_number * self.batch_size.get();

            // Correction when skip_number exceeds the collection length.
            if skip_number >= collection.len() {
                skip_number % collection.len()
            } else {
                skip_number
            }
        };

        self.last_batch_number += 1;

        collection
            .iter()
            .cloned()
            .cycle()
            .skip(skip_number)
            .take(self.batch_size.get())
            .collect::<Vec<_>>()
    }
}

// Convenience alias for peer ID and its multiaddresses.
pub(crate) type PeerAddress = (PeerId, Multiaddr);

// Helper function. Converts multiaddresses to a tuple with peer ID removing the peer Id suffix.
// It logs incorrect multiaddresses.
pub(crate) fn convert_multiaddresses(addresses: Vec<Multiaddr>) -> Vec<PeerAddress> {
    addresses
        .into_iter()
        .filter_map(|multiaddr| {
            let mut modified_multiaddr = multiaddr.clone();

            let peer_id: Option<PeerId> = modified_multiaddr.pop().and_then(|protocol| {
                if let Protocol::P2p(peer_id) = protocol {
                    peer_id.try_into().ok()
                } else {
                    None
                }
            });

            if let Some(peer_id) = peer_id {
                Some((peer_id, modified_multiaddr))
            } else {
                warn!(%multiaddr, "Incorrect multiaddr provided.");

                None
            }
        })
        .collect()
}

/// Errors happening during semaphore usage
#[derive(Debug, Error)]
pub(crate) enum SemaphoreError {
    #[error("Invalid shrink: capacity {capacity}, delta {delta}")]
    InvalidShrink {
        /// The current capacity
        capacity: usize,
        /// How much to shrink
        delta: usize,
    },
    #[error("Invalid expand: capacity {capacity}, delta {delta}")]
    InvalidExpand {
        /// The current capacity
        capacity: usize,
        /// How much to expand
        delta: usize,
    },
}

/// The state shared between the semaphore and the outstanding permits.
#[derive(Debug)]
struct SemShared {
    /// The tuple holds (current usage, current max capacity)
    state: Mutex<SemState>,
    /// To signal waiters for permits to be available
    notify: Notify,
}

/// The semaphore state.
#[derive(Debug)]
struct SemState {
    /// The current capacity
    capacity: usize,
    /// The current outstanding permits
    usage: usize,
}

impl SemState {
    // Allocates a permit if available.
    // Returns true if allocated, false otherwise.
    fn alloc_one(&mut self) -> bool {
        if self.usage < self.capacity {
            self.usage += 1;
            true
        } else {
            false
        }
    }

    // Returns a free permit to the free pool.
    // Returns true if any waiters need to be notified.
    fn free_one(&mut self) -> bool {
        let prev_is_full = self.is_full();
        if let Some(dec) = self.usage.checked_sub(1) {
            self.usage = dec;
        } else {
            unreachable!("Dropping semaphore twice is not possible");
        }

        // Notify if we did a full -> available transition.
        prev_is_full && !self.is_full()
    }

    // Expands the max capacity by delta.
    // Returns true if any waiters need to be notified.
    fn expand(&mut self, delta: usize) -> Result<bool, SemaphoreError> {
        let prev_is_full = self.is_full();
        if let Some(capacity) = self.capacity.checked_add(delta) {
            self.capacity = capacity;
            // Notify if we did a full -> available transition.
            Ok(prev_is_full && !self.is_full())
        } else {
            Err(SemaphoreError::InvalidExpand {
                capacity: self.capacity,
                delta,
            })
        }
    }

    // Shrinks the max capacity by delta.
    fn shrink(&mut self, delta: usize) -> Result<(), SemaphoreError> {
        if let Some(capacity) = self.capacity.checked_sub(delta) {
            self.capacity = capacity;
            Ok(())
        } else {
            Err(SemaphoreError::InvalidShrink {
                capacity: self.capacity,
                delta,
            })
        }
    }

    // Returns true if current usage exceeds capacity
    fn is_full(&self) -> bool {
        self.usage >= self.capacity
    }
}

/// Semaphore like implementation that allows both shrinking and expanding
/// the max permits.
#[derive(Clone, Debug)]
pub(crate) struct ResizableSemaphore(Arc<SemShared>);

impl ResizableSemaphore {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        let shared = SemShared {
            state: Mutex::new(SemState {
                capacity: capacity.get(),
                usage: 0,
            }),
            notify: Notify::new(),
        };
        Self(Arc::new(shared))
    }

    // Acquires a permit. Waits until a permit is available.
    pub(crate) async fn acquire(&self) -> ResizableSemaphorePermit {
        loop {
            let wait = {
                let mut state = self.0.state.lock();
                if state.alloc_one() {
                    None
                } else {
                    // This needs to be done under the lock to avoid race.
                    Some(self.0.notify.notified())
                }
            };

            match wait {
                Some(notified) => notified.await,
                None => break,
            }
        }
        ResizableSemaphorePermit(self.0.clone())
    }

    // Acquires a permit, doesn't wait for permits to be available.
    // Currently used only for tests.
    #[cfg(test)]
    pub(crate) fn try_acquire(&self) -> Option<ResizableSemaphorePermit> {
        let mut state = self.0.state.lock();
        if state.alloc_one() {
            Some(ResizableSemaphorePermit(self.0.clone()))
        } else {
            None
        }
    }

    // Expands the capacity by the specified amount.
    pub(crate) fn expand(&self, delta: usize) -> Result<(), SemaphoreError> {
        let notify_waiters = self.0.state.lock().expand(delta)?;
        if notify_waiters {
            self.0.notify.notify_waiters();
        }

        Ok(())
    }

    // Shrinks the capacity by the specified amount.
    pub(crate) fn shrink(&self, delta: usize) -> Result<(), SemaphoreError> {
        self.0.state.lock().shrink(delta)
    }
}

/// The semaphore permit.
#[derive(Clone, Debug)]
pub(crate) struct ResizableSemaphorePermit(Arc<SemShared>);

impl Drop for ResizableSemaphorePermit {
    fn drop(&mut self) {
        let notify_waiters = self.0.state.lock().free_one();
        if notify_waiters {
            self.0.notify.notify_waiters();
        }
    }
}
