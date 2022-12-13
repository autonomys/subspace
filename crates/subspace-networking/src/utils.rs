pub mod multihash;
pub(crate) mod prometheus;
#[cfg(test)]
mod tests;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
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

/// Semaphore like implementation that allows both shrinking and expanding
/// the max permits.
#[derive(Clone)]
pub(crate) struct ResizableSemaphore {
    state: Arc<SemState>,
}

/// The semaphore permit.
#[derive(Clone)]
pub(crate) struct ResizableSemaphorePermit {
    state: Arc<SemState>,
}

/// The state shared between the semaphore and the outstanding permits.
struct SemState {
    /// The tuple holds (current usage, current max capacity)
    current: Mutex<(usize, usize)>,

    /// To signal waiters for permits to be available.
    notify: Notify,
}

impl SemState {
    fn new(capacity: usize) -> Self {
        Self {
            current: Mutex::new((0, capacity)),
            notify: Notify::new(),
        }
    }

    // Allocates a permit if available.
    // Returns true if a permit was allocated, false otherwise
    async fn alloc_one(&self) -> bool {
        let mut current = self.current.lock().await; // (usage, capacity)
        if current.0 < current.1 {
            current.0 += 1;
            true
        } else {
            false
        }
    }

    // Returns a permit to the free pool, notifies waiters if needed.
    async fn free_one(&self) {
        let should_notify = {
            let mut current = self.current.lock().await; // (usage, capacity)
            assert!(current.0 > 0);
            current.0 -= 1;

            // Notify only if usage fell below the current capacity.
            // For example: if the previous capacity was 100, and current capacity
            // is 50, this will wait for usage to fall below 50 before any waiters
            // are notified.
            current.0 < current.1
        };
        if should_notify {
            self.notify.notify_waiters();
        }
    }

    // Expands the max capacity by delta, and notifies any waiters of the newly available
    // free permits.
    async fn expand(&self, delta: usize) {
        {
            let mut current = self.current.lock().await; // (usage, capacity)
            current.1 += delta;
        }
        self.notify.notify_waiters();
    }

    // Shrinks the max capacity by delta
    async fn shrink(&self, delta: usize) {
        let mut current = self.current.lock().await; // (usage, capacity)
        assert!(current.1 > delta);
        current.1 -= delta;
    }
}

impl ResizableSemaphore {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(SemState::new(capacity)),
        }
    }

    /// Acquires a permit.
    pub(crate) async fn acquire(&self) -> ResizableSemaphorePermit {
        loop {
            if self.state.alloc_one().await {
                break;
            }
            self.state.notify.notified().await;
        }
        ResizableSemaphorePermit {
            state: self.state.clone(),
        }
    }

    /// Expands the capacity by specified amount.
    pub(crate) async fn expand(&self, delta: usize) {
        self.state.expand(delta).await;
    }

    /// Shrinks the capacity by specified amount.
    pub(crate) async fn shrink(&self, delta: usize) {
        self.state.shrink(delta).await;
    }
}

impl Drop for ResizableSemaphorePermit {
    fn drop(&mut self) {
        let state = self.state.clone();
        tokio::spawn({
            async move {
                state.free_one().await;
            }
        });
    }
}
