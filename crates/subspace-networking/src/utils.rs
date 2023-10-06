//! Miscellaneous utilities for networking.

pub mod multihash;
pub mod piece_provider;
pub(crate) mod prometheus;
pub(crate) mod rate_limiter;
#[cfg(test)]
mod tests;
pub(crate) mod unique_record_binary_heap;

use event_listener_primitives::Bag;
use futures::future::{Fuse, FusedFuture, FutureExt};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::future::Future;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::runtime::Handle;
use tokio::task;
use tracing::warn;

/// Joins async join handle on drop
pub(crate) struct AsyncJoinOnDrop<T>(Option<Fuse<task::JoinHandle<T>>>);

impl<T> Drop for AsyncJoinOnDrop<T> {
    fn drop(&mut self) {
        let handle = self.0.take().expect("Always called exactly once; qed");
        if !handle.is_terminated() {
            task::block_in_place(move || {
                let _ = Handle::current().block_on(handle);
            });
        }
    }
}

impl<T> AsyncJoinOnDrop<T> {
    // Create new instance
    pub(crate) fn new(handle: task::JoinHandle<T>) -> Self {
        Self(Some(handle.fuse()))
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(self.0.as_mut().expect("Only dropped in Drop impl; qed")).poll(cx)
    }
}

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

/// Helper function. Converts multiaddresses to a tuple with peer ID removing the peer Id suffix.
/// It logs incorrect multiaddresses.
pub fn strip_peer_id(addresses: Vec<Multiaddr>) -> Vec<PeerAddress> {
    addresses
        .into_iter()
        .filter_map(|multiaddr| {
            let mut modified_multiaddr = multiaddr.clone();

            let peer_id: Option<PeerId> = modified_multiaddr.pop().and_then(|protocol| {
                if let Protocol::P2p(peer_id) = protocol {
                    Some(peer_id)
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

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
pub(crate) type Handler<A> = Bag<HandlerFn<A>, A>;
