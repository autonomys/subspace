pub mod circular_buffer;
pub mod multihash;
#[cfg(test)]
mod tests;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
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
