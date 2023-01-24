use crate::utils::parity_db_store::ParityDbStore;
use crate::utils::piece_cache::PieceCache;
use std::num::NonZeroUsize;
use subspace_core_primitives::Piece;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::PeerId;
use subspace_networking::RecordBinaryHeap;
use tracing::{info, trace, warn};

/// Piece cache with limited size where pieces closer to provided peer ID are retained.
pub struct FarmerPieceCache {
    // Underlying unbounded store.
    store: ParityDbStore,
    // Maintains a heap to limit total number of entries.
    heap: RecordBinaryHeap,
}

impl FarmerPieceCache {
    pub fn new(store: ParityDbStore, max_items_limit: NonZeroUsize, peer_id: PeerId) -> Self {
        let mut heap = RecordBinaryHeap::new(peer_id, max_items_limit.get());

        match store.iter::<Vec<u8>>() {
            Ok(pieces_iter) => {
                for (key, _) in pieces_iter {
                    let _ = heap.insert(key);
                }

                if heap.size() > 0 {
                    info!(size = heap.size(), "Local piece cache loaded.");
                } else {
                    info!("New local piece cache initialized.");
                }
            }
            Err(err) => {
                warn!(?err, "Local pieces from Parity DB iterator failed.");
            }
        }

        Self { store, heap }
    }
}

impl PieceCache for FarmerPieceCache {
    fn should_cache(&self, key: &Key) -> bool {
        self.heap.should_include_key(key)
    }

    fn add_piece(&mut self, key: Key, piece: Piece) {
        self.store.update([(&key, Some(piece.into()))]);

        let evicted_key = self.heap.insert(key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.store.update([(&key, None)]);
        }
    }

    fn get_piece(&self, key: &Key) -> Option<Piece> {
        self.store.get(key)
    }
}
