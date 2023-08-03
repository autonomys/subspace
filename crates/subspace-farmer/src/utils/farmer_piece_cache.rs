use crate::utils::parity_db_store::ParityDbStore;
use crate::utils::piece_cache::PieceCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_core_primitives::Piece;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::PeerId;
use subspace_networking::UniqueRecordBinaryHeap;
use tracing::{debug, trace, warn};

/// Piece cache with limited size where pieces closer to provided peer ID are retained.
#[derive(Clone)]
pub struct FarmerPieceCache {
    // Underlying unbounded store.
    store: ParityDbStore<Key, Piece>,
    // Maintains a heap to limit total number of entries.
    heap: Arc<Mutex<UniqueRecordBinaryHeap>>,
}

impl FarmerPieceCache {
    pub fn new(
        store: ParityDbStore<Key, Piece>,
        max_items_limit: NonZeroUsize,
        peer_id: PeerId,
    ) -> Self {
        let mut heap = UniqueRecordBinaryHeap::new(peer_id, max_items_limit.get());

        match store.iter() {
            Ok(pieces_iter) => {
                for (key, _) in pieces_iter {
                    let _ = heap.insert(key);
                }

                if heap.size() > 0 {
                    debug!(size = heap.size(), "Local piece cache loaded.");
                } else {
                    debug!("New local piece cache initialized.");
                }
            }
            Err(err) => {
                warn!(?err, "Local pieces from Parity DB iterator failed.");
            }
        }

        Self {
            store,
            heap: Arc::new(Mutex::new(heap)),
        }
    }

    pub fn size(&self) -> usize {
        self.heap.lock().size()
    }
}

impl PieceCache for FarmerPieceCache {
    fn should_cache(&self, key: &Key) -> bool {
        self.heap.lock().should_include_key(key.clone())
    }

    fn add_piece(&mut self, key: Key, piece: Piece) {
        self.store.update([(&key, Some(piece.into()))]);

        let evicted_key = self.heap.lock().insert(key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.store.update([(&key, None)]);
        }
    }

    fn get_piece(&self, key: &Key) -> Option<Piece> {
        self.store.get(key)
    }

    fn contains_key(&self, key: &Key) -> bool {
        self.heap.lock().contains_key(key.clone())
    }
}
