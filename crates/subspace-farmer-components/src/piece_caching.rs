use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndexHash};
use tracing::trace;

const CACHE_ITEMS_LIMIT: NonZeroUsize = NonZeroUsize::new(10000).expect("Manually set value > 0."); // TODO: adjust after piece size change

#[derive(Clone)]
pub struct PieceMemoryCache {
    cache: Arc<Mutex<LruCache<PieceIndexHash, Piece>>>,
}
impl Default for PieceMemoryCache {
    fn default() -> Self {
        Self::new(CACHE_ITEMS_LIMIT)
    }
}

impl PieceMemoryCache {
    pub fn new(items_limit: NonZeroUsize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(items_limit))),
        }
    }

    pub fn add_piece(&self, piece_index_hash: PieceIndexHash, piece: Piece) {
        self.cache.lock().put(piece_index_hash, piece);
    }

    pub fn add_pieces(&self, pieces: Vec<(PieceIndexHash, Piece)>) {
        let mut cache = self.cache.lock();

        for (piece_index_hash, piece) in pieces {
            cache.put(piece_index_hash, piece);
        }
    }

    pub fn get_piece(&self, piece_index_hash: &PieceIndexHash) -> Option<Piece> {
        let piece = self.cache.lock().get(piece_index_hash).cloned();

        if piece.is_some() {
            trace!(?piece_index_hash, "Piece memory cache hit.");
        }

        piece
    }
}
