use crate::farm;
use crate::farm::{FarmError, PieceCacheOffset};
use crate::piece_cache::PieceCache;
use async_trait::async_trait;
use futures::{stream, Stream};
use subspace_core_primitives::{Piece, PieceIndex};

/// Dedicated piece cache stored on one disk, is used both to accelerate DSN queries and to plot
/// faster
#[derive(Debug, Clone)]
pub struct DiskPieceCache {
    maybe_piece_cache: Option<PieceCache>,
}

#[async_trait]
impl farm::PieceCache for DiskPieceCache {
    fn max_num_elements(&self) -> usize {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            piece_cache.max_num_elements()
        } else {
            0
        }
    }

    async fn contents(
        &self,
    ) -> Box<dyn Stream<Item = (PieceCacheOffset, Option<PieceIndex>)> + Unpin + '_> {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::contents(piece_cache).await
        } else {
            Box::new(stream::empty())
        }
    }

    async fn write_piece(
        &self,
        offset: PieceCacheOffset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), FarmError> {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::write_piece(piece_cache, offset, piece_index, piece).await
        } else {
            Err("Can't write pieces into empty cache".into())
        }
    }

    async fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, FarmError> {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::read_piece_index(piece_cache, offset).await
        } else {
            Ok(None)
        }
    }

    async fn read_piece(&self, offset: PieceCacheOffset) -> Result<Option<Piece>, FarmError> {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::read_piece(piece_cache, offset).await
        } else {
            Ok(None)
        }
    }
}

impl DiskPieceCache {
    pub(crate) fn new(maybe_piece_cache: Option<PieceCache>) -> Self {
        Self { maybe_piece_cache }
    }
}
