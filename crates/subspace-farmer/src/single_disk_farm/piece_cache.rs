//! Cache implementation specific to single disk farm

use crate::disk_piece_cache::DiskPieceCache;
use crate::farm;
use crate::farm::{FarmError, PieceCacheId, PieceCacheOffset};
use async_trait::async_trait;
use futures::{Stream, stream};
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Dedicated piece cache stored on one disk, is used both to accelerate DSN queries and to plot
/// faster
#[derive(Debug, Clone)]
pub struct SingleDiskPieceCache {
    id: PieceCacheId,
    maybe_piece_cache: Option<DiskPieceCache>,
}

#[async_trait]
impl farm::PieceCache for SingleDiskPieceCache {
    fn id(&self) -> &PieceCacheId {
        &self.id
    }

    fn max_num_elements(&self) -> u32 {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            piece_cache.max_num_elements()
        } else {
            0
        }
    }

    async fn contents(
        &self,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<(PieceCacheOffset, Option<PieceIndex>), FarmError>>
                + Unpin
                + Send
                + '_,
        >,
        FarmError,
    > {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::contents(piece_cache).await
        } else {
            Ok(Box::new(stream::empty()))
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

    async fn read_piece(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<(PieceIndex, Piece)>, FarmError> {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::read_piece(piece_cache, offset).await
        } else {
            Ok(None)
        }
    }

    async fn read_pieces(
        &self,
        offsets: Box<dyn Iterator<Item = PieceCacheOffset> + Send>,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<(PieceCacheOffset, Option<(PieceIndex, Piece)>), FarmError>>
                + Send
                + Unpin
                + '_,
        >,
        FarmError,
    > {
        if let Some(piece_cache) = &self.maybe_piece_cache {
            farm::PieceCache::read_pieces(piece_cache, offsets).await
        } else {
            Ok(Box::new(stream::iter(
                offsets.map(|offset| Ok((offset, None))),
            )))
        }
    }
}

impl SingleDiskPieceCache {
    pub(crate) fn new(id: PieceCacheId, maybe_piece_cache: Option<DiskPieceCache>) -> Self {
        Self {
            id,
            maybe_piece_cache,
        }
    }
}
