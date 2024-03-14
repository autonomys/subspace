use crate::single_disk_farm::plot_cache::MaybePieceStoredResult;
use async_trait::async_trait;
use derive_more::Display;
use futures::Stream;
use parity_scale_codec::{Decode, Encode};
use std::fmt;
use subspace_core_primitives::{Piece, PieceIndex, PieceOffset, SectorIndex};
use subspace_networking::libp2p::kad::RecordKey;

/// Erased error type
pub type FarmError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Offset wrapper for pieces in [`PieceCache`]
#[derive(Debug, Display, Copy, Clone, Encode, Decode)]
#[repr(transparent)]
pub struct PieceCacheOffset(pub(crate) u32);

/// Abstract piece cache implementation
#[async_trait]
pub trait PieceCache: Send + Sync + fmt::Debug {
    /// Max number of elements in this cache
    fn max_num_elements(&self) -> usize;

    /// Contents of this piece cache.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    async fn contents(
        &self,
    ) -> Box<dyn Stream<Item = (PieceCacheOffset, Option<PieceIndex>)> + Unpin + '_>;

    /// Store piece in cache at specified offset, replacing existing piece if there is any.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    async fn write_piece(
        &self,
        offset: PieceCacheOffset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), FarmError>;

    /// Read piece index from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    async fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, FarmError>;

    /// Read piece from cache at specified offset.
    ///
    /// Returns `None` if offset is out of range.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    async fn read_piece(&self, offset: PieceCacheOffset) -> Result<Option<Piece>, FarmError>;
}

/// Abstract plot cache implementation
#[async_trait]
pub trait PlotCache: Send + Sync + fmt::Debug {
    /// Check if piece is potentially stored in this cache (not guaranteed to be because it might be
    /// overridden with sector any time)
    async fn is_piece_maybe_stored(
        &self,
        key: &RecordKey,
    ) -> Result<MaybePieceStoredResult, FarmError>;

    /// Store piece in cache if there is free space, otherwise `Ok(false)` is returned
    async fn try_store_piece(
        &self,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<bool, FarmError>;

    /// Read piece from cache.
    ///
    /// Returns `None` if not cached.
    async fn read_piece(&self, key: &RecordKey) -> Result<Option<Piece>, FarmError>;
}

/// Abstract piece reader implementation
#[async_trait]
pub trait PieceReader: Send + Sync + fmt::Debug {
    /// Read piece from sector by offset, `None` means input parameters are incorrect or piece
    /// reader was shut down
    async fn read_piece(
        &self,
        sector_index: SectorIndex,
        piece_offset: PieceOffset,
    ) -> Result<Option<Piece>, FarmError>;
}
