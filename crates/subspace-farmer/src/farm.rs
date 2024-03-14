use crate::single_disk_farm::farming::FarmingNotification;
use crate::single_disk_farm::plot_cache::MaybePieceStoredResult;
use crate::single_disk_farm::SectorUpdate;
use async_trait::async_trait;
use derive_more::{Display, From};
use futures::Stream;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, PieceOffset, SectorIndex};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_networking::libp2p::kad::RecordKey;
use subspace_rpc_primitives::SolutionResponse;
use ulid::Ulid;

/// Erased error type
pub type FarmError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;

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

/// Opaque handler ID for event handlers, once dropped handler will be removed automatically
pub trait HandlerId: Send + fmt::Debug {
    /// Consumes [`HandlerId`] and prevents handler from being removed automatically.
    fn detach(&self);
}

impl HandlerId for event_listener_primitives::HandlerId {
    fn detach(&self) {
        self.detach();
    }
}

/// An identifier for a farm, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Display, From,
)]
#[serde(untagged)]
pub enum FarmId {
    /// Farm ID
    Ulid(Ulid),
}

#[allow(clippy::new_without_default)]
impl FarmId {
    /// Creates new ID
    pub fn new() -> Self {
        Self::Ulid(Ulid::new())
    }
}

/// Abstract farm implementation
#[async_trait(?Send)]
pub trait Farm {
    /// ID of this farm
    fn id(&self) -> &FarmId;

    /// Number of sectors in this farm
    fn total_sectors_count(&self) -> SectorIndex;

    /// Number of sectors successfully plotted so far
    async fn plotted_sectors_count(&self) -> Result<SectorIndex, FarmError>;

    /// Read information about sectors plotted so far
    async fn plotted_sectors(
        &self,
    ) -> Result<Box<dyn Stream<Item = Result<PlottedSector, FarmError>> + Unpin + '_>, FarmError>;

    /// Get piece cache instance
    fn piece_cache(&self) -> Arc<dyn PieceCache + 'static>;

    /// Get plot cache instance
    fn plot_cache(&self) -> Arc<dyn PlotCache + 'static>;

    /// Get piece reader to read plotted pieces later
    fn piece_reader(&self) -> Arc<dyn PieceReader + 'static>;

    /// Subscribe to sector updates
    fn on_sector_update(
        &self,
        callback: HandlerFn<(SectorIndex, SectorUpdate)>,
    ) -> Box<dyn HandlerId>;

    /// Subscribe to farming notifications
    fn on_farming_notification(
        &self,
        callback: HandlerFn<FarmingNotification>,
    ) -> Box<dyn HandlerId>;

    /// Subscribe to new solution notification
    fn on_solution(&self, callback: HandlerFn<SolutionResponse>) -> Box<dyn HandlerId>;

    /// Run and wait for background threads to exit or return an error
    fn run(self: Box<Self>) -> Pin<Box<dyn Future<Output = anyhow::Result<FarmId>> + Send>>;
}
