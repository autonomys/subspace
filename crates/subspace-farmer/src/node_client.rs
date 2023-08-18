pub(crate) mod node_rpc_client;

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, NodeSyncStatus, RewardSignatureResponse, RewardSigningInfo, SlotInfo,
    SolutionResponse,
};

/// To become error type agnostic
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Abstraction of the Node Client
#[async_trait]
pub trait NodeClient: Clone + Send + Sync + 'static {
    /// Get farmer app info
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, Error>;

    /// Subscribe to slot
    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, Error>;

    /// Submit a slot solution
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;

    /// Subscribe to block signing request
    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, Error>;

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error>;

    /// Subscribe to archived segment headers
    async fn subscribe_archived_segment_headers(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, Error>;

    /// Subscribe to node sync status change
    async fn subscribe_node_sync_status_change(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NodeSyncStatus> + Send + 'static>>, Error>;

    /// Get segment headers for the segments
    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error>;

    /// Get piece by index.
    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Error>;

    /// Acknowledge segment header.
    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error>;

    /// Get the last segment headers.
    async fn last_segment_headers(&self, limit: u64) -> Result<Vec<Option<SegmentHeader>>, Error>;
}
