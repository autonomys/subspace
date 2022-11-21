pub(crate) mod node_rpc_client;

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{Piece, PieceIndex, RecordsRoot, SegmentIndex};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_rpc_primitives::{
    RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

/// To become error type agnostic
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Abstraction of the Remote Procedure Call Client
#[async_trait]
pub trait RpcClient: Clone + Send + Sync + 'static {
    /// Get farmer metadata
    async fn farmer_protocol_info(&self) -> Result<FarmerProtocolInfo, Error>;

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

    /// Subscribe to archived segments
    async fn subscribe_archived_segments(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ArchivedSegment> + Send + 'static>>, Error>;

    /// Get records roots for the segments
    async fn records_roots(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<RecordsRoot>>, Error>;

    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Error>;
}
