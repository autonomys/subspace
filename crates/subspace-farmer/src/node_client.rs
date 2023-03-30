pub(crate) mod node_rpc_client;

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::{SegmentCommitment, SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
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

    /// Subscribe to archived segments
    async fn subscribe_archived_segments(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NewArchivedSegment> + Send + 'static>>, Error>;

    /// Get segment commitments for the segments
    async fn segment_commitments(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentCommitment>>, Error>;

    /// Get segment headers for the segments
    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error>;
}
