pub(crate) mod node_rpc_client;

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{RecordsRoot, RootBlock, SegmentIndex};
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
    ) -> Result<Pin<Box<dyn Stream<Item = ArchivedSegment> + Send + 'static>>, Error>;

    /// Get records roots for the segments
    async fn records_roots(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<RecordsRoot>>, Error>;

    /// Get root blocks for the segments
    async fn root_blocks(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<RootBlock>>, Error>;
}
