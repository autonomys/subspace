use async_trait::async_trait;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc;

/// To become error type agnostic
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Abstraction of the Remote Procedure Call Client
#[async_trait]
pub trait RpcClient: Clone + Send + Sync + 'static {
    /// Get farmer metadata
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error>;

    /// Subscribe to slot
    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, Error>;

    /// Submit a slot solution
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;

    /// Subscribe to block signing request
    async fn subscribe_block_signing(&self) -> Result<mpsc::Receiver<BlockSigningInfo>, Error>;

    /// Submit a block signature
    async fn submit_block_signature(&self, block_signature: BlockSignature) -> Result<(), Error>;

    /// Subscribe to archived segments
    async fn subscribe_archived_segments(&self) -> Result<mpsc::Receiver<ArchivedSegment>, Error>;

    /// Acknowledge receiving of archived segments
    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), Error>;
}
