use async_trait::async_trait;
use serde::Deserialize;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc::Receiver;

// There are more fields in this struct, but we only care about one
#[derive(Debug, Deserialize)]
pub struct NewHead {
    pub number: String,
}

/// To become error type agnostic
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[async_trait]
pub trait RpcClient {
    /// Get farmer metadata.
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error>;

    /// Get a block by number.
    async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, Error>;

    /// Subscribe to chain head.
    async fn subscribe_new_head(&self) -> Result<Receiver<NewHead>, Error>;

    /// Subscribe to slot.
    async fn subscribe_slot_info(&self) -> Result<Receiver<SlotInfo>, Error>;

    /// Submit a slot solution.
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;
}
