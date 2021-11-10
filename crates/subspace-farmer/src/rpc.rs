use async_trait::async_trait;
use jsonrpsee::types::{Error, Subscription};
use serde::Deserialize;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};

// There are more fields in this struct, but we only care about one
#[derive(Debug, Deserialize)]
pub struct NewHead {
    pub number: String,
}

#[async_trait]
pub trait RpcClient {
    /// Get farmer metadata.
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error>;

    async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, Error>;

    async fn subscribe_new_head(&self) -> Result<Subscription<NewHead>, Error>;

    async fn subscribe_slot_info(&self) -> Result<Subscription<SlotInfo>, Error>;

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;
}
