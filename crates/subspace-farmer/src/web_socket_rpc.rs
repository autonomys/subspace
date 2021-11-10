use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::{Error, Subscription};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde::Deserialize;
use std::sync::Arc;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};

// There are more fields in this struct, but we only care about one
#[derive(Debug, Deserialize)]
pub(super) struct NewHead {
    pub number: String,
}

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct WebSocketRpc {
    client: Arc<WsClient>,
}

impl WebSocketRpc {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self, Error> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }

    /// Get farmer metadata.
    pub(super) async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error> {
        self.client
            .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
            .await
    }

    /// Get a block by number.
    pub(super) async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, Error> {
        self.client
            .request(
                "subspace_getBlockByNumber",
                JsonRpcParams::Array(vec![serde_json::to_value(block_number)?]),
            )
            .await
    }

    /// Subscribe to chain head.
    pub(super) async fn subscribe_new_head(&self) -> Result<Subscription<NewHead>, Error> {
        self.client
            .subscribe(
                "chain_subscribeNewHead",
                JsonRpcParams::NoParams,
                "chain_unsubscribeNewHead",
            )
            .await
    }

    /// Subscribe to slot.
    pub(super) async fn subscribe_slot_info(&self) -> Result<Subscription<SlotInfo>, Error> {
        self.client
            .subscribe(
                "subspace_subscribeSlotInfo",
                JsonRpcParams::NoParams,
                "subspace_unsubscribeSlotInfo",
            )
            .await
    }

    /// Submit a slot solution.
    pub(super) async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error> {
        self.client
            .request(
                "subspace_submitSolutionResponse",
                JsonRpcParams::Array(vec![serde_json::to_value(&solution_response)?]),
            )
            .await
    }
}
