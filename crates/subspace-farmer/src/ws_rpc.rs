use crate::rpc::{NewHead, RpcClient};
use async_trait::async_trait;
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::{Error, Subscription};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::sync::Arc;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct WsRpc {
    client: Arc<WsClient>,
}

impl WsRpc {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self, Error> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }
}

#[async_trait]
impl RpcClient for WsRpc {
    /// Get farmer metadata.
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error> {
        self.client
            .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
            .await
    }

    /// Get a block by number.
    async fn block_by_number(
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
    async fn subscribe_new_head(&self) -> Result<Subscription<NewHead>, Error> {
        self.client
            .subscribe(
                "chain_subscribeNewHead",
                JsonRpcParams::NoParams,
                "chain_unsubscribeNewHead",
            )
            .await
    }

    /// Subscribe to slot.
    async fn subscribe_slot_info(&self) -> Result<Subscription<SlotInfo>, Error> {
        self.client
            .subscribe(
                "subspace_subscribeSlotInfo",
                JsonRpcParams::NoParams,
                "subspace_unsubscribeSlotInfo",
            )
            .await
    }

    /// Submit a slot solution.
    async fn submit_solution_response(
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
