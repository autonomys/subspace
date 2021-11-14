use crate::rpc::{Error as RpcError, NewHead, RpcClient};
use async_trait::async_trait;
use jsonrpsee::rpc_params;
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::Error as JsonError;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::sync::Arc;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc;

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct WsRpc {
    client: Arc<WsClient>,
}

impl WsRpc {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }
}

#[async_trait]
impl RpcClient for WsRpc {
    /// Get farmer metadata.
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, RpcError> {
        Ok(self
            .client
            .request("subspace_getFarmerMetadata", rpc_params![])
            .await?)
    }

    /// Get a block by number.
    async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, RpcError> {
        Ok(self
            .client
            .request("subspace_getBlockByNumber", rpc_params![block_number])
            .await?)
    }

    /// Subscribe to chain head.
    async fn subscribe_new_head(&self) -> Result<mpsc::Receiver<NewHead>, RpcError> {
        let mut subscription = self
            .client
            .subscribe(
                "chain_subscribeNewHead",
                rpc_params![],
                "chain_unsubscribeNewHead",
            )
            .await?;

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            while let Ok(Some(notification)) = subscription.next().await {
                let _ = sender.send(notification).await;
            }
        });

        Ok(receiver)
    }

    /// Subscribe to slot.
    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, RpcError> {
        let mut subscription = self
            .client
            .subscribe(
                "subspace_subscribeSlotInfo",
                rpc_params![],
                "subspace_unsubscribeSlotInfo",
            )
            .await?;

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            while let Ok(Some(notification)) = subscription.next().await {
                let _ = sender.send(notification).await;
            }
        });

        Ok(receiver)
    }

    /// Submit a slot solution.
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), RpcError> {
        Ok(self
            .client
            .request(
                "subspace_submitSolutionResponse",
                rpc_params![&solution_response],
            )
            .await?)
    }
}
