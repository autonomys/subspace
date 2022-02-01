use crate::rpc::{Error as RpcError, NewHead, RpcClient};
use async_trait::async_trait;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::core::Error as JsonError;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::sync::Arc;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo,
    SolutionResponse,
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
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, RpcError> {
        Ok(self
            .client
            .request("subspace_getFarmerMetadata", rpc_params![])
            .await?)
    }

    async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, RpcError> {
        Ok(self
            .client
            .request("subspace_getBlockByNumber", rpc_params![block_number])
            .await?)
    }

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
            while let Some(Ok(notification)) = subscription.next().await {
                let _ = sender.send(notification).await;
            }
        });

        Ok(receiver)
    }

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
            while let Some(Ok(notification)) = subscription.next().await {
                let _ = sender.send(notification).await;
            }
        });

        Ok(receiver)
    }

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

    async fn subscribe_block_signing(&self) -> Result<mpsc::Receiver<BlockSigningInfo>, RpcError> {
        let mut subscription = self
            .client
            .subscribe(
                "subspace_subscribeBlockSigning",
                rpc_params![],
                "subspace_unsubscribeBlockSigning",
            )
            .await?;

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            while let Some(Ok(notification)) = subscription.next().await {
                let _ = sender.send(notification).await;
            }
        });

        Ok(receiver)
    }

    /// Submit a block signature
    async fn submit_block_signature(
        &self,
        block_signature: BlockSignature,
    ) -> Result<(), RpcError> {
        Ok(self
            .client
            .request(
                "subspace_submitBlockSignature",
                rpc_params![&block_signature],
            )
            .await?)
    }
}
