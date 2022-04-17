use crate::rpc_client::{Error as RpcError, RpcClient};
use async_trait::async_trait;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::core::Error as JsonError;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::BlockNumber;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct NodeRpcClient {
    client: Arc<WsClient>,
}

impl NodeRpcClient {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }
}

#[async_trait]
impl RpcClient for NodeRpcClient {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, RpcError> {
        Ok(self
            .client
            .request("subspace_getFarmerMetadata", rpc_params![])
            .await?)
    }

    async fn best_block_number(&self) -> Result<BlockNumber, RpcError> {
        Ok(self
            .client
            .request("subspace_getBestBlockNumber", rpc_params![])
            .await?)
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

    async fn subscribe_archived_segments(&self) -> Result<Receiver<ArchivedSegment>, RpcError> {
        let mut subscription = self
            .client
            .subscribe(
                "subspace_subscribeArchivedSegment",
                rpc_params![],
                "subspace_unsubscribeArchivedSegment",
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

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), RpcError> {
        Ok(self
            .client
            .request(
                "subspace_acknowledgeArchivedSegment",
                rpc_params![&segment_index],
            )
            .await?)
    }
}
