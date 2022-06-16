use crate::rpc_client::{Error as RpcError, RpcClient};
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::core::Error as JsonError;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_rpc_primitives::{
    FarmerMetadata, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

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

    async fn total_pieces(&self) -> Result<u64, RpcError> {
        Ok(self
            .client
            .request("subspace_getTotalPieces", rpc_params![])
            .await?)
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, RpcError> {
        let subscription = self
            .client
            .subscribe(
                "subspace_subscribeSlotInfo",
                rpc_params![],
                "subspace_unsubscribeSlotInfo",
            )
            .await?;

        Ok(Box::pin(subscription.filter_map(
            |slot_info_result| async move { slot_info_result.ok() },
        )))
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

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, RpcError> {
        let subscription = self
            .client
            .subscribe(
                "subspace_subscribeRewardSigning",
                rpc_params![],
                "subspace_unsubscribeRewardSigning",
            )
            .await?;

        Ok(Box::pin(subscription.filter_map(
            |reward_signing_info_result| async move { reward_signing_info_result.ok() },
        )))
    }

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), RpcError> {
        Ok(self
            .client
            .request(
                "subspace_submitRewardSignature",
                rpc_params![&reward_signature],
            )
            .await?)
    }

    async fn subscribe_archived_segments(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ArchivedSegment> + Send + 'static>>, RpcError> {
        let subscription = self
            .client
            .subscribe(
                "subspace_subscribeArchivedSegment",
                rpc_params![],
                "subspace_unsubscribeArchivedSegment",
            )
            .await?;

        Ok(Box::pin(subscription.filter_map(
            |archived_segment_result| async move { archived_segment_result.ok() },
        )))
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
