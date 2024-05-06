use crate::node_client::{Error as RpcError, Error, NodeClient, NodeClientExt};
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use jsonrpsee::core::client::{ClientT, Error as JsonError, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tokio::sync::Semaphore;

/// Defines max_concurrent_requests constant in the node rpc client
const RPC_MAX_CONCURRENT_REQUESTS: usize = 1_000_000;
/// Node is having a hard time responding for many piece requests
// TODO: Remove this once https://github.com/paritytech/jsonrpsee/issues/1189 is resolved
const MAX_CONCURRENT_PIECE_REQUESTS: usize = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_mins(5);

/// `WsClient` wrapper.
#[derive(Debug, Clone)]
pub struct NodeRpcClient {
    client: Arc<WsClient>,
    piece_request_semaphore: Arc<Semaphore>,
}

impl NodeRpcClient {
    /// Create a new instance of [`NodeClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(
            WsClientBuilder::default()
                .max_concurrent_requests(RPC_MAX_CONCURRENT_REQUESTS)
                .max_request_size(20 * 1024 * 1024)
                .request_timeout(REQUEST_TIMEOUT)
                .build(url)
                .await?,
        );
        let piece_request_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PIECE_REQUESTS));
        Ok(Self {
            client,
            piece_request_semaphore,
        })
    }
}

#[async_trait]
impl NodeClient for NodeRpcClient {
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, Error> {
        Ok(self
            .client
            .request("subspace_getFarmerAppInfo", rpc_params![])
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

    async fn subscribe_archived_segment_headers(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, RpcError> {
        let subscription = self
            .client
            .subscribe(
                "subspace_subscribeArchivedSegmentHeader",
                rpc_params![],
                "subspace_unsubscribeArchivedSegmentHeader",
            )
            .await?;

        Ok(Box::pin(subscription.filter_map(
            |archived_segment_header_result| async move { archived_segment_header_result.ok() },
        )))
    }

    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        Ok(self
            .client
            .request("subspace_segmentHeaders", rpc_params![&segment_indexes])
            .await?)
    }

    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, RpcError> {
        let _permit = self.piece_request_semaphore.acquire().await?;
        let result: Option<Vec<u8>> = self
            .client
            .request("subspace_piece", rpc_params![&piece_index])
            .await?;

        if let Some(bytes) = result {
            let piece = Piece::try_from(bytes.as_slice())
                .map_err(|_| format!("Cannot convert piece. PieceIndex={}", piece_index))?;

            return Ok(Some(piece));
        }

        Ok(None)
    }

    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error> {
        Ok(self
            .client
            .request(
                "subspace_acknowledgeArchivedSegmentHeader",
                rpc_params![&segment_index],
            )
            .await?)
    }
}

#[async_trait]
impl NodeClientExt for NodeRpcClient {
    async fn last_segment_headers(
        &self,
        limit: u64,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        Ok(self
            .client
            .request("subspace_lastSegmentHeaders", rpc_params![limit])
            .await?)
    }
}
