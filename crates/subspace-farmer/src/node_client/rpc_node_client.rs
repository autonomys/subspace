//! Node client implementation that connects to node via RPC (WebSockets)

use crate::node_client::{Error as RpcError, Error, NodeClient, NodeClientExt};
use async_lock::Semaphore;
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use jsonrpsee::core::client::{ClientT, Error as JsonError, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::SegmentHeader;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

/// TODO: Node is having a hard time responding for many piece requests, specifically this results
///  in subscriptions become broken on the node: https://github.com/paritytech/jsonrpsee/issues/1409
///  This needs to be removed after Substrate upgrade when we can take advantage of new Substrate
///  API that will prevent subscription breakage:
///  https://github.com/paritytech/jsonrpsee/issues/1409#issuecomment-2303914643
const MAX_CONCURRENT_PIECE_REQUESTS: usize = 10;

/// Node client implementation that connects to node via RPC (WebSockets).
///
/// This implementation is supposed to be used on local network and not via public Internet due to
/// sensitive contents.
#[derive(Debug, Clone)]
pub struct RpcNodeClient {
    client: Arc<WsClient>,
    piece_request_semaphore: Arc<Semaphore>,
}

impl RpcNodeClient {
    /// Create a new instance of [`NodeClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(
            WsClientBuilder::default()
                .max_request_size(20 * 1024 * 1024)
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
impl NodeClient for RpcNodeClient {
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
        segment_indices: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        Ok(self
            .client
            .request("subspace_segmentHeaders", rpc_params![&segment_indices])
            .await?)
    }

    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, RpcError> {
        let _permit = self.piece_request_semaphore.acquire().await;
        let client = Arc::clone(&self.client);
        // Spawn a separate task to improve concurrency due to slow-ish JSON decoding that causes
        // issues for jsonrpsee
        let piece_fut = tokio::task::spawn(async move {
            client
                .request("subspace_piece", rpc_params![&piece_index])
                .await
        });
        Ok(piece_fut.await??)
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
impl NodeClientExt for RpcNodeClient {
    async fn last_segment_headers(
        &self,
        limit: u32,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        Ok(self
            .client
            .request("subspace_lastSegmentHeaders", rpc_params![limit])
            .await?)
    }
}
