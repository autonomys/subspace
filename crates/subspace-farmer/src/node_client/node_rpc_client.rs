use crate::node_client::{Error as RpcError, Error, NodeClient, NodeClientExt};
use crate::utils::AsyncJoinOnDrop;
use async_lock::{RwLock as AsyncRwLock, Semaphore};
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use jsonrpsee::core::client::{ClientT, Error as JsonError, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
    MAX_SEGMENT_HEADERS_PER_REQUEST,
};
use tracing::{info, trace, warn};

/// TODO: Node is having a hard time responding for many piece requests, specifically this results
///  in subscriptions become broken on the node: https://github.com/paritytech/jsonrpsee/issues/1409
const MAX_CONCURRENT_PIECE_REQUESTS: usize = 10;

/// `WsClient` wrapper.
#[derive(Debug, Clone)]
pub struct NodeRpcClient {
    client: Arc<WsClient>,
    piece_request_semaphore: Arc<Semaphore>,
    segment_headers: Arc<AsyncRwLock<Vec<SegmentHeader>>>,
    _background_task: Arc<AsyncJoinOnDrop<()>>,
}

impl NodeRpcClient {
    /// Create a new instance of [`NodeClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(
            WsClientBuilder::default()
                .max_request_size(20 * 1024 * 1024)
                .build(url)
                .await?,
        );
        let piece_request_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PIECE_REQUESTS));

        let mut segment_headers = Vec::<SegmentHeader>::new();
        let mut archived_segments_notifications = Box::pin(
            client
                .subscribe::<SegmentHeader, _>(
                    "subspace_subscribeArchivedSegmentHeader",
                    rpc_params![],
                    "subspace_unsubscribeArchivedSegmentHeader",
                )
                .await?
                .filter_map(|archived_segment_header_result| async move {
                    archived_segment_header_result.ok()
                }),
        );

        info!("Downloading all segment headers from node...");
        {
            let mut segment_index_offset = SegmentIndex::from(segment_headers.len() as u64);
            let segment_index_step = SegmentIndex::from(MAX_SEGMENT_HEADERS_PER_REQUEST as u64);

            'outer: loop {
                let from = segment_index_offset;
                let to = segment_index_offset + segment_index_step;
                trace!(%from, %to, "Requesting segment headers");

                for maybe_segment_header in client
                    .request::<Vec<Option<SegmentHeader>>, _>(
                        "subspace_segmentHeaders",
                        rpc_params![&(from..to).collect::<Vec<_>>()],
                    )
                    .await
                    .map_err(|error| {
                        JsonError::Custom(format!(
                            "Failed to download segment headers {from}..{to} from node: {error}"
                        ))
                    })?
                {
                    let Some(segment_header) = maybe_segment_header else {
                        // Reached non-existent segment header
                        break 'outer;
                    };

                    if segment_headers.len() == u64::from(segment_header.segment_index()) as usize {
                        segment_headers.push(segment_header);
                    }
                }

                segment_index_offset += segment_index_step;
            }
        }
        info!("Downloaded all segment headers from node successfully");

        let segment_headers = Arc::new(AsyncRwLock::new(segment_headers));
        let background_task = tokio::spawn({
            let client = Arc::clone(&client);
            let segment_headers = Arc::clone(&segment_headers);

            async move {
                while let Some(archived_segment_header) =
                    archived_segments_notifications.next().await
                {
                    trace!(
                        ?archived_segment_header,
                        "New archived archived segment header notification"
                    );

                    let mut segment_headers = segment_headers.write().await;
                    if segment_headers.len()
                        == u64::from(archived_segment_header.segment_index()) as usize
                    {
                        segment_headers.push(archived_segment_header);
                    }

                    while let Err(error) = client
                        .request::<(), _>(
                            "subspace_acknowledgeArchivedSegmentHeader",
                            rpc_params![&archived_segment_header.segment_index()],
                        )
                        .await
                    {
                        warn!(
                            %error,
                            "Failed to acknowledge archived segment header, trying again"
                        );
                    }
                }
            }
        });

        let node_client = Self {
            client,
            piece_request_semaphore,
            segment_headers,
            _background_task: Arc::new(AsyncJoinOnDrop::new(background_task, true)),
        };

        Ok(node_client)
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
        segment_indices: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        let segment_headers = self.segment_headers.read().await;
        Ok(segment_indices
            .into_iter()
            .map(|segment_index| {
                segment_headers
                    .get(u64::from(segment_index) as usize)
                    .copied()
            })
            .collect())
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
