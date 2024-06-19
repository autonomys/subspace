//! Node client wrapper around another node client that caches some data for better performance and
//! proxies other requests through

use crate::node_client::{Error as RpcError, Error, NodeClient};
use crate::utils::AsyncJoinOnDrop;
use async_lock::RwLock as AsyncRwLock;
use async_trait::async_trait;
use futures::{select, FutureExt, Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
    MAX_SEGMENT_HEADERS_PER_REQUEST,
};
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tracing::{info, trace, warn};

async fn sync_segment_headers<NC>(
    segment_headers: &mut Vec<SegmentHeader>,
    client: &NC,
) -> Result<(), Error>
where
    NC: NodeClient,
{
    let mut segment_index_offset = SegmentIndex::from(segment_headers.len() as u64);
    let segment_index_step = SegmentIndex::from(MAX_SEGMENT_HEADERS_PER_REQUEST as u64);

    'outer: loop {
        let from = segment_index_offset;
        let to = segment_index_offset + segment_index_step;
        trace!(%from, %to, "Requesting segment headers");

        for maybe_segment_header in client
            .segment_headers((from..to).collect::<Vec<_>>())
            .await
            .map_err(|error| {
                format!("Failed to download segment headers {from}..{to} from node: {error}")
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

    Ok(())
}

/// Node client wrapper around another node client that caches some data for better performance and
/// proxies other requests through.
///
/// NOTE: Archived segment acknowledgement is ignored in this client, all subscriptions are
/// acknowledged implicitly and immediately.
/// NOTE: Subscription messages that are not processed in time will be skipped for performance
/// reasons!
#[derive(Debug, Clone)]
pub struct CachingProxyNodeClient<NC> {
    inner: NC,
    slot_info_receiver: watch::Receiver<Option<SlotInfo>>,
    segment_headers: Arc<AsyncRwLock<Vec<SegmentHeader>>>,
    _background_task: Arc<AsyncJoinOnDrop<()>>,
}

impl<NC> CachingProxyNodeClient<NC>
where
    NC: NodeClient + Clone,
{
    /// Create a new instance
    pub async fn new(client: NC) -> Result<Self, Error> {
        let mut segment_headers = Vec::<SegmentHeader>::new();
        let mut archived_segments_notifications =
            client.subscribe_archived_segment_headers().await?;

        info!("Downloading all segment headers from node...");
        sync_segment_headers(&mut segment_headers, &client).await?;
        info!("Downloaded all segment headers from node successfully");

        let segment_headers = Arc::new(AsyncRwLock::new(segment_headers));

        let (slot_info_sender, slot_info_receiver) = watch::channel(None::<SlotInfo>);
        let slot_info_proxy_fut = {
            let mut slot_info_subscription = client.subscribe_slot_info().await?;

            async move {
                while let Some(slot_info) = slot_info_subscription.next().await {
                    if let Err(error) = slot_info_sender.send(Some(slot_info)) {
                        warn!(%error, "Failed to proxy slot info notification");
                        return;
                    }
                }
            }
        };
        let segment_headers_maintenance_fut = {
            let client = client.clone();
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
                        .acknowledge_archived_segment_header(
                            archived_segment_header.segment_index(),
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
        };

        let background_task = tokio::spawn(async move {
            select! {
                _ = slot_info_proxy_fut.fuse() => {},
                _ = segment_headers_maintenance_fut.fuse() => {},
            }
        });

        let node_client = Self {
            inner: client,
            slot_info_receiver,
            segment_headers,
            _background_task: Arc::new(AsyncJoinOnDrop::new(background_task, true)),
        };

        Ok(node_client)
    }
}

#[async_trait]
impl<NC> NodeClient for CachingProxyNodeClient<NC>
where
    NC: NodeClient,
{
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, Error> {
        self.inner.farmer_app_info().await
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, RpcError> {
        Ok(Box::pin(
            WatchStream::new(self.slot_info_receiver.clone())
                .filter_map(|maybe_slot_info| async move { maybe_slot_info }),
        ))
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), RpcError> {
        self.inner.submit_solution_response(solution_response).await
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, RpcError> {
        self.inner.subscribe_reward_signing().await
    }

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), RpcError> {
        self.inner.submit_reward_signature(reward_signature).await
    }

    async fn subscribe_archived_segment_headers(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, RpcError> {
        self.inner.subscribe_archived_segment_headers().await
    }

    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, RpcError> {
        let retrieved_segment_headers = {
            let segment_headers = self.segment_headers.read().await;

            segment_indices
                .iter()
                .map(|segment_index| {
                    segment_headers
                        .get(u64::from(*segment_index) as usize)
                        .copied()
                })
                .collect::<Vec<_>>()
        };

        if retrieved_segment_headers.iter().all(Option::is_some) {
            Ok(retrieved_segment_headers)
        } else {
            // Re-sync segment headers
            let mut segment_headers = self.segment_headers.write().await;
            sync_segment_headers(&mut segment_headers, &self.inner).await?;

            Ok(segment_indices
                .iter()
                .map(|segment_index| {
                    segment_headers
                        .get(u64::from(*segment_index) as usize)
                        .copied()
                })
                .collect::<Vec<_>>())
        }
    }

    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, RpcError> {
        self.inner.piece(piece_index).await
    }

    async fn acknowledge_archived_segment_header(
        &self,
        _segment_index: SegmentIndex,
    ) -> Result<(), Error> {
        // Not supported
        Ok(())
    }
}
