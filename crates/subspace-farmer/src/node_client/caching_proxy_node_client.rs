//! Node client wrapper around another node client that caches some data for better performance and
//! proxies other requests through

use crate::node_client::{NodeClient, NodeClientExt};
use async_lock::{
    Mutex as AsyncMutex, RwLock as AsyncRwLock,
    RwLockUpgradableReadGuardArc as AsyncRwLockUpgradableReadGuard,
    RwLockWriteGuardArc as AsyncRwLockWriteGuard,
};
use async_trait::async_trait;
use futures::{FutureExt, Stream, StreamExt, select};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_process::AsyncJoinOnDrop;
use subspace_rpc_primitives::{
    FarmerAppInfo, MAX_SEGMENT_HEADERS_PER_REQUEST, RewardSignatureResponse, RewardSigningInfo,
    SlotInfo, SolutionResponse,
};
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tracing::{info, trace, warn};

const SEGMENT_HEADERS_SYNC_INTERVAL: Duration = Duration::from_secs(1);
const FARMER_APP_INFO_DEDUPLICATION_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct SegmentHeaders {
    segment_headers: Vec<SegmentHeader>,
    last_synced: Option<Instant>,
}

impl SegmentHeaders {
    /// Push a new segment header to the cache, if it is the next segment header.
    /// Otherwise, skip the push.
    fn push(&mut self, archived_segment_header: SegmentHeader) {
        if self.segment_headers.len() == u64::from(archived_segment_header.segment_index()) as usize
        {
            self.segment_headers.push(archived_segment_header);
        }
    }

    /// Get cached segment headers for the given segment indices.
    ///
    /// Returns `None` for segment indices that are not in the cache.
    fn get_segment_headers(&self, segment_indices: &[SegmentIndex]) -> Vec<Option<SegmentHeader>> {
        segment_indices
            .iter()
            .map(|segment_index| {
                self.segment_headers
                    .get(u64::from(*segment_index) as usize)
                    .copied()
            })
            .collect::<Vec<_>>()
    }

    /// Get the last `limit` segment headers from the cache.
    fn last_segment_headers(&self, limit: u32) -> Vec<Option<SegmentHeader>> {
        self.segment_headers
            .iter()
            .rev()
            .take(limit as usize)
            .rev()
            .copied()
            .map(Some)
            .collect()
    }

    /// Get uncached headers from the node, if we're not rate-limited.
    /// This only requires a read lock.
    ///
    /// Returns any extra segment headers if the download succeeds, or an error if it fails.
    /// The caller must write the returned segment headers to the cache, and reset the sync
    /// rate-limit timer.
    async fn request_uncached_headers<NC>(&self, client: &NC) -> anyhow::Result<Vec<SegmentHeader>>
    where
        NC: NodeClient,
    {
        // Skip the sync if we're still within the sync rate limit.
        if let Some(last_synced) = &self.last_synced
            && last_synced.elapsed() < SEGMENT_HEADERS_SYNC_INTERVAL
        {
            return Ok(Vec::new());
        }

        let mut extra_segment_headers = Vec::new();
        let mut segment_index_offset = SegmentIndex::from(self.segment_headers.len() as u64);
        let segment_index_step = SegmentIndex::from(MAX_SEGMENT_HEADERS_PER_REQUEST as u64);

        'outer: loop {
            let from = segment_index_offset;
            let to = segment_index_offset + segment_index_step;
            trace!(%from, %to, "Requesting segment headers");

            for maybe_segment_header in client
                .segment_headers((from..to).collect::<Vec<_>>())
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "Failed to download segment headers {from}..{to} from node: {error}"
                    )
                })?
            {
                let Some(segment_header) = maybe_segment_header else {
                    // Reached non-existent segment header
                    break 'outer;
                };

                extra_segment_headers.push(segment_header);
            }

            segment_index_offset += segment_index_step;
        }

        Ok(extra_segment_headers)
    }

    /// Write the sync results to the cache, and reset the sync rate-limit timer.
    fn write_cache(&mut self, extra_segment_headers: Vec<SegmentHeader>) {
        self.segment_headers.extend(extra_segment_headers);
        self.last_synced.replace(Instant::now());
    }
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
    archived_segment_headers_receiver: watch::Receiver<Option<SegmentHeader>>,
    reward_signing_receiver: watch::Receiver<Option<RewardSigningInfo>>,
    segment_headers: Arc<AsyncRwLock<SegmentHeaders>>,
    last_farmer_app_info: Arc<AsyncMutex<(FarmerAppInfo, Instant)>>,
    _background_task: Arc<AsyncJoinOnDrop<()>>,
}

impl<NC> CachingProxyNodeClient<NC>
where
    NC: NodeClient + Clone,
{
    /// Create a new instance
    pub async fn new(client: NC) -> anyhow::Result<Self> {
        let mut segment_headers = SegmentHeaders::default();
        let mut archived_segments_notifications =
            client.subscribe_archived_segment_headers().await?;

        info!("Downloading all segment headers from node...");
        // No locking is needed, we are the first and only instance right now.
        let headers = segment_headers.request_uncached_headers(&client).await?;
        segment_headers.write_cache(headers);
        info!("Downloaded all segment headers from node successfully");

        let segment_headers = Arc::new(AsyncRwLock::new(segment_headers));

        let (slot_info_sender, slot_info_receiver) = watch::channel(None::<SlotInfo>);
        let slot_info_proxy_fut = {
            let mut slot_info_subscription = client.subscribe_slot_info().await?;

            async move {
                let mut last_slot_number = None;
                while let Some(slot_info) = slot_info_subscription.next().await {
                    if let Some(last_slot_number) = last_slot_number
                        && last_slot_number >= slot_info.slot_number
                    {
                        continue;
                    }
                    last_slot_number.replace(slot_info.slot_number);

                    if let Err(error) = slot_info_sender.send(Some(slot_info)) {
                        warn!(%error, "Failed to proxy slot info notification");
                        return;
                    }
                }
            }
        };

        let (archived_segment_headers_sender, archived_segment_headers_receiver) =
            watch::channel(None::<SegmentHeader>);
        let segment_headers_maintenance_fut = {
            let client = client.clone();
            let segment_headers = Arc::clone(&segment_headers);

            async move {
                let mut last_archived_segment_index = None;
                while let Some(archived_segment_header) =
                    archived_segments_notifications.next().await
                {
                    let segment_index = archived_segment_header.segment_index();
                    trace!(
                        ?archived_segment_header,
                        "New archived archived segment header notification"
                    );

                    while let Err(error) = client
                        .acknowledge_archived_segment_header(segment_index)
                        .await
                    {
                        warn!(
                            %error,
                            "Failed to acknowledge archived segment header, trying again"
                        );
                    }

                    if let Some(last_archived_segment_index) = last_archived_segment_index
                        && last_archived_segment_index >= segment_index
                    {
                        continue;
                    }
                    last_archived_segment_index.replace(segment_index);

                    segment_headers.write().await.push(archived_segment_header);

                    if let Err(error) =
                        archived_segment_headers_sender.send(Some(archived_segment_header))
                    {
                        warn!(%error, "Failed to proxy archived segment header notification");
                        return;
                    }
                }
            }
        };

        let (reward_signing_sender, reward_signing_receiver) =
            watch::channel(None::<RewardSigningInfo>);
        let reward_signing_proxy_fut = {
            let mut reward_signing_subscription = client.subscribe_reward_signing().await?;

            async move {
                while let Some(reward_signing_info) = reward_signing_subscription.next().await {
                    if let Err(error) = reward_signing_sender.send(Some(reward_signing_info)) {
                        warn!(%error, "Failed to proxy reward signing notification");
                        return;
                    }
                }
            }
        };

        let farmer_app_info = client
            .farmer_app_info()
            .await
            .map_err(|error| anyhow::anyhow!("Failed to get farmer app info: {error}"))?;
        let last_farmer_app_info = Arc::new(AsyncMutex::new((farmer_app_info, Instant::now())));

        let background_task = tokio::spawn(async move {
            select! {
                _ = slot_info_proxy_fut.fuse() => {},
                _ = segment_headers_maintenance_fut.fuse() => {},
                _ = reward_signing_proxy_fut.fuse() => {},
            }
        });

        let node_client = Self {
            inner: client,
            slot_info_receiver,
            archived_segment_headers_receiver,
            reward_signing_receiver,
            segment_headers,
            last_farmer_app_info,
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
    async fn farmer_app_info(&self) -> anyhow::Result<FarmerAppInfo> {
        let (last_farmer_app_info, last_farmer_app_info_request) =
            &mut *self.last_farmer_app_info.lock().await;

        if last_farmer_app_info_request.elapsed() > FARMER_APP_INFO_DEDUPLICATION_WINDOW {
            let new_last_farmer_app_info = self.inner.farmer_app_info().await?;

            *last_farmer_app_info = new_last_farmer_app_info;
            *last_farmer_app_info_request = Instant::now();
        }

        Ok(last_farmer_app_info.clone())
    }

    async fn subscribe_slot_info(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>> {
        Ok(Box::pin(
            WatchStream::new(self.slot_info_receiver.clone())
                .filter_map(|maybe_slot_info| async move { maybe_slot_info }),
        ))
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> anyhow::Result<()> {
        self.inner.submit_solution_response(solution_response).await
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>> {
        Ok(Box::pin(
            WatchStream::new(self.reward_signing_receiver.clone())
                .filter_map(|maybe_reward_signing_info| async move { maybe_reward_signing_info }),
        ))
    }

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> anyhow::Result<()> {
        self.inner.submit_reward_signature(reward_signature).await
    }

    async fn subscribe_archived_segment_headers(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>> {
        Ok(Box::pin(
            WatchStream::new(self.archived_segment_headers_receiver.clone())
                .filter_map(|maybe_segment_header| async move { maybe_segment_header }),
        ))
    }

    /// Gets segment headers for the given segment indices, updating the cache from the node if
    /// needed.
    ///
    /// Returns `None` for segment indices that are not in the cache.
    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>> {
        let retrieved_segment_headers = self
            .segment_headers
            .read()
            .await
            .get_segment_headers(&segment_indices);

        if retrieved_segment_headers.iter().all(Option::is_some) {
            Ok(retrieved_segment_headers)
        } else {
            // We might be missing a requested segment header.
            // Sync the cache with the node, applying a rate limit, and return cached segment headers.

            // If we took a write lock here, a queue of writers could starve all the readers, even if
            // those writers would be rate-limited. So we take an upgradable read lock for the rate
            // limit check.
            let segment_headers = self.segment_headers.upgradable_read_arc().await;

            // Try again after acquiring the upgradeable read lock, in case another caller already
            // synced the headers.
            let retrieved_segment_headers = segment_headers.get_segment_headers(&segment_indices);
            if retrieved_segment_headers.iter().all(Option::is_some) {
                return Ok(retrieved_segment_headers);
            }

            // Try to sync the cache with the node.
            let extra_segment_headers = segment_headers
                .request_uncached_headers(&self.inner)
                .await?;

            if extra_segment_headers.is_empty() {
                // No extra segment headers on the node, or we are rate-limited.
                // So just return what we have in the cache.
                return Ok(retrieved_segment_headers);
            }

            // We need to update the cached segment headers, so take the write lock.
            let mut segment_headers =
                AsyncRwLockUpgradableReadGuard::upgrade(segment_headers).await;
            segment_headers.write_cache(extra_segment_headers);

            // Downgrade the write lock to a read lock to get the updated segment headers for the
            // query.
            Ok(AsyncRwLockWriteGuard::downgrade(segment_headers)
                .get_segment_headers(&segment_indices))
        }
    }

    async fn piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        self.inner.piece(piece_index).await
    }

    async fn acknowledge_archived_segment_header(
        &self,
        _segment_index: SegmentIndex,
    ) -> anyhow::Result<()> {
        // Not supported
        Ok(())
    }
}

#[async_trait]
impl<NC> NodeClientExt for CachingProxyNodeClient<NC>
where
    NC: NodeClientExt,
{
    async fn cached_segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>> {
        // To avoid remote denial of service, we don't update the cache here, because it is called
        // from network code.
        Ok(self
            .segment_headers
            .read()
            .await
            .get_segment_headers(&segment_indices))
    }

    async fn last_segment_headers(&self, limit: u32) -> anyhow::Result<Vec<Option<SegmentHeader>>> {
        Ok(self
            .segment_headers
            .read()
            .await
            .last_segment_headers(limit))
    }
}
