//! Farming cluster cache
//!
//! Cache is responsible for caching pieces within allocated space to accelerate plotting and serve
//! pieces in response to DSN requests.
//!
//! This module exposes some data structures for NATS communication, custom piece cache
//! implementation designed to work with cluster cache and a service function to drive the backend
//! part of the cache.

use crate::cluster::controller::ClusterControllerCacheIdentifyBroadcast;
use crate::cluster::nats_client::{
    GenericBroadcast, GenericRequest, GenericStreamRequest, NatsClient, StreamRequest,
};
use crate::farm::{FarmError, PieceCache, PieceCacheId, PieceCacheOffset};
use anyhow::anyhow;
use async_nats::Message;
use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::{select, stream, FutureExt, Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use std::future::{pending, Future};
use std::pin::{pin, Pin};
use std::time::{Duration, Instant};
use subspace_core_primitives::{Piece, PieceIndex};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, trace, warn};

const MIN_CACHE_IDENTIFICATION_INTERVAL: Duration = Duration::from_secs(1);

/// Broadcast with identification details by caches
#[derive(Debug, Clone, Encode, Decode)]
pub struct ClusterCacheIdentifyBroadcast {
    /// Cache ID
    pub cache_id: PieceCacheId,
    /// Max number of elements in this cache
    pub max_num_elements: u32,
}

impl GenericBroadcast for ClusterCacheIdentifyBroadcast {
    const SUBJECT: &'static str = "subspace.cache.*.identify";
}

/// Write piece into cache
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterCacheWritePieceRequest {
    offset: PieceCacheOffset,
    piece_index: PieceIndex,
    piece: Piece,
}

impl GenericRequest for ClusterCacheWritePieceRequest {
    const SUBJECT: &'static str = "subspace.cache.*.write-piece";
    type Response = Result<(), String>;
}

/// Read piece index from cache
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterCacheReadPieceIndexRequest {
    offset: PieceCacheOffset,
}

impl GenericRequest for ClusterCacheReadPieceIndexRequest {
    const SUBJECT: &'static str = "subspace.cache.*.read-piece-index";
    type Response = Result<Option<PieceIndex>, String>;
}

/// Read piece from cache
#[derive(Debug, Clone, Encode, Decode)]
pub(super) struct ClusterCacheReadPieceRequest {
    pub(super) offset: PieceCacheOffset,
}

impl GenericRequest for ClusterCacheReadPieceRequest {
    const SUBJECT: &'static str = "subspace.cache.*.read-piece";
    type Response = Result<Option<(PieceIndex, Piece)>, String>;
}

/// Request plotted from farmer, request
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterCacheContentsRequest;

impl GenericStreamRequest for ClusterCacheContentsRequest {
    const SUBJECT: &'static str = "subspace.cache.*.contents";
    type Response = Result<(PieceCacheOffset, Option<PieceIndex>), String>;
}

/// Cluster cache implementation
#[derive(Debug)]
pub struct ClusterPieceCache {
    cache_id: PieceCacheId,
    cache_id_string: String,
    max_num_elements: u32,
    nats_client: NatsClient,
}

#[async_trait]
impl PieceCache for ClusterPieceCache {
    fn id(&self) -> &PieceCacheId {
        &self.cache_id
    }

    #[inline]
    fn max_num_elements(&self) -> u32 {
        self.max_num_elements
    }

    async fn contents(
        &self,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<(PieceCacheOffset, Option<PieceIndex>), FarmError>>
                + Unpin
                + Send
                + '_,
        >,
        FarmError,
    > {
        Ok(Box::new(
            self.nats_client
                .stream_request(ClusterCacheContentsRequest, Some(&self.cache_id_string))
                .await?
                .map(|response| response.map_err(FarmError::from)),
        ))
    }

    async fn write_piece(
        &self,
        offset: PieceCacheOffset,
        piece_index: PieceIndex,
        piece: &Piece,
    ) -> Result<(), FarmError> {
        Ok(self
            .nats_client
            .request(
                &ClusterCacheWritePieceRequest {
                    offset,
                    piece_index,
                    piece: piece.clone(),
                },
                Some(&self.cache_id_string),
            )
            .await??)
    }

    async fn read_piece_index(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<PieceIndex>, FarmError> {
        Ok(self
            .nats_client
            .request(
                &ClusterCacheReadPieceIndexRequest { offset },
                Some(&self.cache_id_string),
            )
            .await??)
    }

    async fn read_piece(
        &self,
        offset: PieceCacheOffset,
    ) -> Result<Option<(PieceIndex, Piece)>, FarmError> {
        Ok(self
            .nats_client
            .request(
                &ClusterCacheReadPieceRequest { offset },
                Some(&self.cache_id_string),
            )
            .await??)
    }
}

impl ClusterPieceCache {
    /// Create new instance using information from previously received
    /// [`ClusterCacheIdentifyBroadcast`]
    #[inline]
    pub fn new(
        cache_id: PieceCacheId,
        max_num_elements: u32,
        nats_client: NatsClient,
    ) -> ClusterPieceCache {
        Self {
            cache_id,
            cache_id_string: cache_id.to_string(),
            max_num_elements,
            nats_client,
        }
    }
}

#[derive(Debug)]
struct CacheDetails<'a, C> {
    cache_id: PieceCacheId,
    cache_id_string: String,
    cache: &'a C,
}

/// Create cache service for specified caches that will be processing incoming requests and send
/// periodic identify notifications
pub async fn cache_service<C>(
    nats_client: NatsClient,
    caches: &[C],
    cache_group: &str,
    identification_broadcast_interval: Duration,
    primary_instance: bool,
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    let caches_details = caches
        .iter()
        .map(|cache| {
            let cache_id = *cache.id();

            if primary_instance {
                info!(%cache_id, max_num_elements = %cache.max_num_elements(), "Created cache");
            }

            CacheDetails {
                cache_id,
                cache_id_string: cache_id.to_string(),
                cache,
            }
        })
        .collect::<Vec<_>>();

    if primary_instance {
        select! {
            result = identify_responder(&nats_client, &caches_details, cache_group, identification_broadcast_interval).fuse() => {
                result
            },
            result = write_piece_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = read_piece_index_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = read_piece_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = contents_responder(&nats_client, &caches_details).fuse() => {
                result
            },
        }
    } else {
        select! {
            result = write_piece_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = read_piece_index_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = read_piece_responder(&nats_client, &caches_details).fuse() => {
                result
            },
            result = contents_responder(&nats_client, &caches_details).fuse() => {
                result
            },
        }
    }
}

/// Listen for cache identification broadcast from controller and publish identification
/// broadcast in response, also send periodic notifications reminding that cache exists.
///
/// Implementation is using concurrency with multiple tokio tasks, but can be started multiple times
/// per controller instance in order to parallelize more work across threads if needed.
async fn identify_responder<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
    cache_group: &str,
    identification_broadcast_interval: Duration,
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    let mut subscription = nats_client
        .subscribe_to_broadcasts::<ClusterControllerCacheIdentifyBroadcast>(
            Some(cache_group),
            Some(cache_group.to_string()),
        )
        .await
        .map_err(|error| {
            anyhow!("Failed to subscribe to cache identify broadcast requests: {error}")
        })?
        .fuse();

    // Also send periodic updates in addition to the subscription response
    let mut interval = tokio::time::interval(identification_broadcast_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut last_identification = Instant::now();

    loop {
        select! {
            maybe_message = subscription.next() => {
                let Some(message) = maybe_message else {
                    debug!("Identify broadcast stream ended");
                    break;
                };

                trace!(?message, "Cache received identify broadcast message");

                if last_identification.elapsed() < MIN_CACHE_IDENTIFICATION_INTERVAL {
                    // Skip too frequent identification requests
                    continue;
                }

                last_identification = Instant::now();
                send_identify_broadcast(nats_client, caches_details).await;
                interval.reset();
            }
            _ = interval.tick().fuse() => {
                last_identification = Instant::now();
                trace!("Cache self-identification");

                send_identify_broadcast(nats_client, caches_details).await;
            }
        }
    }

    Ok(())
}

async fn send_identify_broadcast<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
) where
    C: PieceCache,
{
    caches_details
        .iter()
        .map(|cache| async move {
            if let Err(error) = nats_client
                .broadcast(
                    &ClusterCacheIdentifyBroadcast {
                        cache_id: cache.cache_id,
                        max_num_elements: cache.cache.max_num_elements(),
                    },
                    &cache.cache_id_string,
                )
                .await
            {
                warn!(
                    cache_id = %cache.cache_id,
                    %error,
                    "Failed to send cache identify notification"
                );
            }
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;
}

async fn write_piece_responder<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    caches_details
        .iter()
        .map(|cache_details| async move {
            // Initialize with pending future so it never ends
            let mut processing =
                FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
                    Box::pin(pending()) as Pin<Box<_>>,
                ]);
            let subscription = nats_client
                .queue_subscribe(
                    ClusterCacheWritePieceRequest::SUBJECT
                        .replace('*', &cache_details.cache_id_string),
                    cache_details.cache_id_string.clone(),
                )
                .await
                .map_err(|error| {
                    anyhow!(
                        "Failed to subscribe to write piece requests for cache {}: {}",
                        cache_details.cache_id,
                        error
                    )
                })?;
            debug!(?subscription, "Write piece requests subscription");
            let mut subscription = subscription.fuse();

            loop {
                select! {
                    maybe_message = subscription.next() => {
                        let Some(message) = maybe_message else {
                            break;
                        };

                        // Create background task for concurrent processing
                        processing.push(Box::pin(process_write_piece_request(
                            nats_client,
                            cache_details,
                            message,
                        )));
                    }
                    _ = processing.next() => {
                        // Nothing to do here
                    }
                }
            }

            Ok(())
        })
        .collect::<FuturesUnordered<_>>()
        .next()
        .await
        .ok_or_else(|| anyhow!("No caches"))?
}

async fn process_write_piece_request<C>(
    nats_client: &NatsClient,
    cache_details: &CacheDetails<'_, C>,
    message: Message,
) where
    C: PieceCache,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    let ClusterCacheWritePieceRequest {
        offset,
        piece_index,
        piece,
    } = match ClusterCacheWritePieceRequest::decode(&mut message.payload.as_ref()) {
        Ok(request) => request,
        Err(error) => {
            warn!(
                %error,
                message = %hex::encode(message.payload),
                "Failed to decode write piece request"
            );
            return;
        }
    };

    trace!(%offset, %piece_index, %reply_subject, "Write piece request");

    let response: <ClusterCacheWritePieceRequest as GenericRequest>::Response = cache_details
        .cache
        .write_piece(offset, piece_index, &piece)
        .await
        .map_err(|error| error.to_string());

    if let Err(error) = nats_client
        .publish(reply_subject, response.encode().into())
        .await
    {
        warn!(%error, "Failed to send write piece response");
    }
}

async fn read_piece_index_responder<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    caches_details
        .iter()
        .map(|cache_details| async move {
            // Initialize with pending future so it never ends
            let mut processing =
                FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
                    Box::pin(pending()) as Pin<Box<_>>,
                ]);
            let subscription = nats_client
                .queue_subscribe(
                    ClusterCacheReadPieceIndexRequest::SUBJECT
                        .replace('*', &cache_details.cache_id_string),
                    cache_details.cache_id_string.clone(),
                )
                .await
                .map_err(|error| {
                    anyhow!(
                        "Failed to subscribe to read piece index requests for cache {}: {}",
                        cache_details.cache_id,
                        error
                    )
                })?;
            debug!(?subscription, "Read piece index requests subscription");
            let mut subscription = subscription.fuse();

            loop {
                select! {
                    maybe_message = subscription.next() => {
                        let Some(message) = maybe_message else {
                            break;
                        };

                        // Create background task for concurrent processing
                        processing.push(Box::pin(process_read_piece_index_request(
                            nats_client,
                            cache_details,
                            message,
                        )));
                    }
                    _ = processing.next() => {
                        // Nothing to do here
                    }
                }
            }

            Ok(())
        })
        .collect::<FuturesUnordered<_>>()
        .next()
        .await
        .ok_or_else(|| anyhow!("No caches"))?
}

async fn process_read_piece_index_request<C>(
    nats_client: &NatsClient,
    cache_details: &CacheDetails<'_, C>,
    message: Message,
) where
    C: PieceCache,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    let ClusterCacheReadPieceIndexRequest { offset } =
        match ClusterCacheReadPieceIndexRequest::decode(&mut message.payload.as_ref()) {
            Ok(request) => request,
            Err(error) => {
                warn!(
                    %error,
                    message = %hex::encode(message.payload),
                    "Failed to decode read piece index request"
                );
                return;
            }
        };

    trace!(%offset, %reply_subject, "Read piece index request");

    let response: <ClusterCacheReadPieceIndexRequest as GenericRequest>::Response = cache_details
        .cache
        .read_piece_index(offset)
        .await
        .map_err(|error| error.to_string());

    if let Err(error) = nats_client
        .publish(reply_subject, response.encode().into())
        .await
    {
        warn!(%error, "Failed to send read piece index response");
    }
}

async fn read_piece_responder<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    caches_details
        .iter()
        .map(|cache_details| async move {
            // Initialize with pending future so it never ends
            let mut processing =
                FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
                    Box::pin(pending()) as Pin<Box<_>>,
                ]);
            let subscription = nats_client
                .queue_subscribe(
                    ClusterCacheReadPieceRequest::SUBJECT
                        .replace('*', &cache_details.cache_id_string),
                    cache_details.cache_id_string.clone(),
                )
                .await
                .map_err(|error| {
                    anyhow!(
                        "Failed to subscribe to read piece requests for cache {}: {}",
                        cache_details.cache_id,
                        error
                    )
                })?;
            debug!(?subscription, "Read piece requests subscription");
            let mut subscription = subscription.fuse();

            loop {
                select! {
                    maybe_message = subscription.next() => {
                        let Some(message) = maybe_message else {
                            break;
                        };

                        // Create background task for concurrent processing
                        processing.push(Box::pin(process_read_piece_request(
                            nats_client,
                            cache_details,
                            message,
                        )));
                    }
                    _ = processing.next() => {
                        // Nothing to do here
                    }
                }
            }

            Ok(())
        })
        .collect::<FuturesUnordered<_>>()
        .next()
        .await
        .ok_or_else(|| anyhow!("No caches"))?
}

async fn process_read_piece_request<C>(
    nats_client: &NatsClient,
    cache_details: &CacheDetails<'_, C>,
    message: Message,
) where
    C: PieceCache,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    let ClusterCacheReadPieceRequest { offset } =
        match ClusterCacheReadPieceRequest::decode(&mut message.payload.as_ref()) {
            Ok(request) => request,
            Err(error) => {
                warn!(
                    %error,
                    message = %hex::encode(message.payload),
                    "Failed to decode read piece request"
                );
                return;
            }
        };

    trace!(%offset, %reply_subject, "Read piece request");

    let response: <ClusterCacheReadPieceRequest as GenericRequest>::Response = cache_details
        .cache
        .read_piece(offset)
        .await
        .map_err(|error| error.to_string());

    if let Err(error) = nats_client
        .publish(reply_subject, response.encode().into())
        .await
    {
        warn!(%error, "Failed to send read piece response");
    }
}

async fn contents_responder<C>(
    nats_client: &NatsClient,
    caches_details: &[CacheDetails<'_, C>],
) -> anyhow::Result<()>
where
    C: PieceCache,
{
    caches_details
        .iter()
        .map(|cache_details| async move {
            // Initialize with pending future so it never ends
            let mut processing = FuturesUnordered::from_iter([
                Box::pin(pending()) as Pin<Box<dyn Future<Output = ()> + Send>>
            ]);
            let mut subscription = nats_client
                .subscribe_to_stream_requests(
                    Some(&cache_details.cache_id_string),
                    Some(cache_details.cache_id_string.clone()),
                )
                .await
                .map_err(|error| {
                    anyhow!(
                        "Failed to subscribe to contents requests for cache {}: {}",
                        cache_details.cache_id,
                        error
                    )
                })?
                .fuse();

            loop {
                select! {
                    maybe_message = subscription.next() => {
                        let Some(message) = maybe_message else {
                            break;
                        };

                        // Create background task for concurrent processing
                        processing.push(Box::pin(process_contents_request(
                            nats_client,
                            cache_details,
                            message,
                        )));
                    }
                    _ = processing.next() => {
                        // Nothing to do here
                    }
                }
            }

            Ok(())
        })
        .collect::<FuturesUnordered<_>>()
        .next()
        .await
        .ok_or_else(|| anyhow!("No caches"))?
}

async fn process_contents_request<C>(
    nats_client: &NatsClient,
    cache_details: &CacheDetails<'_, C>,
    request: StreamRequest<ClusterCacheContentsRequest>,
) where
    C: PieceCache,
{
    trace!(?request, "Contents request");

    match cache_details.cache.contents().await {
        Ok(contents) => {
            nats_client
                .stream_response::<ClusterCacheContentsRequest, _>(
                    request.response_subject,
                    contents.map(|maybe_cache_element| {
                        maybe_cache_element.map_err(|error| error.to_string())
                    }),
                )
                .await;
        }
        Err(error) => {
            error!(
                %error,
                cache_id = %cache_details.cache_id,
                "Failed to get contents"
            );

            nats_client
                .stream_response::<ClusterCacheContentsRequest, _>(
                    request.response_subject,
                    pin!(stream::once(async move {
                        Err(format!("Failed to get contents: {error}"))
                    })),
                )
                .await;
        }
    }
}
