//! Farming cluster controller
//!
//! Controller is responsible for managing farming cluster.
//!
//! This module exposes some data structures for NATS communication, custom piece getter and node
//! client implementations designed to work with cluster controller and a service function to drive
//! the backend part of the controller.

use crate::cluster::cache::{
    ClusterCacheIndex, ClusterCacheReadPieceRequest, ClusterCacheReadPiecesRequest,
};
use crate::cluster::nats_client::{
    GenericBroadcast, GenericNotification, GenericRequest, GenericStreamRequest, NatsClient,
};
use crate::farm::{PieceCacheId, PieceCacheOffset};
use crate::farmer_cache::FarmerCache;
use crate::node_client::NodeClient;
use anyhow::anyhow;
use async_nats::HeaderValue;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::FusedFuture;
use futures::stream::FuturesUnordered;
use futures::{select, stream, FutureExt, Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_farmer_components::PieceGetter;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tracing::{debug, error, trace, warn};

/// Broadcast sent by controllers requesting farmers to identify themselves
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct ClusterControllerFarmerIdentifyBroadcast;

impl GenericBroadcast for ClusterControllerFarmerIdentifyBroadcast {
    const SUBJECT: &'static str = "subspace.controller.farmer-identify";
}

/// Broadcast sent by controllers requesting caches in cache group to identify themselves
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct ClusterControllerCacheIdentifyBroadcast;

impl GenericBroadcast for ClusterControllerCacheIdentifyBroadcast {
    /// `*` here stands for cache group
    const SUBJECT: &'static str = "subspace.controller.*.cache-identify";
}

/// Broadcast with slot info sent by controllers
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerSlotInfoBroadcast {
    slot_info: SlotInfo,
    instance: String,
}

impl GenericBroadcast for ClusterControllerSlotInfoBroadcast {
    const SUBJECT: &'static str = "subspace.controller.slot-info";

    fn deterministic_message_id(&self) -> Option<HeaderValue> {
        // TODO: Depending on answer in `https://github.com/nats-io/nats.docs/issues/663` this might
        //  be simplified to just a slot number
        Some(HeaderValue::from(
            format!("slot-info-{}", self.slot_info.slot_number).as_str(),
        ))
    }
}

/// Broadcast with reward signing info by controllers
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerRewardSigningBroadcast {
    reward_signing_info: RewardSigningInfo,
}

impl GenericBroadcast for ClusterControllerRewardSigningBroadcast {
    const SUBJECT: &'static str = "subspace.controller.reward-signing-info";
}

/// Broadcast with archived segment headers by controllers
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerArchivedSegmentHeaderBroadcast {
    archived_segment_header: SegmentHeader,
}

impl GenericBroadcast for ClusterControllerArchivedSegmentHeaderBroadcast {
    const SUBJECT: &'static str = "subspace.controller.archived-segment-header";

    fn deterministic_message_id(&self) -> Option<HeaderValue> {
        // TODO: Depending on answer in `https://github.com/nats-io/nats.docs/issues/663` this might
        //  be simplified to just a segment index
        Some(HeaderValue::from(
            format!(
                "archived-segment-{}",
                self.archived_segment_header.segment_index()
            )
            .as_str(),
        ))
    }
}

/// Notification messages with solution by farmers
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerSolutionNotification {
    solution_response: SolutionResponse,
}

impl GenericNotification for ClusterControllerSolutionNotification {
    const SUBJECT: &'static str = "subspace.controller.*.solution";
}

/// Notification messages with reward signature by farmers
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerRewardSignatureNotification {
    reward_signature: RewardSignatureResponse,
}

impl GenericNotification for ClusterControllerRewardSignatureNotification {
    const SUBJECT: &'static str = "subspace.controller.reward-signature";
}

/// Request farmer app info from controller
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerFarmerAppInfoRequest;

impl GenericRequest for ClusterControllerFarmerAppInfoRequest {
    const SUBJECT: &'static str = "subspace.controller.farmer-app-info";
    type Response = Result<FarmerAppInfo, String>;
}

/// Request segment headers with specified segment indices
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerSegmentHeadersRequest {
    segment_indices: Vec<SegmentIndex>,
}

impl GenericRequest for ClusterControllerSegmentHeadersRequest {
    const SUBJECT: &'static str = "subspace.controller.segment-headers";
    type Response = Vec<Option<SegmentHeader>>;
}

/// Find piece with specified index in cache
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerFindPieceInCacheRequest {
    piece_index: PieceIndex,
}

impl GenericRequest for ClusterControllerFindPieceInCacheRequest {
    const SUBJECT: &'static str = "subspace.controller.find-piece-in-cache";
    type Response = Option<(PieceCacheId, PieceCacheOffset)>;
}

/// Find pieces with specified indices in cache
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerFindPiecesInCacheRequest {
    piece_indices: Vec<PieceIndex>,
}

impl GenericStreamRequest for ClusterControllerFindPiecesInCacheRequest {
    const SUBJECT: &'static str = "subspace.controller.find-pieces-in-cache";
    /// Only pieces that were found are returned
    type Response = (PieceIndex, PieceCacheId, PieceCacheOffset);
}

/// Request piece with specified index
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerPieceRequest {
    piece_index: PieceIndex,
}

impl GenericRequest for ClusterControllerPieceRequest {
    const SUBJECT: &'static str = "subspace.controller.piece";
    type Response = Option<Piece>;
}

/// Request pieces with specified index
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerPiecesRequest {
    piece_indices: Vec<PieceIndex>,
}

impl GenericStreamRequest for ClusterControllerPiecesRequest {
    const SUBJECT: &'static str = "subspace.controller.pieces";
    /// Only pieces that were found are returned
    type Response = (PieceIndex, Piece);
}

/// Cluster piece getter
#[derive(Debug, Clone)]
pub struct ClusterPieceGetter {
    nats_client: NatsClient,
}

#[async_trait]
impl PieceGetter for ClusterPieceGetter {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if let Some((piece_cache_id, piece_cache_offset)) = self
            .nats_client
            .request(
                &ClusterControllerFindPieceInCacheRequest { piece_index },
                None,
            )
            .await?
        {
            trace!(
                %piece_index,
                %piece_cache_id,
                %piece_cache_offset,
                "Found piece in cache, retrieving"
            );

            match self
                .nats_client
                .request(
                    &ClusterCacheReadPieceRequest {
                        offset: piece_cache_offset,
                    },
                    Some(&piece_cache_id.to_string()),
                )
                .await
                .map_err(|error| error.to_string())
                .flatten()
            {
                Ok(Some((retrieved_piece_index, piece))) => {
                    if retrieved_piece_index == piece_index {
                        trace!(
                            %piece_index,
                            %piece_cache_id,
                            %piece_cache_offset,
                            "Retrieved piece from cache successfully"
                        );

                        return Ok(Some(piece));
                    } else {
                        trace!(
                            %piece_index,
                            %piece_cache_id,
                            %piece_cache_offset,
                            "Retrieving piece was replaced in cache during retrieval"
                        );
                    }
                }
                Ok(None) => {
                    trace!(
                        %piece_index,
                        %piece_cache_id,
                        %piece_cache_offset,
                        "Piece cache didn't have piece at offset"
                    );
                }
                Err(error) => {
                    debug!(
                        %piece_index,
                        %piece_cache_id,
                        %piece_cache_offset,
                        %error,
                        "Retrieving piece from cache failed"
                    );
                }
            }
        } else {
            trace!(%piece_index, "Piece not found in cache");
        }

        Ok(self
            .nats_client
            .request(&ClusterControllerPieceRequest { piece_index }, None)
            .await?)
    }

    async fn get_pieces<'a, PieceIndices>(
        &'a self,
        piece_indices: PieceIndices,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    >
    where
        PieceIndices: IntoIterator<Item = PieceIndex, IntoIter: Send> + Send + 'a,
    {
        let (tx, mut rx) = mpsc::unbounded();

        let piece_indices = piece_indices.into_iter().collect::<Vec<_>>();
        let piece_indices_to_get =
            Mutex::new(piece_indices.iter().copied().collect::<HashSet<_>>());

        let mut cached_pieces_by_cache_id = HashMap::<PieceCacheId, Vec<PieceCacheOffset>>::new();

        {
            let mut cached_pieces = self
                .nats_client
                .stream_request(
                    &ClusterControllerFindPiecesInCacheRequest { piece_indices },
                    None,
                )
                .await?;

            while let Some((_piece_index, piece_cache_id, piece_cache_offset)) =
                cached_pieces.next().await
            {
                cached_pieces_by_cache_id
                    .entry(piece_cache_id)
                    .or_default()
                    .push(piece_cache_offset);
            }
        }

        let fut = async move {
            let tx = &tx;

            let mut getting_from_piece_cache = cached_pieces_by_cache_id
                .into_iter()
                .map(|(piece_cache_id, offsets)| {
                    let piece_indices_to_get = &piece_indices_to_get;

                    async move {
                        let mut pieces_stream = match self
                            .nats_client
                            .stream_request(
                                &ClusterCacheReadPiecesRequest { offsets },
                                Some(&piece_cache_id.to_string()),
                            )
                            .await
                        {
                            Ok(pieces) => pieces,
                            Err(error) => {
                                warn!(
                                    %error,
                                    %piece_cache_id,
                                    "Failed to request pieces from cache"
                                );

                                return;
                            }
                        };

                        while let Some(piece_result) = pieces_stream.next().await {
                            let (piece_offset, maybe_piece) = match piece_result {
                                Ok(result) => result,
                                Err(error) => {
                                    warn!(%error, "Failed to get piece from cache");
                                    continue;
                                }
                            };

                            if let Some((piece_index, piece)) = maybe_piece {
                                piece_indices_to_get.lock().remove(&piece_index);

                                tx.unbounded_send((piece_index, Ok(Some(piece)))).expect(
                                    "This future isn't polled after receiver is dropped; qed",
                                );
                            } else {
                                warn!(
                                    %piece_cache_id,
                                    %piece_offset,
                                    "Failed to get piece from cache, it was missing or already gone"
                                );
                            }
                        }
                    }
                })
                .collect::<FuturesUnordered<_>>();
            // TODO: Can't use this due to https://github.com/rust-lang/rust/issues/64650
            // Simply drain everything
            // .for_each(|()| async {})

            // TODO: Remove once https://github.com/rust-lang/rust/issues/64650 is resolved
            while let Some(()) = getting_from_piece_cache.next().await {
                // Simply drain everything
            }
            drop(getting_from_piece_cache);

            let mut piece_indices_to_get = piece_indices_to_get.into_inner();
            if piece_indices_to_get.is_empty() {
                return;
            }

            let mut pieces_from_controller = match self
                .nats_client
                .stream_request(
                    &ClusterControllerPiecesRequest {
                        piece_indices: piece_indices_to_get.iter().copied().collect(),
                    },
                    None,
                )
                .await
            {
                Ok(pieces_from_controller) => pieces_from_controller,
                Err(error) => {
                    error!(%error, "Failed to get pieces from controller");

                    for piece_index in piece_indices_to_get {
                        tx.unbounded_send((
                            piece_index,
                            Err(anyhow::anyhow!("Failed to get piece from controller")),
                        ))
                        .expect("This future isn't polled after receiver is dropped; qed");
                    }
                    return;
                }
            };

            while let Some((piece_index, piece)) = pieces_from_controller.next().await {
                piece_indices_to_get.remove(&piece_index);
                tx.unbounded_send((piece_index, Ok(Some(piece))))
                    .expect("This future isn't polled after receiver is dropped; qed");
            }

            for piece_index in piece_indices_to_get {
                tx.unbounded_send((piece_index, Err(anyhow::anyhow!("Failed to get piece"))))
                    .expect("This future isn't polled after receiver is dropped; qed");
            }
        };
        let mut fut = Box::pin(fut.fuse());

        // Drive above future and stream back any pieces that were downloaded so far
        Ok(Box::new(stream::poll_fn(move |cx| {
            if !fut.is_terminated() {
                // Result doesn't matter, we'll need to poll stream below anyway
                let _ = fut.poll_unpin(cx);
            }

            if let Poll::Ready(maybe_result) = rx.poll_next_unpin(cx) {
                return Poll::Ready(maybe_result);
            }

            // Exit will be done by the stream above
            Poll::Pending
        })))
    }
}

impl ClusterPieceGetter {
    /// Create new instance
    #[inline]
    pub fn new(nats_client: NatsClient) -> Self {
        Self { nats_client }
    }
}

/// [`NodeClient`] used in cluster environment that connects to node through a controller instead
/// of to the node directly
#[derive(Debug, Clone)]
pub struct ClusterNodeClient {
    nats_client: NatsClient,
    // Store last slot info instance that can be used to send solution response to (some instances
    // may be not synced and not able to receive solution responses)
    last_slot_info_instance: Arc<Mutex<String>>,
}

impl ClusterNodeClient {
    /// Create a new instance
    pub fn new(nats_client: NatsClient) -> Self {
        Self {
            nats_client,
            last_slot_info_instance: Arc::default(),
        }
    }
}

#[async_trait]
impl NodeClient for ClusterNodeClient {
    async fn farmer_app_info(&self) -> anyhow::Result<FarmerAppInfo> {
        Ok(self
            .nats_client
            .request(&ClusterControllerFarmerAppInfoRequest, None)
            .await?
            .map_err(anyhow::Error::msg)?)
    }

    async fn subscribe_slot_info(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>> {
        let subscription = self
            .nats_client
            .subscribe_to_broadcasts::<ClusterControllerSlotInfoBroadcast>(None, None)
            .await?
            .filter_map({
                let mut last_slot_number = None;
                let last_slot_info_instance = Arc::clone(&self.last_slot_info_instance);

                move |broadcast| {
                    let slot_info = broadcast.slot_info;

                    let maybe_slot_info = if let Some(last_slot_number) = last_slot_number
                        && last_slot_number >= slot_info.slot_number
                    {
                        None
                    } else {
                        last_slot_number.replace(slot_info.slot_number);
                        *last_slot_info_instance.lock() = broadcast.instance;

                        Some(slot_info)
                    };

                    async move { maybe_slot_info }
                }
            });

        Ok(Box::pin(subscription))
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> anyhow::Result<()> {
        let last_slot_info_instance = self.last_slot_info_instance.lock().clone();
        Ok(self
            .nats_client
            .notification(
                &ClusterControllerSolutionNotification { solution_response },
                Some(&last_slot_info_instance),
            )
            .await?)
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>> {
        let subscription = self
            .nats_client
            .subscribe_to_broadcasts::<ClusterControllerRewardSigningBroadcast>(None, None)
            .await?
            .map(|broadcast| broadcast.reward_signing_info);

        Ok(Box::pin(subscription))
    }

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> anyhow::Result<()> {
        Ok(self
            .nats_client
            .notification(
                &ClusterControllerRewardSignatureNotification { reward_signature },
                None,
            )
            .await?)
    }

    async fn subscribe_archived_segment_headers(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>> {
        let subscription = self
            .nats_client
            .subscribe_to_broadcasts::<ClusterControllerArchivedSegmentHeaderBroadcast>(None, None)
            .await?
            .filter_map({
                let mut last_archived_segment_index = None;

                move |broadcast| {
                    let archived_segment_header = broadcast.archived_segment_header;
                    let segment_index = archived_segment_header.segment_index();

                    let maybe_archived_segment_header = if let Some(last_archived_segment_index) =
                        last_archived_segment_index
                        && last_archived_segment_index >= segment_index
                    {
                        None
                    } else {
                        last_archived_segment_index.replace(segment_index);

                        Some(archived_segment_header)
                    };

                    async move { maybe_archived_segment_header }
                }
            });

        Ok(Box::pin(subscription))
    }

    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>> {
        Ok(self
            .nats_client
            .request(
                &ClusterControllerSegmentHeadersRequest { segment_indices },
                None,
            )
            .await?)
    }

    async fn piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        Ok(self
            .nats_client
            .request(&ClusterControllerPieceRequest { piece_index }, None)
            .await?)
    }

    async fn acknowledge_archived_segment_header(
        &self,
        _segment_index: SegmentIndex,
    ) -> anyhow::Result<()> {
        // Acknowledgement is unnecessary/unsupported
        Ok(())
    }
}

/// Create controller service that handles things like broadcasting information (for example slot
/// notifications) as well as responding to incoming requests (like piece requests).
///
/// Implementation is using concurrency with multiple tokio tasks, but can be started multiple times
/// per controller instance in order to parallelize more work across threads if needed.
pub async fn controller_service<NC, PG>(
    nats_client: &NatsClient,
    node_client: &NC,
    piece_getter: &PG,
    farmer_cache: &FarmerCache<ClusterCacheIndex>,
    instance: &str,
    primary_instance: bool,
) -> anyhow::Result<()>
where
    NC: NodeClient,
    PG: PieceGetter + Sync,
{
    if primary_instance {
        select! {
            result = slot_info_broadcaster(nats_client, node_client, instance).fuse() => {
                result
            },
            result = reward_signing_broadcaster(nats_client, node_client, instance).fuse() => {
                result
            },
            result = archived_segment_headers_broadcaster(nats_client, node_client, instance).fuse() => {
                result
            },
            result = solution_response_forwarder(nats_client, node_client, instance).fuse() => {
                result
            },
            result = reward_signature_forwarder(nats_client, node_client, instance).fuse() => {
                result
            },
            result = farmer_app_info_responder(nats_client, node_client).fuse() => {
                result
            },
            result = segment_headers_responder(nats_client, node_client).fuse() => {
                result
            },
            result = find_piece_responder(nats_client, farmer_cache).fuse() => {
                result
            },
            result = find_pieces_responder(nats_client, farmer_cache).fuse() => {
                result
            },
            result = piece_responder(nats_client, piece_getter).fuse() => {
                result
            },
            result = pieces_responder(nats_client, piece_getter).fuse() => {
                result
            },
        }
    } else {
        select! {
            result = farmer_app_info_responder(nats_client, node_client).fuse() => {
                result
            },
            result = segment_headers_responder(nats_client, node_client).fuse() => {
                result
            },
            result = find_piece_responder(nats_client, farmer_cache).fuse() => {
                result
            },
            result = find_pieces_responder(nats_client, farmer_cache).fuse() => {
                result
            },
            result = piece_responder(nats_client, piece_getter).fuse() => {
                result
            },
            result = pieces_responder(nats_client, piece_getter).fuse() => {
                result
            },
        }
    }
}

async fn slot_info_broadcaster<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    let mut slot_info_notifications = node_client
        .subscribe_slot_info()
        .await
        .map_err(|error| anyhow!("Failed to subscribe to slot info notifications: {error}"))?;

    while let Some(slot_info) = slot_info_notifications.next().await {
        debug!(?slot_info, "New slot");

        let slot = slot_info.slot_number;

        if let Err(error) = nats_client
            .broadcast(
                &ClusterControllerSlotInfoBroadcast {
                    slot_info,
                    instance: instance.to_string(),
                },
                instance,
            )
            .await
        {
            warn!(%slot, %error, "Failed to broadcast slot info");
        }
    }

    Ok(())
}

async fn reward_signing_broadcaster<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    let mut reward_signing_notifications = node_client
        .subscribe_reward_signing()
        .await
        .map_err(|error| anyhow!("Failed to subscribe to reward signing notifications: {error}"))?;

    while let Some(reward_signing_info) = reward_signing_notifications.next().await {
        trace!(?reward_signing_info, "New reward signing notification");

        if let Err(error) = nats_client
            .broadcast(
                &ClusterControllerRewardSigningBroadcast {
                    reward_signing_info,
                },
                instance,
            )
            .await
        {
            warn!(%error, "Failed to broadcast reward signing info");
        }
    }

    Ok(())
}

async fn archived_segment_headers_broadcaster<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    let mut archived_segments_notifications = node_client
        .subscribe_archived_segment_headers()
        .await
        .map_err(|error| {
            anyhow!("Failed to subscribe to archived segment header notifications: {error}")
        })?;

    while let Some(archived_segment_header) = archived_segments_notifications.next().await {
        trace!(
            ?archived_segment_header,
            "New archived archived segment header notification"
        );

        node_client
            .acknowledge_archived_segment_header(archived_segment_header.segment_index())
            .await
            .map_err(|error| anyhow!("Failed to acknowledge archived segment header: {error}"))?;

        if let Err(error) = nats_client
            .broadcast(
                &ClusterControllerArchivedSegmentHeaderBroadcast {
                    archived_segment_header,
                },
                instance,
            )
            .await
        {
            warn!(%error, "Failed to broadcast archived segment header info");
        }
    }

    Ok(())
}

async fn solution_response_forwarder<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    let mut subscription = nats_client
        .subscribe_to_notifications::<ClusterControllerSolutionNotification>(
            Some(instance),
            Some(instance.to_string()),
        )
        .await
        .map_err(|error| anyhow!("Failed to subscribe to solution notifications: {error}"))?;

    while let Some(notification) = subscription.next().await {
        debug!(?notification, "Solution notification");

        let slot = notification.solution_response.slot_number;
        let public_key = notification.solution_response.solution.public_key;
        let sector_index = notification.solution_response.solution.sector_index;

        if let Err(error) = node_client
            .submit_solution_response(notification.solution_response)
            .await
        {
            warn!(
                %error,
                %slot,
                %public_key,
                %sector_index,
                "Failed to send solution response"
            );
        }
    }

    Ok(())
}

async fn reward_signature_forwarder<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    let mut subscription = nats_client
        .subscribe_to_notifications::<ClusterControllerRewardSignatureNotification>(
            None,
            Some(instance.to_string()),
        )
        .await
        .map_err(|error| {
            anyhow!("Failed to subscribe to reward signature notifications: {error}")
        })?;

    while let Some(notification) = subscription.next().await {
        debug!(?notification, "Reward signature notification");

        if let Err(error) = node_client
            .submit_reward_signature(notification.reward_signature)
            .await
        {
            warn!(%error, "Failed to send reward signature");
        }
    }

    Ok(())
}

async fn farmer_app_info_responder<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    nats_client
        .request_responder(
            None,
            Some("subspace.controller".to_string()),
            |_: ClusterControllerFarmerAppInfoRequest| async move {
                Some(
                    node_client
                        .farmer_app_info()
                        .await
                        .map_err(|error| error.to_string()),
                )
            },
        )
        .await
}

async fn segment_headers_responder<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    nats_client
        .request_responder(
            None,
            Some("subspace.controller".to_string()),
            |ClusterControllerSegmentHeadersRequest { segment_indices }| async move {
                node_client
                    .segment_headers(segment_indices.clone())
                    .await
                    .inspect_err(|error| {
                        warn!(%error, ?segment_indices, "Failed to get segment headers");
                    })
                    .ok()
            },
        )
        .await
}

async fn find_piece_responder(
    nats_client: &NatsClient,
    farmer_cache: &FarmerCache<ClusterCacheIndex>,
) -> anyhow::Result<()> {
    nats_client
        .request_responder(
            None,
            Some("subspace.controller".to_string()),
            |ClusterControllerFindPieceInCacheRequest { piece_index }| async move {
                Some(farmer_cache.find_piece(piece_index).await)
            },
        )
        .await
}

async fn find_pieces_responder(
    nats_client: &NatsClient,
    farmer_cache: &FarmerCache<ClusterCacheIndex>,
) -> anyhow::Result<()> {
    nats_client
        .stream_request_responder(
            None,
            Some("subspace.controller".to_string()),
            |ClusterControllerFindPiecesInCacheRequest { piece_indices }| async move {
                Some(stream::iter(farmer_cache.find_pieces(piece_indices).await))
            },
        )
        .await
}

async fn piece_responder<PG>(nats_client: &NatsClient, piece_getter: &PG) -> anyhow::Result<()>
where
    PG: PieceGetter + Sync,
{
    nats_client
        .request_responder(
            None,
            Some("subspace.controller".to_string()),
            |ClusterControllerPieceRequest { piece_index }| async move {
                piece_getter
                    .get_piece(piece_index)
                    .await
                    .inspect_err(|error| warn!(%error, %piece_index, "Failed to get piece"))
                    .ok()
            },
        )
        .await
}

async fn pieces_responder<PG>(nats_client: &NatsClient, piece_getter: &PG) -> anyhow::Result<()>
where
    PG: PieceGetter + Sync,
{
    nats_client
        .stream_request_responder(
            None,
            Some("subspace.controller".to_string()),
            |ClusterControllerPiecesRequest { piece_indices }| async move {
                piece_getter
                    .get_pieces(piece_indices)
                    .await
                    .map(|stream| {
                        Box::pin(stream.filter_map(
                            |(piece_index, maybe_piece_result)| async move {
                                match maybe_piece_result {
                                    Ok(Some(piece)) => Some((piece_index, piece)),
                                    Ok(None) => None,
                                    Err(error) => {
                                        warn!(%error, %piece_index, "Failed to get piece");
                                        None
                                    }
                                }
                            },
                        ))
                    })
                    .inspect_err(|error| warn!(%error, "Failed to get pieces"))
                    .ok()
            },
        )
        .await
}
