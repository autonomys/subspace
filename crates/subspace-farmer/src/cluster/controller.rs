//! Farming cluster controller
//!
//! Controller is responsible for managing farming cluster.
//!
//! This module exposes some data structures for NATS communication, custom piece getter and node
//! client implementations designed to work with cluster controller and a service function to drive
//! the backend part of the controller.

use crate::cluster::nats_client::{
    GenericBroadcast, GenericNotification, GenericRequest, NatsClient,
};
use crate::node_client::{Error as NodeClientError, NodeClient};
use crate::utils::AsyncJoinOnDrop;
use anyhow::anyhow;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock, Semaphore};
use async_nats::{HeaderValue, Message};
use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::error::Error;
use std::future::{pending, Future};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::{
    ArchivedBlockProgress, Blake3Hash, LastArchivedBlock, Piece, PieceIndex, SegmentHeader,
    SegmentIndex,
};
use subspace_farmer_components::PieceGetter;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tracing::{debug, info, trace, warn};

const FARMER_APP_INFO_DEDUPLICATION_WINDOW: Duration = Duration::from_secs(1);

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
    type Response = FarmerAppInfo;
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

/// Request piece with specified index
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterControllerPieceRequest {
    piece_index: PieceIndex,
}

impl GenericRequest for ClusterControllerPieceRequest {
    const SUBJECT: &'static str = "subspace.controller.piece";
    type Response = Option<Piece>;
}

/// Cluster piece getter
#[derive(Debug, Clone)]
pub struct ClusterPieceGetter {
    nats_client: NatsClient,
    request_semaphore: Arc<Semaphore>,
}

#[async_trait]
impl PieceGetter for ClusterPieceGetter {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let _guard = self.request_semaphore.acquire().await;
        Ok(self
            .nats_client
            .request(&ClusterControllerPieceRequest { piece_index }, None)
            .await?)
    }
}

impl ClusterPieceGetter {
    /// Create new instance
    #[inline]
    pub fn new(nats_client: NatsClient, request_concurrency: NonZeroUsize) -> Self {
        let request_semaphore = Arc::new(Semaphore::new(request_concurrency.get()));
        Self {
            nats_client,
            request_semaphore,
        }
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
    segment_headers: Arc<AsyncRwLock<Vec<SegmentHeader>>>,
    _background_task: Arc<AsyncJoinOnDrop<()>>,
}

impl ClusterNodeClient {
    /// Create a new instance
    pub async fn new(nats_client: NatsClient) -> anyhow::Result<Self> {
        let mut segment_headers = Vec::<SegmentHeader>::new();
        let mut archived_segments_notifications = nats_client
            .subscribe_to_broadcasts::<ClusterControllerArchivedSegmentHeaderBroadcast>(None, None)
            .await?
            .map(|broadcast| broadcast.archived_segment_header);

        info!("Downloading all segment headers from controller...");
        {
            let mut segment_index_offset = SegmentIndex::from(segment_headers.len() as u64);
            let dummy_header = SegmentHeader::V0 {
                segment_index: Default::default(),
                segment_commitment: Default::default(),
                prev_segment_header_hash: Blake3Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    archived_progress: ArchivedBlockProgress::Partial(0),
                },
            };
            let segment_index_step = SegmentIndex::from(
                nats_client.approximate_max_message_size() as u64
                    / dummy_header.encoded_size() as u64,
            );

            'outer: loop {
                let from = segment_index_offset;
                let to = segment_index_offset + segment_index_step;
                trace!(%from, %to, "Requesting segment headers");

                for maybe_segment_header in nats_client
                    .request(
                        &ClusterControllerSegmentHeadersRequest {
                            segment_indices: (from..to).collect::<Vec<_>>(),
                        },
                        None,
                    )
                    .await?
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
                }
            }
        });

        Ok(Self {
            nats_client,
            last_slot_info_instance: Arc::default(),
            segment_headers,
            _background_task: Arc::new(AsyncJoinOnDrop::new(background_task, true)),
        })
    }
}

#[async_trait]
impl NodeClient for ClusterNodeClient {
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, NodeClientError> {
        Ok(self
            .nats_client
            .request(&ClusterControllerFarmerAppInfoRequest, None)
            .await?)
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, NodeClientError> {
        let last_slot_info_instance = Arc::clone(&self.last_slot_info_instance);
        let subscription = self
            .nats_client
            .subscribe_to_broadcasts::<ClusterControllerSlotInfoBroadcast>(None, None)
            .await?
            .map(move |broadcast| {
                *last_slot_info_instance.lock() = broadcast.instance;

                broadcast.slot_info
            });

        Ok(Box::pin(subscription))
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), NodeClientError> {
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
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, NodeClientError>
    {
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
    ) -> Result<(), NodeClientError> {
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
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, NodeClientError> {
        let subscription = self
            .nats_client
            .subscribe_to_broadcasts::<ClusterControllerArchivedSegmentHeaderBroadcast>(None, None)
            .await?
            .map(|broadcast| broadcast.archived_segment_header);

        Ok(Box::pin(subscription))
    }

    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, NodeClientError> {
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

    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, NodeClientError> {
        Ok(self
            .nats_client
            .request(&ClusterControllerPieceRequest { piece_index }, None)
            .await?)
    }

    async fn acknowledge_archived_segment_header(
        &self,
        _segment_index: SegmentIndex,
    ) -> Result<(), NodeClientError> {
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
    instance: &str,
) -> anyhow::Result<()>
where
    NC: NodeClient,
    PG: PieceGetter + Sync,
{
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
        result = piece_responder(nats_client, piece_getter).fuse() => {
            result
        },
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
    let farmer_app_info: <ClusterControllerFarmerAppInfoRequest as GenericRequest>::Response =
        node_client
            .farmer_app_info()
            .await
            .map_err(|error| anyhow!("Failed to get farmer app info: {error}"))?;
    let last_farmer_app_info = AsyncMutex::new((farmer_app_info, Instant::now()));

    // Initialize with pending future so it never ends
    let mut processing = FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
        Box::pin(pending()) as Pin<Box<_>>,
    ]);

    let subscription = nats_client
        .queue_subscribe(
            ClusterControllerFarmerAppInfoRequest::SUBJECT,
            "subspace.controller".to_string(),
        )
        .await
        .map_err(|error| anyhow!("Failed to subscribe to farmer app info requests: {error}"))?;
    debug!(?subscription, "Farmer app info requests subscription");
    let mut subscription = subscription.fuse();

    loop {
        select! {
            maybe_message = subscription.next() => {
                let Some(message) = maybe_message else {
                    break;
                };

                // Create background task for concurrent processing
                processing.push(Box::pin(process_farmer_app_info_request(
                    nats_client,
                    node_client,
                    message,
                    &last_farmer_app_info,
                )));
            }
            _ = processing.next() => {
                // Nothing to do here
            }
        }
    }

    Ok(())
}

async fn process_farmer_app_info_request<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    message: Message,
    last_farmer_app_info: &AsyncMutex<(FarmerAppInfo, Instant)>,
) where
    NC: NodeClient,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    trace!("Farmer app info request");

    let farmer_app_info = {
        let (last_farmer_app_info, last_farmer_app_info_request) =
            &mut *last_farmer_app_info.lock().await;

        if last_farmer_app_info_request.elapsed() > FARMER_APP_INFO_DEDUPLICATION_WINDOW {
            let farmer_app_info: Result<
                <ClusterControllerFarmerAppInfoRequest as GenericRequest>::Response,
                _,
            > = node_client.farmer_app_info().await;
            match farmer_app_info {
                Ok(new_last_farmer_app_info) => {
                    *last_farmer_app_info = new_last_farmer_app_info;
                    *last_farmer_app_info_request = Instant::now();
                }
                Err(error) => {
                    warn!(%error, "Failed to get farmer app info");
                }
            }
        }

        last_farmer_app_info.clone()
    };

    if let Err(error) = nats_client
        .publish(reply_subject, farmer_app_info.encode().into())
        .await
    {
        warn!(%error, "Failed to send farmer app info response");
    }
}

async fn segment_headers_responder<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
) -> anyhow::Result<()>
where
    NC: NodeClient,
{
    // Initialize with pending future so it never ends
    let mut processing = FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
        Box::pin(pending()) as Pin<Box<_>>,
    ]);

    let subscription = nats_client
        .queue_subscribe(
            ClusterControllerSegmentHeadersRequest::SUBJECT,
            "subspace.controller".to_string(),
        )
        .await
        .map_err(|error| anyhow!("Failed to subscribe to segment headers requests: {error}"))?;
    debug!(?subscription, "Segment headers requests subscription");
    let mut subscription = subscription.fuse();

    loop {
        select! {
            maybe_message = subscription.next() => {
                let Some(message) = maybe_message else {
                    break;
                };

                // Create background task for concurrent processing
                processing.push(Box::pin(process_segment_headers_request(
                    nats_client,
                    node_client,
                    message,
                )));
            }
            _ = processing.next() => {
                // Nothing to do here
            }
        }
    }
    Ok(())
}

async fn process_segment_headers_request<NC>(
    nats_client: &NatsClient,
    node_client: &NC,
    message: Message,
) where
    NC: NodeClient,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    let request =
        match ClusterControllerSegmentHeadersRequest::decode(&mut message.payload.as_ref()) {
            Ok(request) => request,
            Err(error) => {
                warn!(
                    %error,
                    message = %hex::encode(message.payload),
                    "Failed to decode segment headers request"
                );
                return;
            }
        };
    trace!(?request, "Segment headers request");

    let response: <ClusterControllerSegmentHeadersRequest as GenericRequest>::Response =
        match node_client
            .segment_headers(request.segment_indices.clone())
            .await
        {
            Ok(segment_headers) => segment_headers,
            Err(error) => {
                warn!(
                    %error,
                    segment_indices = ?request.segment_indices,
                    "Failed to get segment headers"
                );
                return;
            }
        };

    if let Err(error) = nats_client
        .publish(reply_subject, response.encode().into())
        .await
    {
        warn!(%error, "Failed to send segment headers response");
    }
}

async fn piece_responder<PG>(nats_client: &NatsClient, piece_getter: &PG) -> anyhow::Result<()>
where
    PG: PieceGetter + Sync,
{
    // Initialize with pending future so it never ends
    let mut processing = FuturesUnordered::<Pin<Box<dyn Future<Output = ()> + Send>>>::from_iter([
        Box::pin(pending()) as Pin<Box<_>>,
    ]);

    let subscription = nats_client
        .queue_subscribe(
            ClusterControllerPieceRequest::SUBJECT,
            "subspace.controller".to_string(),
        )
        .await
        .map_err(|error| anyhow!("Failed to subscribe to piece requests: {error}"))?;
    debug!(?subscription, "Piece requests subscription");
    let mut subscription = subscription.fuse();

    loop {
        select! {
            maybe_message = subscription.next() => {
                let Some(message) = maybe_message else {
                    break;
                };

                // Create background task for concurrent processing
                processing.push(Box::pin(process_piece_request(
                    nats_client,
                    piece_getter,
                    message,
                )));
            }
            _ = processing.next() => {
                // Nothing to do here
            }
        }
    }

    Ok(())
}

async fn process_piece_request<PG>(nats_client: &NatsClient, piece_getter: &PG, message: Message)
where
    PG: PieceGetter,
{
    let Some(reply_subject) = message.reply else {
        return;
    };

    let request = match ClusterControllerPieceRequest::decode(&mut message.payload.as_ref()) {
        Ok(request) => request,
        Err(error) => {
            warn!(
                %error,
                message = %hex::encode(message.payload),
                "Failed to decode piece request"
            );
            return;
        }
    };
    trace!(?request, "Piece request");

    // TODO: It would be great to send cached pieces from cache instance directly to requested
    //  rather than proxying through controller, but it is awkward with current architecture

    let maybe_piece: <ClusterControllerPieceRequest as GenericRequest>::Response =
        match piece_getter.get_piece(request.piece_index).await {
            Ok(maybe_piece) => maybe_piece,
            Err(error) => {
                warn!(
                    %error,
                    piece_index = %request.piece_index,
                    "Failed to get piece"
                );
                return;
            }
        };

    if let Err(error) = nats_client
        .publish(reply_subject, maybe_piece.encode().into())
        .await
    {
        warn!(%error, "Failed to send farmer app info response");
    }
}
