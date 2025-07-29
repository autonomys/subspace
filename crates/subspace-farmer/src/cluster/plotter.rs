//! Farming cluster plotter
//!
//! Plotter is responsible for plotting sectors in response to farmer requests.
//!
//! This module exposes some data structures for NATS communication, custom plotter
//! implementation designed to work with cluster plotter and a service function to drive the backend
//! part of the plotter.

use crate::cluster::nats_client::{GenericRequest, GenericStreamRequest, NatsClient};
use crate::plotter::{Plotter, SectorPlottingProgress};
use anyhow::anyhow;
use async_nats::RequestErrorKind;
use async_trait::async_trait;
use backoff::ExponentialBackoff;
use backoff::backoff::Backoff;
use bytes::Bytes;
use derive_more::Display;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::mpsc;
use futures::future::FusedFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Sink, SinkExt, StreamExt, select, stream};
use parity_scale_codec::{Decode, Encode};
use std::error::Error;
use std::future::pending;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::sectors::SectorIndex;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::sector::sector_size;
use subspace_networking::utils::AsyncJoinOnDrop;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::MissedTickBehavior;
use tracing::{Instrument, debug, info, info_span, trace, warn};
use ulid::Ulid;

const FREE_CAPACITY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Intervals between pings from plotter server to client
const PING_INTERVAL: Duration = Duration::from_secs(10);
/// Timeout after which plotter that doesn't send pings is assumed to be down
const PING_TIMEOUT: Duration = Duration::from_mins(1);

/// Type alias used for event handlers
pub type HandlerFn3<A, B, C> = Arc<dyn Fn(&A, &B, &C) + Send + Sync + 'static>;
type Handler3<A, B, C> = Bag<HandlerFn3<A, B, C>, A, B, C>;

/// An ephemeral identifier for a plotter
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Display)]
pub enum ClusterPlotterId {
    /// Plotter ID
    Ulid(Ulid),
}

#[allow(clippy::new_without_default)]
impl ClusterPlotterId {
    /// Creates new ID
    pub fn new() -> Self {
        Self::Ulid(Ulid::new())
    }
}

/// Request for free plotter instance
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterPlotterFreeInstanceRequest;

impl GenericRequest for ClusterPlotterFreeInstanceRequest {
    const SUBJECT: &'static str = "subspace.plotter.free-instance";
    /// Might be `None` if instance had to respond, but turned out it was fully occupied already
    type Response = Option<String>;
}

#[derive(Debug, Encode, Decode)]
enum ClusterSectorPlottingProgress {
    /// Plotter is already fully occupied with other work
    Occupied,
    /// Periodic ping indicating plotter is still busy
    Ping,
    /// Downloading sector pieces
    Downloading,
    /// Downloaded sector pieces
    Downloaded(Duration),
    /// Encoding sector pieces
    Encoding,
    /// Encoded sector pieces
    Encoded(Duration),
    /// Finished plotting, followed by a series of sector chunks
    Finished {
        /// Information about plotted sector
        plotted_sector: PlottedSector,
        /// How much time it took to plot a sector
        time: Duration,
    },
    /// Sector chunk after finished plotting
    SectorChunk(Result<Bytes, String>),
    /// Plotting failed
    Error {
        /// Error message
        error: String,
    },
}

/// Request to plot sector from plotter
#[derive(Debug, Clone, Encode, Decode)]
struct ClusterPlotterPlotSectorRequest {
    public_key: PublicKey,
    sector_index: SectorIndex,
    farmer_protocol_info: FarmerProtocolInfo,
    pieces_in_sector: u16,
}

impl GenericStreamRequest for ClusterPlotterPlotSectorRequest {
    const SUBJECT: &'static str = "subspace.plotter.*.plot-sector";
    type Response = ClusterSectorPlottingProgress;
}

#[derive(Default, Debug)]
struct Handlers {
    plotting_progress: Handler3<PublicKey, SectorIndex, SectorPlottingProgress>,
}

/// Cluster plotter
#[derive(Debug)]
pub struct ClusterPlotter {
    sector_encoding_semaphore: Arc<Semaphore>,
    retry_backoff_policy: ExponentialBackoff,
    nats_client: NatsClient,
    handlers: Arc<Handlers>,
    tasks_sender: mpsc::Sender<AsyncJoinOnDrop<()>>,
    _background_tasks: AsyncJoinOnDrop<()>,
}

impl Drop for ClusterPlotter {
    #[inline]
    fn drop(&mut self) {
        self.tasks_sender.close_channel();
    }
}

#[async_trait]
impl Plotter for ClusterPlotter {
    async fn has_free_capacity(&self) -> Result<bool, String> {
        Ok(self.sector_encoding_semaphore.available_permits() > 0
            && self
                .nats_client
                .request(&ClusterPlotterFreeInstanceRequest, None)
                .await
                .map_err(|error| error.to_string())?
                .is_some())
    }

    async fn plot_sector(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        _replotting: bool,
        mut progress_sender: mpsc::Sender<SectorPlottingProgress>,
    ) {
        let start = Instant::now();

        // Done outside the future below as a backpressure, ensuring that it is not possible to
        // schedule unbounded number of plotting tasks
        let sector_encoding_permit = match Arc::clone(&self.sector_encoding_semaphore)
            .acquire_owned()
            .await
        {
            Ok(sector_encoding_permit) => sector_encoding_permit,
            Err(error) => {
                warn!(%error, "Failed to acquire sector encoding permit");

                let progress_updater = ProgressUpdater {
                    public_key,
                    sector_index,
                    handlers: Arc::clone(&self.handlers),
                };

                progress_updater
                    .update_progress_and_events(
                        &mut progress_sender,
                        SectorPlottingProgress::Error {
                            error: format!("Failed to acquire sector encoding permit: {error}"),
                        },
                    )
                    .await;

                return;
            }
        };

        self.plot_sector_internal(
            start,
            sector_encoding_permit,
            public_key,
            sector_index,
            farmer_protocol_info,
            pieces_in_sector,
            progress_sender,
        )
        .await
    }

    async fn try_plot_sector(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        _replotting: bool,
        progress_sender: mpsc::Sender<SectorPlottingProgress>,
    ) -> bool {
        let start = Instant::now();

        let Ok(sector_encoding_permit) =
            Arc::clone(&self.sector_encoding_semaphore).try_acquire_owned()
        else {
            return false;
        };

        self.plot_sector_internal(
            start,
            sector_encoding_permit,
            public_key,
            sector_index,
            farmer_protocol_info,
            pieces_in_sector,
            progress_sender,
        )
        .await;

        true
    }
}

impl ClusterPlotter {
    /// Create new instance
    pub fn new(
        nats_client: NatsClient,
        sector_encoding_concurrency: NonZeroUsize,
        retry_backoff_policy: ExponentialBackoff,
    ) -> Self {
        let sector_encoding_semaphore = Arc::new(Semaphore::new(sector_encoding_concurrency.get()));

        let (tasks_sender, mut tasks_receiver) = mpsc::channel(1);

        // Basically runs plotting tasks in the background and allows to abort on drop
        let background_tasks = AsyncJoinOnDrop::new(
            tokio::spawn(async move {
                let background_tasks = FuturesUnordered::new();
                let mut background_tasks = pin!(background_tasks);
                // Just so that `FuturesUnordered` will never end
                background_tasks.push(AsyncJoinOnDrop::new(tokio::spawn(pending::<()>()), true));

                loop {
                    select! {
                        maybe_background_task = tasks_receiver.next().fuse() => {
                            let Some(background_task) = maybe_background_task else {
                                break;
                            };

                            background_tasks.push(background_task);
                        },
                        _ = background_tasks.select_next_some() => {
                            // Nothing to do
                        }
                    }
                }
            }),
            true,
        );

        Self {
            sector_encoding_semaphore,
            retry_backoff_policy,
            nats_client,
            handlers: Arc::default(),
            tasks_sender,
            _background_tasks: background_tasks,
        }
    }

    /// Subscribe to plotting progress notifications
    pub fn on_plotting_progress(
        &self,
        callback: HandlerFn3<PublicKey, SectorIndex, SectorPlottingProgress>,
    ) -> HandlerId {
        self.handlers.plotting_progress.add(callback)
    }

    #[allow(clippy::too_many_arguments)]
    async fn plot_sector_internal<PS>(
        &self,
        start: Instant,
        sector_encoding_permit: OwnedSemaphorePermit,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        mut progress_sender: PS,
    ) where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error,
    {
        trace!("Starting plotting, getting plotting permit");

        let progress_updater = ProgressUpdater {
            public_key,
            sector_index,
            handlers: Arc::clone(&self.handlers),
        };

        let mut retry_backoff_policy = self.retry_backoff_policy.clone();
        retry_backoff_policy.reset();

        // Try to get plotter instance here first as a backpressure measure
        let free_plotter_instance_fut = get_free_plotter_instance(
            &self.nats_client,
            &progress_updater,
            &mut progress_sender,
            &mut retry_backoff_policy,
        );
        let mut maybe_free_instance = free_plotter_instance_fut.await;
        if maybe_free_instance.is_none() {
            return;
        }

        trace!("Got plotting permit #1");

        let nats_client = self.nats_client.clone();

        let plotting_fut = async move {
            'outer: loop {
                // Take free instance that was found earlier if available or try to find a new one
                let free_instance = match maybe_free_instance.take() {
                    Some(free_instance) => free_instance,
                    None => {
                        let free_plotter_instance_fut = get_free_plotter_instance(
                            &nats_client,
                            &progress_updater,
                            &mut progress_sender,
                            &mut retry_backoff_policy,
                        );
                        let Some(free_instance) = free_plotter_instance_fut.await else {
                            break;
                        };
                        trace!("Got plotting permit #2");
                        free_instance
                    }
                };

                let response_stream_result = nats_client
                    .stream_request(
                        &ClusterPlotterPlotSectorRequest {
                            public_key,
                            sector_index,
                            farmer_protocol_info,
                            pieces_in_sector,
                        },
                        Some(&free_instance),
                    )
                    .await;
                trace!("Subscribed to plotting notifications");

                let mut response_stream = match response_stream_result {
                    Ok(response_stream) => response_stream,
                    Err(error) => {
                        progress_updater
                            .update_progress_and_events(
                                &mut progress_sender,
                                SectorPlottingProgress::Error {
                                    error: format!("Failed make stream request: {error}"),
                                },
                            )
                            .await;

                        break;
                    }
                };

                // Allow to buffer up to the whole sector in memory to not block plotter on the
                // other side
                let (mut sector_sender, sector_receiver) = mpsc::channel(
                    (sector_size(pieces_in_sector) / nats_client.approximate_max_message_size())
                        .max(1),
                );
                let mut maybe_sector_receiver = Some(sector_receiver);
                loop {
                    match tokio::time::timeout(PING_TIMEOUT, response_stream.next()).await {
                        Ok(Some(response)) => {
                            match process_response_notification(
                                &start,
                                &free_instance,
                                &progress_updater,
                                &mut progress_sender,
                                &mut retry_backoff_policy,
                                response,
                                &mut sector_sender,
                                &mut maybe_sector_receiver,
                            )
                            .await
                            {
                                ResponseProcessingResult::Retry => {
                                    debug!("Retrying");
                                    continue 'outer;
                                }
                                ResponseProcessingResult::Abort => {
                                    debug!("Aborting");
                                    break 'outer;
                                }
                                ResponseProcessingResult::Continue => {
                                    trace!("Continue");
                                    // Nothing to do
                                }
                            }
                        }
                        Ok(None) => {
                            trace!("Plotting done");
                            break;
                        }
                        Err(_error) => {
                            progress_updater
                                .update_progress_and_events(
                                    &mut progress_sender,
                                    SectorPlottingProgress::Error {
                                        error: "Timed out without ping from plotter".to_string(),
                                    },
                                )
                                .await;
                            break;
                        }
                    }
                }

                break;
            }

            drop(sector_encoding_permit);
        };

        let plotting_task =
            AsyncJoinOnDrop::new(tokio::spawn(plotting_fut.in_current_span()), true);
        if let Err(error) = self.tasks_sender.clone().send(plotting_task).await {
            warn!(%error, "Failed to send plotting task");

            let progress = SectorPlottingProgress::Error {
                error: format!("Failed to send plotting task: {error}"),
            };

            self.handlers
                .plotting_progress
                .call_simple(&public_key, &sector_index, &progress);
        }
    }
}

// Try to get free plotter instance and return `None` if it is not possible
async fn get_free_plotter_instance<PS>(
    nats_client: &NatsClient,
    progress_updater: &ProgressUpdater,
    progress_sender: &mut PS,
    retry_backoff_policy: &mut ExponentialBackoff,
) -> Option<String>
where
    PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
    PS::Error: Error,
{
    loop {
        match nats_client
            .request(&ClusterPlotterFreeInstanceRequest, None)
            .await
        {
            Ok(Some(free_instance)) => {
                return Some(free_instance);
            }
            Ok(None) => {
                if let Some(delay) = retry_backoff_policy.next_backoff() {
                    debug!("Instance was occupied, retrying #1");

                    tokio::time::sleep(delay).await;
                    continue;
                } else {
                    progress_updater
                        .update_progress_and_events(
                            progress_sender,
                            SectorPlottingProgress::Error {
                                error: "Instance was occupied, exiting #1".to_string(),
                            },
                        )
                        .await;
                    return None;
                }
            }
            Err(error) => match error.kind() {
                RequestErrorKind::TimedOut => {
                    if let Some(delay) = retry_backoff_policy.next_backoff() {
                        debug!("Plotter request timed out, retrying");

                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        progress_updater
                            .update_progress_and_events(
                                progress_sender,
                                SectorPlottingProgress::Error {
                                    error: "Plotter request timed out, exiting".to_string(),
                                },
                            )
                            .await;
                        return None;
                    }
                }
                RequestErrorKind::NoResponders => {
                    if let Some(delay) = retry_backoff_policy.next_backoff() {
                        debug!("No plotters, retrying");

                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        progress_updater
                            .update_progress_and_events(
                                progress_sender,
                                SectorPlottingProgress::Error {
                                    error: "No plotters, exiting".to_string(),
                                },
                            )
                            .await;
                        return None;
                    }
                }
                RequestErrorKind::Other => {
                    progress_updater
                        .update_progress_and_events(
                            progress_sender,
                            SectorPlottingProgress::Error {
                                error: format!("Failed to get free plotter instance: {error}"),
                            },
                        )
                        .await;
                    return None;
                }
            },
        };
    }
}

enum ResponseProcessingResult {
    Retry,
    Abort,
    Continue,
}

#[allow(clippy::too_many_arguments)]
async fn process_response_notification<PS>(
    start: &Instant,
    free_instance: &str,
    progress_updater: &ProgressUpdater,
    progress_sender: &mut PS,
    retry_backoff_policy: &mut ExponentialBackoff,
    response: ClusterSectorPlottingProgress,
    sector_sender: &mut mpsc::Sender<Result<Bytes, String>>,
    maybe_sector_receiver: &mut Option<mpsc::Receiver<Result<Bytes, String>>>,
) -> ResponseProcessingResult
where
    PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
    PS::Error: Error,
{
    if !matches!(response, ClusterSectorPlottingProgress::SectorChunk(_)) {
        trace!(?response, "Processing plotting response notification");
    } else {
        trace!("Processing plotting response notification (sector chunk)");
    }

    match response {
        ClusterSectorPlottingProgress::Occupied => {
            debug!(%free_instance, "Instance was occupied, retrying #2");

            if let Some(delay) = retry_backoff_policy.next_backoff() {
                debug!("Instance was occupied, retrying #2");

                tokio::time::sleep(delay).await;
                return ResponseProcessingResult::Retry;
            } else {
                debug!("Instance was occupied, exiting #2");
                return ResponseProcessingResult::Abort;
            }
        }
        ClusterSectorPlottingProgress::Ping => {
            // Expected
        }
        ClusterSectorPlottingProgress::Downloading => {
            if !progress_updater
                .update_progress_and_events(progress_sender, SectorPlottingProgress::Downloading)
                .await
            {
                return ResponseProcessingResult::Abort;
            }
        }
        ClusterSectorPlottingProgress::Downloaded(time) => {
            if !progress_updater
                .update_progress_and_events(
                    progress_sender,
                    SectorPlottingProgress::Downloaded(time),
                )
                .await
            {
                return ResponseProcessingResult::Abort;
            }
        }
        ClusterSectorPlottingProgress::Encoding => {
            if !progress_updater
                .update_progress_and_events(progress_sender, SectorPlottingProgress::Encoding)
                .await
            {
                return ResponseProcessingResult::Abort;
            }
        }
        ClusterSectorPlottingProgress::Encoded(time) => {
            if !progress_updater
                .update_progress_and_events(progress_sender, SectorPlottingProgress::Encoded(time))
                .await
            {
                return ResponseProcessingResult::Abort;
            }
        }
        ClusterSectorPlottingProgress::Finished {
            plotted_sector,
            time: _,
        } => {
            let Some(sector_receiver) = maybe_sector_receiver.take() else {
                debug!("Unexpected duplicated sector plotting progress Finished");

                progress_updater
                    .update_progress_and_events(
                        progress_sender,
                        SectorPlottingProgress::Error {
                            error: "Unexpected duplicated sector plotting progress Finished"
                                .to_string(),
                        },
                    )
                    .await;
                return ResponseProcessingResult::Abort;
            };

            let progress = SectorPlottingProgress::Finished {
                plotted_sector,
                // Use local time instead of reported by remote plotter
                time: start.elapsed(),
                sector: Box::pin(sector_receiver),
            };
            if !progress_updater
                .update_progress_and_events(progress_sender, progress)
                .await
            {
                return ResponseProcessingResult::Abort;
            }

            return ResponseProcessingResult::Continue;
        }
        // This variant must be sent after Finished and it handled above
        ClusterSectorPlottingProgress::SectorChunk(maybe_sector_chunk) => {
            if let Err(error) = sector_sender.send(maybe_sector_chunk).await {
                warn!(%error, "Failed to send sector chunk");
                return ResponseProcessingResult::Abort;
            }
            return ResponseProcessingResult::Continue;
        }
        ClusterSectorPlottingProgress::Error { error } => {
            if !progress_updater
                .update_progress_and_events(
                    progress_sender,
                    SectorPlottingProgress::Error { error },
                )
                .await
            {
                return ResponseProcessingResult::Abort;
            }
        }
    }

    ResponseProcessingResult::Continue
}

struct ProgressUpdater {
    public_key: PublicKey,
    sector_index: SectorIndex,
    handlers: Arc<Handlers>,
}

impl ProgressUpdater {
    /// Returns `true` on success and `false` if progress receiver channel is gone
    async fn update_progress_and_events<PS>(
        &self,
        progress_sender: &mut PS,
        progress: SectorPlottingProgress,
    ) -> bool
    where
        PS: Sink<SectorPlottingProgress> + Unpin,
        PS::Error: Error,
    {
        self.handlers.plotting_progress.call_simple(
            &self.public_key,
            &self.sector_index,
            &progress,
        );

        if let Err(error) = progress_sender.send(progress).await {
            warn!(%error, "Failed to send error progress update");

            false
        } else {
            true
        }
    }
}

/// Create plotter service that will be processing incoming requests.
///
/// Implementation is using concurrency with multiple tokio tasks, but can be started multiple times
/// per controller instance in order to parallelize more work across threads if needed.
pub async fn plotter_service<P>(nats_client: &NatsClient, plotter: &P) -> anyhow::Result<()>
where
    P: Plotter + Sync,
{
    let plotter_id = ClusterPlotterId::new();

    select! {
        result = free_instance_responder(&plotter_id, nats_client, plotter).fuse() => {
            result
        }
        result = plot_sector_responder(&plotter_id, nats_client, plotter).fuse() => {
            result
        }
    }
}

async fn free_instance_responder<P>(
    plotter_id: &ClusterPlotterId,
    nats_client: &NatsClient,
    plotter: &P,
) -> anyhow::Result<()>
where
    P: Plotter + Sync,
{
    loop {
        while !plotter.has_free_capacity().await.unwrap_or_default() {
            tokio::time::sleep(FREE_CAPACITY_CHECK_INTERVAL).await;
        }

        let mut subscription = nats_client
            .queue_subscribe(
                ClusterPlotterFreeInstanceRequest::SUBJECT,
                "subspace.plotter".to_string(),
            )
            .await
            .map_err(|error| anyhow!("Failed to subscribe to free instance requests: {error}"))?;
        debug!(?subscription, "Free instance subscription");

        while let Some(message) = subscription.next().await {
            let Some(reply_subject) = message.reply else {
                continue;
            };

            debug!(%reply_subject, "Free instance request");

            let has_free_capacity = plotter.has_free_capacity().await.unwrap_or_default();
            let response: <ClusterPlotterFreeInstanceRequest as GenericRequest>::Response =
                has_free_capacity.then(|| plotter_id.to_string());

            if let Err(error) = nats_client
                .publish(reply_subject, response.encode().into())
                .await
            {
                warn!(%error, "Failed to send free instance response");
            }

            if !has_free_capacity {
                subscription.unsubscribe().await.map_err(|error| {
                    anyhow!("Failed to unsubscribe from free instance requests: {error}")
                })?;
            }
        }
    }
}

async fn plot_sector_responder<P>(
    plotter_id: &ClusterPlotterId,
    nats_client: &NatsClient,
    plotter: &P,
) -> anyhow::Result<()>
where
    P: Plotter + Sync,
{
    let plotter_id_string = plotter_id.to_string();

    nats_client
        .stream_request_responder(
            Some(&plotter_id_string),
            Some(plotter_id_string.clone()),
            |request| async move {
                let (progress_sender, mut progress_receiver) = mpsc::channel(10);

                let fut =
                    process_plot_sector_request(nats_client, plotter, request, progress_sender);
                let mut fut = Box::pin(fut.fuse());

                Some(
                    // Drive above future and stream back any pieces that were downloaded so far
                    stream::poll_fn(move |cx| {
                        if !fut.is_terminated() {
                            // Result doesn't matter, we'll need to poll stream below anyway
                            let _ = fut.poll_unpin(cx);
                        }

                        if let Poll::Ready(maybe_result) = progress_receiver.poll_next_unpin(cx) {
                            return Poll::Ready(maybe_result);
                        }

                        // Exit will be done by the stream above
                        Poll::Pending
                    }),
                )
            },
        )
        .await
}

async fn process_plot_sector_request<P>(
    nats_client: &NatsClient,
    plotter: &P,
    request: ClusterPlotterPlotSectorRequest,
    mut response_proxy_sender: mpsc::Sender<ClusterSectorPlottingProgress>,
) where
    P: Plotter,
{
    let ClusterPlotterPlotSectorRequest {
        public_key,
        sector_index,
        farmer_protocol_info,
        pieces_in_sector,
    } = request;

    // Wrapper future just for instrumentation below
    let inner_fut = async {
        info!("Plot sector request");

        let (progress_sender, mut progress_receiver) = mpsc::channel(1);

        if !plotter
            .try_plot_sector(
                public_key,
                sector_index,
                farmer_protocol_info,
                pieces_in_sector,
                false,
                progress_sender,
            )
            .await
        {
            debug!("Plotter is currently occupied and can't plot more sectors");

            if let Err(error) = response_proxy_sender
                .send(ClusterSectorPlottingProgress::Occupied)
                .await
            {
                warn!(%error, "Failed to send plotting progress");
                return;
            }
            return;
        }

        let progress_proxy_fut = {
            let mut response_proxy_sender = response_proxy_sender.clone();
            let approximate_max_message_size = nats_client.approximate_max_message_size();

            async move {
                while let Some(progress) = progress_receiver.next().await {
                    send_publish_progress(
                        &mut response_proxy_sender,
                        progress,
                        approximate_max_message_size,
                    )
                    .await;
                }
            }
        };

        let mut ping_interval = tokio::time::interval(PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let ping_fut = async {
            loop {
                ping_interval.tick().await;
                if let Err(error) = response_proxy_sender
                    .send(ClusterSectorPlottingProgress::Ping)
                    .await
                {
                    warn!(%error, "Failed to send plotting ping");
                    return;
                }
            }
        };

        select! {
            _ = progress_proxy_fut.fuse() => {
                // Done
            }
            _ = ping_fut.fuse() => {
                unreachable!("Ping loop never ends");
            }
        }

        info!("Finished plotting sector successfully");
    };

    inner_fut
        .instrument(info_span!("", %public_key, %sector_index))
        .await
}

async fn send_publish_progress(
    response_sender: &mut mpsc::Sender<ClusterSectorPlottingProgress>,
    progress: SectorPlottingProgress,
    approximate_max_message_size: usize,
) {
    // Finished response is large and needs special care
    let cluster_progress = match progress {
        SectorPlottingProgress::Downloading => ClusterSectorPlottingProgress::Downloading,
        SectorPlottingProgress::Downloaded(time) => ClusterSectorPlottingProgress::Downloaded(time),
        SectorPlottingProgress::Encoding => ClusterSectorPlottingProgress::Encoding,
        SectorPlottingProgress::Encoded(time) => ClusterSectorPlottingProgress::Encoded(time),
        SectorPlottingProgress::Finished {
            plotted_sector,
            time,
            mut sector,
        } => {
            if let Err(error) = response_sender
                .send(ClusterSectorPlottingProgress::Finished {
                    plotted_sector,
                    time,
                })
                .await
            {
                warn!(%error, "Failed to send plotting progress");
                return;
            }

            while let Some(maybe_sector_chunk) = sector.next().await {
                match maybe_sector_chunk {
                    Ok(sector_chunk) => {
                        // Slice large chunks into smaller ones before publishing
                        for small_sector_chunk in sector_chunk.chunks(approximate_max_message_size)
                        {
                            if let Err(error) = response_sender
                                .send(ClusterSectorPlottingProgress::SectorChunk(Ok(
                                    sector_chunk.slice_ref(small_sector_chunk)
                                )))
                                .await
                            {
                                warn!(%error, "Failed to send plotting progress");
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        if let Err(error) = response_sender
                            .send(ClusterSectorPlottingProgress::SectorChunk(Err(error)))
                            .await
                        {
                            warn!(%error, "Failed to send plotting progress");
                            return;
                        }
                    }
                }
            }

            return;
        }
        SectorPlottingProgress::Error { error } => ClusterSectorPlottingProgress::Error { error },
    };

    if let Err(error) = response_sender.send(cluster_progress).await {
        warn!(%error, "Failed to send plotting progress");
    }
}
