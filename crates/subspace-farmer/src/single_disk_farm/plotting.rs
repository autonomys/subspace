use crate::farm::{SectorExpirationDetails, SectorPlottingDetails, SectorUpdate};
use crate::node_client::NodeClient;
use crate::plotter::{Plotter, SectorPlottingProgress};
use crate::single_disk_farm::direct_io_file::DirectIoFile;
use crate::single_disk_farm::metrics::{SectorState, SingleDiskFarmMetrics};
use crate::single_disk_farm::{
    BackgroundTaskError, Handlers, PlotMetadataHeader, RESERVED_PLOT_METADATA,
};
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock, Semaphore, SemaphoreGuard};
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesOrdered;
use futures::{select, FutureExt, SinkExt, StreamExt};
use parity_scale_codec::Encode;
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::hashes::Blake3Hash;
use subspace_core_primitives::pieces::PieceOffset;
use subspace_core_primitives::sectors::{SectorId, SectorIndex};
use subspace_core_primitives::segments::{HistorySize, SegmentHeader, SegmentIndex};
use subspace_core_primitives::PublicKey;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task;
use tracing::{debug, info, info_span, trace, warn, Instrument};

const FARMER_APP_INFO_RETRY_INTERVAL: Duration = Duration::from_millis(500);
const PLOTTING_RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) struct SectorToPlot {
    sector_index: SectorIndex,
    /// Progress so far in % (not including this sector)
    progress: f32,
    /// Whether this is the last sector queued so far
    last_queued: bool,
    acknowledgement_sender: oneshot::Sender<()>,
}

/// Errors that happen during plotting
#[derive(Debug, Error)]
pub enum PlottingError {
    /// Failed to retrieve farmer info
    #[error("Failed to retrieve farmer info: {error}")]
    FailedToGetFarmerInfo {
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Failed to get segment header
    #[error("Failed to get segment header: {error}")]
    FailedToGetSegmentHeader {
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Missing archived segment header
    #[error("Missing archived segment header: {segment_index}")]
    MissingArchivedSegmentHeader {
        /// Segment index that was missing
        segment_index: SegmentIndex,
    },
    /// Failed to subscribe to archived segments
    #[error("Failed to subscribe to archived segments: {error}")]
    FailedToSubscribeArchivedSegments {
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Low-level plotting error
    #[error("Low-level plotting error: {0}")]
    LowLevel(String),
    /// I/O error occurred
    #[error("Plotting I/O error: {0}")]
    Io(#[from] io::Error),
    /// Background downloading panicked
    #[error("Background downloading panicked")]
    BackgroundDownloadingPanicked,
}

pub(super) struct SectorPlottingOptions<'a, NC> {
    pub(super) public_key: PublicKey,
    pub(super) node_client: &'a NC,
    pub(super) pieces_in_sector: u16,
    pub(super) sector_size: usize,
    pub(super) plot_file: Arc<DirectIoFile>,
    pub(super) metadata_file: Arc<DirectIoFile>,
    pub(super) handlers: &'a Handlers,
    pub(super) global_mutex: &'a AsyncMutex<()>,
    pub(super) plotter: Arc<dyn Plotter>,
    pub(super) metrics: Option<Arc<SingleDiskFarmMetrics>>,
}

pub(super) struct PlottingOptions<'a, NC> {
    pub(super) metadata_header: PlotMetadataHeader,
    pub(super) sectors_metadata: &'a AsyncRwLock<Vec<SectorMetadataChecksummed>>,
    pub(super) sectors_being_modified: &'a AsyncRwLock<HashSet<SectorIndex>>,
    pub(super) sectors_to_plot_receiver: mpsc::Receiver<SectorToPlot>,
    pub(super) sector_plotting_options: SectorPlottingOptions<'a, NC>,
    pub(super) max_plotting_sectors_per_farm: NonZeroUsize,
}

/// Starts plotting process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn plotting<NC>(
    plotting_options: PlottingOptions<'_, NC>,
) -> Result<(), PlottingError>
where
    NC: NodeClient,
{
    let PlottingOptions {
        mut metadata_header,
        sectors_metadata,
        sectors_being_modified,
        mut sectors_to_plot_receiver,
        sector_plotting_options,
        max_plotting_sectors_per_farm,
    } = plotting_options;

    let sector_plotting_options = &sector_plotting_options;
    let plotting_semaphore = Semaphore::new(max_plotting_sectors_per_farm.get());
    let mut sectors_being_plotted = FuturesOrdered::new();
    // Channel size is intentionally unbounded for easier analysis, but it is bounded by plotting
    // semaphore in practice due to permit stored in `SectorPlottingResult`
    let (sector_plotting_result_sender, mut sector_plotting_result_receiver) = mpsc::unbounded();
    let process_plotting_result_fut = async move {
        while let Some(sector_plotting_result) = sector_plotting_result_receiver.next().await {
            process_plotting_result(
                sector_plotting_result,
                sectors_metadata,
                sectors_being_modified,
                &mut metadata_header,
                Arc::clone(&sector_plotting_options.metadata_file),
            )
            .await?;
        }

        unreachable!(
            "Stream will not end before the rest of the plotting process is shutting down"
        );
    };
    let process_plotting_result_fut = process_plotting_result_fut.fuse();
    let mut process_plotting_result_fut = pin!(process_plotting_result_fut);

    // Wait for new sectors to plot from `sectors_to_plot_receiver` and wait for sectors that
    // already started plotting to finish plotting and then update metadata header
    loop {
        select! {
            maybe_sector_to_plot = sectors_to_plot_receiver.next() => {
                let Some(sector_to_plot) = maybe_sector_to_plot else {
                    break;
                };

                let sector_index = sector_to_plot.sector_index;
                let sector_plotting_init_fut = plot_single_sector(
                    sector_to_plot,
                    sector_plotting_options,
                    sectors_metadata,
                    sectors_being_modified,
                    &plotting_semaphore,
                )
                    .instrument(info_span!("", %sector_index))
                    .fuse();
                let mut sector_plotting_init_fut = pin!(sector_plotting_init_fut);

                // Wait for plotting of new sector to start (backpressure), while also waiting
                // for sectors that already started plotting to finish plotting and then update
                // metadata header
                loop {
                    select! {
                        sector_plotting_init_result = sector_plotting_init_fut => {
                            let sector_plotting_fut = match sector_plotting_init_result {
                                PlotSingleSectorResult::Scheduled(future) => future,
                                PlotSingleSectorResult::Skipped => {
                                    break;
                                }
                                PlotSingleSectorResult::FatalError(error) => {
                                    return Err(error);
                                }
                            };
                            sectors_being_plotted.push_back(
                                sector_plotting_fut.instrument(info_span!("", %sector_index))
                            );
                            break;
                        }
                        maybe_sector_plotting_result = sectors_being_plotted.select_next_some() => {
                            sector_plotting_result_sender
                                .unbounded_send(maybe_sector_plotting_result?)
                                .expect("Sending means receiver is not dropped yet; qed");
                        }
                        result = process_plotting_result_fut => {
                            return result;
                        }
                    }
                }
            }
            maybe_sector_plotting_result = sectors_being_plotted.select_next_some() => {
                sector_plotting_result_sender
                    .unbounded_send(maybe_sector_plotting_result?)
                    .expect("Sending means receiver is not dropped yet; qed");
            }
            result = process_plotting_result_fut => {
                return result;
            }
        }
    }

    Ok(())
}

async fn process_plotting_result(
    sector_plotting_result: SectorPlottingResult<'_>,
    sectors_metadata: &AsyncRwLock<Vec<SectorMetadataChecksummed>>,
    sectors_being_modified: &AsyncRwLock<HashSet<SectorIndex>>,
    metadata_header: &mut PlotMetadataHeader,
    metadata_file: Arc<DirectIoFile>,
) -> Result<(), PlottingError> {
    let SectorPlottingResult {
        sector_metadata,
        replotting,
        last_queued,
        plotting_permit,
    } = sector_plotting_result;

    let sector_index = sector_metadata.sector_index;

    {
        let mut sectors_metadata = sectors_metadata.write().await;
        // If exists then we're replotting, otherwise we create sector for the first time
        if let Some(existing_sector_metadata) = sectors_metadata.get_mut(sector_index as usize) {
            *existing_sector_metadata = sector_metadata;
        } else {
            sectors_metadata.push(sector_metadata);
        }
    }

    // Inform others that this sector is no longer being modified
    sectors_being_modified.write().await.remove(&sector_index);

    if sector_index + 1 > metadata_header.plotted_sector_count {
        metadata_header.plotted_sector_count = sector_index + 1;

        let encoded_metadata_header = metadata_header.encode();
        let write_fut =
            task::spawn_blocking(move || metadata_file.write_all_at(&encoded_metadata_header, 0));
        write_fut.await.map_err(|error| {
            PlottingError::LowLevel(format!("Failed to spawn blocking tokio task: {error}"))
        })??;
    }

    if last_queued {
        if replotting {
            info!("Replotting complete");
        } else {
            info!("Initial plotting complete");
        }
    }

    drop(plotting_permit);

    Ok(())
}

enum PlotSingleSectorResult<F> {
    Scheduled(F),
    Skipped,
    FatalError(PlottingError),
}

struct SectorPlottingResult<'a> {
    sector_metadata: SectorMetadataChecksummed,
    replotting: bool,
    last_queued: bool,
    plotting_permit: SemaphoreGuard<'a>,
}

async fn plot_single_sector<'a, NC>(
    sector_to_plot: SectorToPlot,
    sector_plotting_options: &'a SectorPlottingOptions<'a, NC>,
    sectors_metadata: &'a AsyncRwLock<Vec<SectorMetadataChecksummed>>,
    sectors_being_modified: &'a AsyncRwLock<HashSet<SectorIndex>>,
    plotting_semaphore: &'a Semaphore,
) -> PlotSingleSectorResult<
    impl Future<Output = Result<SectorPlottingResult<'a>, PlottingError>> + 'a,
>
where
    NC: NodeClient,
{
    let SectorPlottingOptions {
        public_key,
        node_client,
        pieces_in_sector,
        sector_size,
        plot_file,
        metadata_file,
        handlers,
        global_mutex,
        plotter,
        metrics,
    } = sector_plotting_options;

    let SectorToPlot {
        sector_index,
        progress,
        last_queued,
        acknowledgement_sender: _acknowledgement_sender,
    } = sector_to_plot;
    trace!("Preparing to plot sector");

    // Inform others that this sector is being modified
    {
        let mut sectors_being_modified = sectors_being_modified.write().await;
        if !sectors_being_modified.insert(sector_index) {
            debug!("Skipped sector plotting, it is already in progress");
            return PlotSingleSectorResult::Skipped;
        }
    }

    let plotting_permit = plotting_semaphore.acquire().await;

    let maybe_old_sector_metadata = sectors_metadata
        .read()
        .await
        .get(sector_index as usize)
        .cloned();
    let replotting = maybe_old_sector_metadata.is_some();

    if let Some(metrics) = metrics {
        metrics.sector_plotting.inc();
    }
    let sector_state = SectorUpdate::Plotting(SectorPlottingDetails::Starting {
        progress,
        replotting,
        last_queued,
    });
    handlers
        .sector_update
        .call_simple(&(sector_index, sector_state));

    let start = Instant::now();

    // This `loop` is a workaround for edge-case in local setup if expiration is configured to 1.
    // In that scenario we get replotting notification essentially straight from block import
    // pipeline of the node, before block is imported. This can result in subsequent request for
    // farmer app info to return old data, meaning we're replotting exactly the same sector that
    // just expired.
    let farmer_app_info = loop {
        let farmer_app_info = match node_client.farmer_app_info().await {
            Ok(farmer_app_info) => farmer_app_info,
            Err(error) => {
                return PlotSingleSectorResult::FatalError(PlottingError::FailedToGetFarmerInfo {
                    error,
                });
            }
        };

        if let Some(old_sector_metadata) = &maybe_old_sector_metadata {
            if farmer_app_info.protocol_info.history_size <= old_sector_metadata.history_size {
                if farmer_app_info.protocol_info.min_sector_lifetime == HistorySize::ONE {
                    debug!(
                        current_history_size = %farmer_app_info.protocol_info.history_size,
                        old_sector_history_size = %old_sector_metadata.history_size,
                        "Latest protocol history size is not yet newer than old sector history \
                        size, wait for a bit and try again"
                    );
                    tokio::time::sleep(FARMER_APP_INFO_RETRY_INTERVAL).await;
                    continue;
                } else {
                    debug!(
                        current_history_size = %farmer_app_info.protocol_info.history_size,
                        old_sector_history_size = %old_sector_metadata.history_size,
                        "Skipped sector plotting, likely redundant due to redundant archived \
                        segment notification"
                    );
                    return PlotSingleSectorResult::Skipped;
                }
            }
        }

        break farmer_app_info;
    };

    let (progress_sender, mut progress_receiver) = mpsc::channel(10);

    // Initiate plotting
    plotter
        .plot_sector(
            *public_key,
            sector_index,
            farmer_app_info.protocol_info,
            *pieces_in_sector,
            replotting,
            progress_sender,
        )
        .await;

    if replotting {
        info!("Replotting sector ({progress:.2}% complete)");
    } else {
        info!("Plotting sector ({progress:.2}% complete)");
    }

    PlotSingleSectorResult::Scheduled(async move {
        let plotted_sector = loop {
            match plot_single_sector_internal(
                sector_index,
                *sector_size,
                plot_file,
                metadata_file,
                handlers,
                global_mutex,
                progress_receiver,
                metrics,
            )
            .await?
            {
                Ok(plotted_sector) => {
                    break plotted_sector;
                }
                Err(error) => {
                    warn!(
                        %error,
                        "Failed to plot sector, retrying in {PLOTTING_RETRY_DELAY:?}"
                    );

                    tokio::time::sleep(PLOTTING_RETRY_DELAY).await;
                }
            }

            let (retry_progress_sender, retry_progress_receiver) = mpsc::channel(10);
            progress_receiver = retry_progress_receiver;

            // Initiate plotting
            plotter
                .plot_sector(
                    *public_key,
                    sector_index,
                    farmer_app_info.protocol_info,
                    *pieces_in_sector,
                    replotting,
                    retry_progress_sender,
                )
                .await;

            if replotting {
                info!("Replotting sector retry");
            } else {
                info!("Plotting sector retry");
            }
        };

        let maybe_old_plotted_sector = maybe_old_sector_metadata.map(|old_sector_metadata| {
            let old_history_size = old_sector_metadata.history_size;

            PlottedSector {
                sector_id: plotted_sector.sector_id,
                sector_index: plotted_sector.sector_index,
                sector_metadata: old_sector_metadata,
                piece_indexes: {
                    let mut piece_indexes = Vec::with_capacity(usize::from(*pieces_in_sector));
                    (PieceOffset::ZERO..)
                        .take(usize::from(*pieces_in_sector))
                        .map(|piece_offset| {
                            plotted_sector.sector_id.derive_piece_index(
                                piece_offset,
                                old_history_size,
                                farmer_app_info.protocol_info.max_pieces_in_sector,
                                farmer_app_info.protocol_info.recent_segments,
                                farmer_app_info.protocol_info.recent_history_fraction,
                            )
                        })
                        .collect_into(&mut piece_indexes);
                    piece_indexes
                },
            }
        });

        if replotting {
            debug!("Sector replotted successfully");
        } else {
            debug!("Sector plotted successfully");
        }

        let sector_metadata = plotted_sector.sector_metadata.clone();

        let time = start.elapsed();
        if let Some(metrics) = metrics {
            metrics.sector_plotting_time.observe(time.as_secs_f64());
            metrics.sector_plotted.inc();
            metrics.update_sector_state(SectorState::Plotted);
        }
        let sector_state = SectorUpdate::Plotting(SectorPlottingDetails::Finished {
            plotted_sector,
            old_plotted_sector: maybe_old_plotted_sector,
            time,
        });
        handlers
            .sector_update
            .call_simple(&(sector_index, sector_state));

        Ok(SectorPlottingResult {
            sector_metadata,
            replotting,
            last_queued,
            plotting_permit,
        })
    })
}

/// Outer error is used to indicate irrecoverable plotting errors, while inner result is for
/// recoverable errors
#[allow(clippy::too_many_arguments)]
async fn plot_single_sector_internal(
    sector_index: SectorIndex,
    sector_size: usize,
    plot_file: &Arc<DirectIoFile>,
    metadata_file: &Arc<DirectIoFile>,
    handlers: &Handlers,
    global_mutex: &AsyncMutex<()>,
    mut progress_receiver: mpsc::Receiver<SectorPlottingProgress>,
    metrics: &Option<Arc<SingleDiskFarmMetrics>>,
) -> Result<Result<PlottedSector, PlottingError>, PlottingError> {
    // Process plotting progress notifications
    let progress_processor_fut = async {
        while let Some(progress) = progress_receiver.next().await {
            match progress {
                SectorPlottingProgress::Downloading => {
                    if let Some(metrics) = metrics {
                        metrics.sector_downloading.inc();
                    }
                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Plotting(SectorPlottingDetails::Downloading),
                    ));
                }
                SectorPlottingProgress::Downloaded(time) => {
                    if let Some(metrics) = metrics {
                        metrics.sector_downloading_time.observe(time.as_secs_f64());
                        metrics.sector_downloaded.inc();
                    }
                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Plotting(SectorPlottingDetails::Downloaded(time)),
                    ));
                }
                SectorPlottingProgress::Encoding => {
                    if let Some(metrics) = metrics {
                        metrics.sector_encoding.inc();
                    }
                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Plotting(SectorPlottingDetails::Encoding),
                    ));
                }
                SectorPlottingProgress::Encoded(time) => {
                    if let Some(metrics) = metrics {
                        metrics.sector_encoding_time.observe(time.as_secs_f64());
                        metrics.sector_encoded.inc();
                    }
                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Plotting(SectorPlottingDetails::Encoded(time)),
                    ));
                }
                SectorPlottingProgress::Finished {
                    plotted_sector,
                    time: _,
                    sector,
                } => {
                    return Ok((plotted_sector, sector));
                }
                SectorPlottingProgress::Error { error } => {
                    if let Some(metrics) = metrics {
                        metrics.sector_plotting_error.inc();
                    }
                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Plotting(SectorPlottingDetails::Error(error.clone())),
                    ));
                    return Err(error);
                }
            }
        }

        Err("Plotting progress stream ended before plotting finished".to_string())
    };

    let (plotted_sector, mut sector) = match progress_processor_fut.await {
        Ok(result) => result,
        Err(error) => {
            return Ok(Err(PlottingError::LowLevel(error)));
        }
    };

    {
        // Take mutex briefly to make sure writing is allowed right now
        global_mutex.lock().await;

        if let Some(metrics) = metrics {
            metrics.sector_writing.inc();
        }
        handlers.sector_update.call_simple(&(
            sector_index,
            SectorUpdate::Plotting(SectorPlottingDetails::Writing),
        ));

        let start = Instant::now();

        {
            let sector_write_base_offset = u64::from(sector_index) * sector_size as u64;
            let mut total_received = 0;
            let mut sector_write_offset = sector_write_base_offset;
            while let Some(maybe_sector_chunk) = sector.next().await {
                let sector_chunk = match maybe_sector_chunk {
                    Ok(sector_chunk) => sector_chunk,
                    Err(error) => {
                        return Ok(Err(PlottingError::LowLevel(format!(
                            "Sector chunk receive error: {error}"
                        ))));
                    }
                };

                total_received += sector_chunk.len();

                if total_received > sector_size {
                    return Ok(Err(PlottingError::LowLevel(format!(
                        "Received too many bytes {total_received} instead of expected \
                        {sector_size} bytes"
                    ))));
                }

                let sector_chunk_size = sector_chunk.len() as u64;

                trace!(sector_chunk_size, "Writing sector chunk to disk");
                let write_fut = task::spawn_blocking({
                    let plot_file = Arc::clone(plot_file);

                    move || plot_file.write_all_at(&sector_chunk, sector_write_offset)
                });
                write_fut.await.map_err(|error| {
                    PlottingError::LowLevel(format!("Failed to spawn blocking tokio task: {error}"))
                })??;

                sector_write_offset += sector_chunk_size;
            }
            drop(sector);

            if total_received != sector_size {
                return Ok(Err(PlottingError::LowLevel(format!(
                    "Received only {total_received} sector bytes out of {sector_size} \
                    expected bytes"
                ))));
            }
        }
        {
            let encoded_sector_metadata = plotted_sector.sector_metadata.encode();
            let write_fut = task::spawn_blocking({
                let metadata_file = Arc::clone(metadata_file);

                move || {
                    metadata_file.write_all_at(
                        &encoded_sector_metadata,
                        RESERVED_PLOT_METADATA
                            + (u64::from(sector_index) * encoded_sector_metadata.len() as u64),
                    )
                }
            });
            write_fut.await.map_err(|error| {
                PlottingError::LowLevel(format!("Failed to spawn blocking tokio task: {error}"))
            })??;
        }

        let time = start.elapsed();
        if let Some(metrics) = metrics {
            metrics.sector_writing_time.observe(time.as_secs_f64());
            metrics.sector_written.inc();
        }
        handlers.sector_update.call_simple(&(
            sector_index,
            SectorUpdate::Plotting(SectorPlottingDetails::Written(time)),
        ));
    }

    Ok(Ok(plotted_sector))
}

pub(super) struct PlottingSchedulerOptions<NC> {
    pub(super) public_key_hash: Blake3Hash,
    pub(super) sectors_indices_left_to_plot: Range<SectorIndex>,
    pub(super) target_sector_count: SectorIndex,
    pub(super) last_archived_segment_index: SegmentIndex,
    pub(super) min_sector_lifetime: HistorySize,
    pub(super) node_client: NC,
    pub(super) handlers: Arc<Handlers>,
    pub(super) sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) sectors_to_plot_sender: mpsc::Sender<SectorToPlot>,
    // Delay between segment header being acknowledged by farmer and potentially triggering
    // replotting
    pub(super) new_segment_processing_delay: Duration,
    pub(super) metrics: Option<Arc<SingleDiskFarmMetrics>>,
}

pub(super) async fn plotting_scheduler<NC>(
    plotting_scheduler_options: PlottingSchedulerOptions<NC>,
) -> Result<(), BackgroundTaskError>
where
    NC: NodeClient,
{
    let PlottingSchedulerOptions {
        public_key_hash,
        sectors_indices_left_to_plot,
        target_sector_count,
        last_archived_segment_index,
        min_sector_lifetime,
        node_client,
        handlers,
        sectors_metadata,
        sectors_to_plot_sender,
        new_segment_processing_delay,
        metrics,
    } = plotting_scheduler_options;

    // Create a proxy channel with atomically updatable last archived segment that
    // allows to not buffer messages from RPC subscription, but also access the most
    // recent value at any time
    let last_archived_segment = node_client
        .segment_headers(vec![last_archived_segment_index])
        .await
        .map_err(|error| PlottingError::FailedToGetSegmentHeader { error })?
        .into_iter()
        .next()
        .flatten()
        .ok_or(PlottingError::MissingArchivedSegmentHeader {
            segment_index: last_archived_segment_index,
        })?;

    let (archived_segments_sender, archived_segments_receiver) =
        watch::channel(last_archived_segment);

    let read_archived_segments_notifications_fut = read_archived_segments_notifications(
        &node_client,
        archived_segments_sender,
        new_segment_processing_delay,
    );

    let send_plotting_notifications_fut = send_plotting_notifications(
        public_key_hash,
        sectors_indices_left_to_plot,
        target_sector_count,
        min_sector_lifetime,
        &node_client,
        &handlers,
        sectors_metadata,
        archived_segments_receiver,
        sectors_to_plot_sender,
        &metrics,
    );

    select! {
        result = read_archived_segments_notifications_fut.fuse() => {
            result
        }
        result = send_plotting_notifications_fut.fuse() => {
            result
        }
    }
}

async fn read_archived_segments_notifications<NC>(
    node_client: &NC,
    archived_segments_sender: watch::Sender<SegmentHeader>,
    new_segment_processing_delay: Duration,
) -> Result<(), BackgroundTaskError>
where
    NC: NodeClient,
{
    info!("Subscribing to archived segments");

    let mut archived_segments_notifications = node_client
        .subscribe_archived_segment_headers()
        .await
        .map_err(|error| PlottingError::FailedToSubscribeArchivedSegments { error })?;

    while let Some(segment_header) = archived_segments_notifications.next().await {
        debug!(?segment_header, "New archived segment");
        if let Err(error) = node_client
            .acknowledge_archived_segment_header(segment_header.segment_index())
            .await
        {
            debug!(%error, "Failed to acknowledge segment header");
        }

        // There is no urgent need to rush replotting sectors immediately and this delay allows for
        // newly archived pieces to be both cached locally and on other farmers on the network
        tokio::time::sleep(new_segment_processing_delay).await;

        if archived_segments_sender.send(segment_header).is_err() {
            break;
        }
    }

    Ok(())
}

struct SectorToReplot {
    sector_index: SectorIndex,
    expires_at: SegmentIndex,
}

#[allow(clippy::too_many_arguments)]
async fn send_plotting_notifications<NC>(
    public_key_hash: Blake3Hash,
    sectors_indices_left_to_plot: Range<SectorIndex>,
    target_sector_count: SectorIndex,
    min_sector_lifetime: HistorySize,
    node_client: &NC,
    handlers: &Handlers,
    sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    mut archived_segments_receiver: watch::Receiver<SegmentHeader>,
    mut sectors_to_plot_sender: mpsc::Sender<SectorToPlot>,
    metrics: &Option<Arc<SingleDiskFarmMetrics>>,
) -> Result<(), BackgroundTaskError>
where
    NC: NodeClient,
{
    // Finish initial plotting if some sectors were not plotted fully yet
    for sector_index in sectors_indices_left_to_plot {
        let (acknowledgement_sender, acknowledgement_receiver) = oneshot::channel();
        if let Err(error) = sectors_to_plot_sender
            .send(SectorToPlot {
                sector_index,
                progress: sector_index as f32 / target_sector_count as f32 * 100.0,
                last_queued: sector_index + 1 == target_sector_count,
                acknowledgement_sender,
            })
            .await
        {
            warn!(%error, "Failed to send sector index for initial plotting");
            return Ok(());
        }

        // We do not care if message was sent back or sender was just dropped
        let _ = acknowledgement_receiver.await;
    }

    let mut sectors_expire_at = vec![None::<SegmentIndex>; usize::from(target_sector_count)];
    // 10% capacity is generous and should prevent reallocation in most cases
    let mut sectors_to_replot = Vec::with_capacity(usize::from(target_sector_count) / 10);

    loop {
        let segment_index = archived_segments_receiver
            .borrow_and_update()
            .segment_index();
        trace!(%segment_index, "New archived segment received");

        let sectors_metadata = sectors_metadata.read().await;
        let sectors_to_check = sectors_metadata
            .iter()
            .map(|sector_metadata| (sector_metadata.sector_index, sector_metadata.history_size));
        for (sector_index, history_size) in sectors_to_check {
            if let Some(Some(expires_at)) =
                sectors_expire_at.get(usize::from(sector_index)).copied()
            {
                trace!(
                    %sector_index,
                    %history_size,
                    %expires_at,
                    "Checking sector for expiration"
                );
                // +1 means we will start replotting a bit before it actually expires to avoid
                // storing expired sectors
                if expires_at <= (segment_index + SegmentIndex::ONE) {
                    debug!(
                        %sector_index,
                        %history_size,
                        %expires_at,
                        "Sector expires soon #1, scheduling replotting"
                    );

                    let expiration_details = if expires_at <= segment_index {
                        if let Some(metrics) = metrics {
                            metrics.update_sector_state(SectorState::Expired);
                        }
                        SectorExpirationDetails::Expired
                    } else {
                        if let Some(metrics) = metrics {
                            metrics.update_sector_state(SectorState::AboutToExpire);
                        }
                        SectorExpirationDetails::AboutToExpire
                    };
                    handlers
                        .sector_update
                        .call_simple(&(sector_index, SectorUpdate::Expiration(expiration_details)));

                    // Time to replot
                    sectors_to_replot.push(SectorToReplot {
                        sector_index,
                        expires_at,
                    });
                }
                continue;
            }

            if let Some(expiration_check_segment_index) = history_size
                .sector_expiration_check(min_sector_lifetime)
                .map(|expiration_check_history_size| expiration_check_history_size.segment_index())
            {
                trace!(
                    %sector_index,
                    %history_size,
                    %expiration_check_segment_index,
                    "Determined sector expiration check segment index"
                );
                let maybe_sector_expiration_check_segment_commitment = node_client
                    .segment_headers(vec![expiration_check_segment_index])
                    .await
                    .map_err(|error| PlottingError::FailedToGetSegmentHeader { error })?
                    .into_iter()
                    .next()
                    .flatten()
                    .map(|segment_header| segment_header.segment_commitment());

                if let Some(sector_expiration_check_segment_commitment) =
                    maybe_sector_expiration_check_segment_commitment
                {
                    let sector_id = SectorId::new(public_key_hash, sector_index, history_size);
                    let expiration_history_size = sector_id
                        .derive_expiration_history_size(
                            history_size,
                            &sector_expiration_check_segment_commitment,
                            min_sector_lifetime,
                        )
                        .expect(
                            "Farmers internally stores correct history size in sector \
                            metadata; qed",
                        );

                    let expires_at = expiration_history_size.segment_index();

                    trace!(
                        %sector_index,
                        %history_size,
                        sector_expire_at = %expires_at,
                        "Determined sector expiration segment index"
                    );
                    // +1 means we will start replotting a bit before it actually expires to avoid
                    // storing expired sectors
                    if expires_at <= (segment_index + SegmentIndex::ONE) {
                        debug!(
                            %sector_index,
                            %history_size,
                            %expires_at,
                            "Sector expires soon #2, scheduling replotting"
                        );

                        let expiration_details = if expires_at <= segment_index {
                            if let Some(metrics) = metrics {
                                metrics.update_sector_state(SectorState::Expired);
                            }
                            SectorExpirationDetails::Expired
                        } else {
                            if let Some(metrics) = metrics {
                                metrics.update_sector_state(SectorState::AboutToExpire);
                            }
                            SectorExpirationDetails::AboutToExpire
                        };
                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Expiration(expiration_details),
                        ));

                        // Time to replot
                        sectors_to_replot.push(SectorToReplot {
                            sector_index,
                            expires_at,
                        });
                    } else {
                        trace!(
                            %sector_index,
                            %history_size,
                            sector_expire_at = %expires_at,
                            "Sector expires later, remembering sector expiration"
                        );

                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Expiration(SectorExpirationDetails::Determined {
                                expires_at,
                            }),
                        ));

                        // Store expiration so we don't have to recalculate it later
                        if let Some(expires_at_entry) =
                            sectors_expire_at.get_mut(usize::from(sector_index))
                        {
                            expires_at_entry.replace(expires_at);
                        }
                    }
                }
            }
        }
        drop(sectors_metadata);

        let sectors_queued = sectors_to_replot.len();
        sectors_to_replot.sort_by_key(|sector_to_replot| sector_to_replot.expires_at);
        for (index, SectorToReplot { sector_index, .. }) in sectors_to_replot.drain(..).enumerate()
        {
            let (acknowledgement_sender, acknowledgement_receiver) = oneshot::channel();
            if let Err(error) = sectors_to_plot_sender
                .send(SectorToPlot {
                    sector_index,
                    progress: index as f32 / sectors_queued as f32 * 100.0,
                    last_queued: index + 1 == sectors_queued,
                    acknowledgement_sender,
                })
                .await
            {
                warn!(%error, "Failed to send sector index for replotting");
                return Ok(());
            }

            // We do not care if message was sent back or sender was just dropped
            let _ = acknowledgement_receiver.await;

            if let Some(expires_at_entry) = sectors_expire_at.get_mut(usize::from(sector_index)) {
                expires_at_entry.take();
            }
        }

        if archived_segments_receiver.changed().await.is_err() {
            break;
        }
    }

    Ok(())
}
