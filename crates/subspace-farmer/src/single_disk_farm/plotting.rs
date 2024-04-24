use crate::farm::{SectorExpirationDetails, SectorPlottingDetails, SectorUpdate};
use crate::plotter::{Plotter, SectorPlottingProgress};
#[cfg(windows)]
use crate::single_disk_farm::unbuffered_io_file_windows::UnbufferedIoFileWindows;
use crate::single_disk_farm::{
    BackgroundTaskError, Handlers, PlotMetadataHeader, RESERVED_PLOT_METADATA,
};
use crate::{node_client, NodeClient};
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesOrdered;
use futures::{select, FutureExt, SinkExt, StreamExt};
use lru::LruCache;
use parity_scale_codec::Encode;
use std::collections::{HashMap, HashSet};
#[cfg(not(windows))]
use std::fs::File;
use std::future::{pending, Future};
use std::io;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::{
    Blake3Hash, HistorySize, PieceOffset, PublicKey, SectorId, SectorIndex, SegmentHeader,
    SegmentIndex,
};
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

const FARMER_APP_INFO_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Size of the cache of archived segments for the purposes of faster sector expiration checks.
const ARCHIVED_SEGMENTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).expect("Not zero; qed");

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
        error: node_client::Error,
    },
    /// Failed to get segment header
    #[error("Failed to get segment header: {error}")]
    FailedToGetSegmentHeader {
        /// Lower-level error
        error: node_client::Error,
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
        error: node_client::Error,
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

pub(super) struct SectorPlottingOptions<'a, NC, P> {
    pub(super) public_key: PublicKey,
    pub(super) node_client: &'a NC,
    pub(super) pieces_in_sector: u16,
    pub(super) sector_size: usize,
    pub(super) sector_metadata_size: usize,
    #[cfg(not(windows))]
    pub(super) plot_file: &'a File,
    #[cfg(windows)]
    pub(super) plot_file: &'a UnbufferedIoFileWindows,
    #[cfg(not(windows))]
    pub(super) metadata_file: File,
    #[cfg(windows)]
    pub(super) metadata_file: UnbufferedIoFileWindows,
    pub(super) sectors_metadata: &'a AsyncRwLock<Vec<SectorMetadataChecksummed>>,
    pub(super) handlers: &'a Handlers,
    pub(super) sectors_being_modified: &'a AsyncRwLock<HashSet<SectorIndex>>,
    pub(super) global_mutex: &'a AsyncMutex<()>,
    pub(super) plotter: P,
}

pub(super) struct PlottingOptions<'a, NC, P> {
    pub(super) metadata_header: PlotMetadataHeader,
    pub(super) sectors_to_plot_receiver: mpsc::Receiver<SectorToPlot>,
    pub(super) sector_plotting_options: SectorPlottingOptions<'a, NC, P>,
}

/// Starts plotting process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn plotting<NC, P>(
    plotting_options: PlottingOptions<'_, NC, P>,
) -> Result<(), PlottingError>
where
    NC: NodeClient,
    P: Plotter,
{
    let PlottingOptions {
        mut metadata_header,
        mut sectors_to_plot_receiver,
        sector_plotting_options,
    } = plotting_options;

    let mut sectors_being_plotted = FuturesOrdered::new();

    // Wait for new sectors to plot from `sectors_to_plot_receiver` and wait for sectors that
    // already started plotting to finish plotting and then update metadata header
    loop {
        select! {
            maybe_sector_to_plot = sectors_to_plot_receiver.next() => {
                if let Some(sector_to_plot) = maybe_sector_to_plot {
                    let sector_plotting_init_fut = plot_single_sector(sector_to_plot, &sector_plotting_options).fuse();
                    let mut sector_plotting_init_fut = pin!(sector_plotting_init_fut);

                    // Wait for plotting of new sector to start (backpressure), while also waiting
                    // for sectors that already started plotting to finish plotting and then update
                    // metadata header
                    loop {
                        select! {
                            sector_plotting_init_result = sector_plotting_init_fut => {
                                sectors_being_plotted.push_back(sector_plotting_init_result?);
                                break;
                            }
                            maybe_sector_plotting_result = maybe_wait_futures_ordered(&mut sectors_being_plotted).fuse() => {
                                process_plotting_result(
                                    maybe_sector_plotting_result?,
                                    &mut metadata_header,
                                    &sector_plotting_options.metadata_file
                                )?;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            maybe_sector_plotting_result = maybe_wait_futures_ordered(&mut sectors_being_plotted).fuse() => {
                process_plotting_result(
                    maybe_sector_plotting_result?,
                    &mut metadata_header,
                    &sector_plotting_options.metadata_file
                )?;
            }
        }
    }

    Ok(())
}

fn process_plotting_result(
    sector_plotting_result: SectorPlottingResult,
    metadata_header: &mut PlotMetadataHeader,
    #[cfg(not(windows))] metadata_file: &File,
    #[cfg(windows)] metadata_file: &UnbufferedIoFileWindows,
) -> Result<(), PlottingError> {
    let SectorPlottingResult {
        sector_index,
        replotting,
        last_queued,
    } = sector_plotting_result;

    if sector_index + 1 > metadata_header.plotted_sector_count {
        metadata_header.plotted_sector_count = sector_index + 1;
        metadata_file.write_all_at(&metadata_header.encode(), 0)?;
    }

    if last_queued {
        if replotting {
            info!("Replotting complete");
        } else {
            info!("Initial plotting complete");
        }
    }

    Ok(())
}

/// Wait for next element in `FuturesOrdered`, but only if it is not empty. This avoids calling
/// `.poll_next()` if `FuturesOrdered` is already empty, so it can be reused indefinitely
async fn maybe_wait_futures_ordered<F>(stream: &mut FuturesOrdered<F>) -> F::Output
where
    F: Future,
{
    if stream.is_empty() {
        pending().await
    } else {
        stream.next().await.expect("Not empty; qed")
    }
}

struct SectorPlottingResult {
    sector_index: SectorIndex,
    replotting: bool,
    last_queued: bool,
}

async fn plot_single_sector<'a, NC, P>(
    sector_to_plot: SectorToPlot,
    sector_plotting_options: &'a SectorPlottingOptions<'a, NC, P>,
) -> Result<impl Future<Output = Result<SectorPlottingResult, PlottingError>> + 'a, PlottingError>
where
    NC: NodeClient,
    P: Plotter,
{
    let SectorPlottingOptions {
        public_key,
        node_client,
        pieces_in_sector,
        sector_size,
        sector_metadata_size,
        plot_file,
        metadata_file,
        sectors_metadata,
        handlers,
        sectors_being_modified,
        global_mutex,
        plotter,
    } = sector_plotting_options;

    let SectorToPlot {
        sector_index,
        progress,
        last_queued,
        acknowledgement_sender: _acknowledgement_sender,
    } = sector_to_plot;
    trace!(%sector_index, "Preparing to plot sector");

    let maybe_old_sector_metadata = sectors_metadata
        .read()
        .await
        .get(sector_index as usize)
        .cloned();
    let replotting = maybe_old_sector_metadata.is_some();

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
        let farmer_app_info = node_client
            .farmer_app_info()
            .await
            .map_err(|error| PlottingError::FailedToGetFarmerInfo { error })?;

        if let Some(old_sector_metadata) = &maybe_old_sector_metadata {
            if farmer_app_info.protocol_info.history_size <= old_sector_metadata.history_size {
                debug!(
                    current_history_size = %farmer_app_info.protocol_info.history_size,
                    old_sector_history_size = %old_sector_metadata.history_size,
                    "Latest protocol history size is not yet newer than old sector history \
                    size, wait for a bit and try again"
                );
                tokio::time::sleep(FARMER_APP_INFO_RETRY_INTERVAL).await;
                continue;
            }
        }

        break farmer_app_info;
    };

    let (progress_sender, mut progress_receiver) = mpsc::channel(0);

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
        info!(%sector_index, "Replotting sector ({progress:.2}% complete)");
    } else {
        info!(%sector_index, "Plotting sector ({progress:.2}% complete)");
    }

    Ok(async move {
        // Process plotting progress notifications
        let progress_processor_fut = async {
            while let Some(progress) = progress_receiver.next().await {
                match progress {
                    SectorPlottingProgress::Downloading => {
                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Plotting(SectorPlottingDetails::Downloading),
                        ));
                    }
                    SectorPlottingProgress::Downloaded(time) => {
                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Plotting(SectorPlottingDetails::Downloaded(time)),
                        ));
                    }
                    SectorPlottingProgress::Encoding => {
                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Plotting(SectorPlottingDetails::Encoding),
                        ));
                    }
                    SectorPlottingProgress::Encoded(time) => {
                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Plotting(SectorPlottingDetails::Encoded(time)),
                        ));
                    }
                    SectorPlottingProgress::Finished {
                        plotted_sector,
                        time: _,
                        sector,
                        sector_metadata,
                    } => {
                        return Ok((plotted_sector, sector, sector_metadata));
                    }
                    SectorPlottingProgress::Error { error } => {
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

        let (plotted_sector, sector, sector_metadata) = progress_processor_fut
            .await
            .map_err(PlottingError::LowLevel)?;

        // Inform others that this sector is being modified
        sectors_being_modified.write().await.insert(sector_index);

        {
            // Take mutex briefly to make sure writing is allowed right now
            global_mutex.lock().await;

            handlers.sector_update.call_simple(&(
                sector_index,
                SectorUpdate::Plotting(SectorPlottingDetails::Writing),
            ));

            let start = Instant::now();

            plot_file.write_all_at(&sector, (sector_index as usize * sector_size) as u64)?;
            metadata_file.write_all_at(
                &sector_metadata,
                RESERVED_PLOT_METADATA + (u64::from(sector_index) * *sector_metadata_size as u64),
            )?;

            handlers.sector_update.call_simple(&(
                sector_index,
                SectorUpdate::Plotting(SectorPlottingDetails::Written(start.elapsed())),
            ));
        }

        {
            let mut sectors_metadata = sectors_metadata.write().await;
            // If exists then we're replotting, otherwise we create sector for the first time
            if let Some(existing_sector_metadata) = sectors_metadata.get_mut(sector_index as usize)
            {
                *existing_sector_metadata = plotted_sector.sector_metadata.clone();
            } else {
                sectors_metadata.push(plotted_sector.sector_metadata.clone());
            }
        }

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

        // Inform others that this sector is no longer being modified
        sectors_being_modified.write().await.remove(&sector_index);

        if replotting {
            debug!(%sector_index, "Sector replotted successfully");
        } else {
            debug!(%sector_index, "Sector plotted successfully");
        }

        let sector_state = SectorUpdate::Plotting(SectorPlottingDetails::Finished {
            plotted_sector,
            old_plotted_sector: maybe_old_plotted_sector,
            time: start.elapsed(),
        });
        handlers
            .sector_update
            .call_simple(&(sector_index, sector_state));

        Ok(SectorPlottingResult {
            sector_index,
            replotting,
            last_queued,
        })
    })
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
    pub(super) initial_plotting_finished: Option<oneshot::Sender<()>>,
    // Delay between segment header being acknowledged by farmer and potentially triggering
    // replotting
    pub(super) new_segment_processing_delay: Duration,
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
        initial_plotting_finished,
        new_segment_processing_delay,
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
        initial_plotting_finished,
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
    initial_plotting_finished: Option<oneshot::Sender<()>>,
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

    if let Some(initial_plotting_finished) = initial_plotting_finished {
        // Doesn't matter if receiver is still around
        let _ = initial_plotting_finished.send(());
    }

    let mut sectors_expire_at =
        HashMap::<SectorIndex, SegmentIndex>::with_capacity(usize::from(target_sector_count));

    let mut sectors_to_replot = Vec::new();
    let mut sectors_to_check = Vec::with_capacity(usize::from(target_sector_count));
    let mut archived_segment_commitments_cache = LruCache::new(ARCHIVED_SEGMENTS_CACHE_SIZE);

    loop {
        let archived_segment_header = *archived_segments_receiver.borrow_and_update();
        trace!(
            segment_index = %archived_segment_header.segment_index(),
            "New archived segment received",
        );

        // It is fine to take a synchronous read lock here because the only time
        // write lock is taken is during plotting, which we know doesn't happen
        // right now. We copy data here because `.read()`'s guard is not `Send`.
        sectors_metadata
            .read()
            .await
            .iter()
            .map(|sector_metadata| (sector_metadata.sector_index, sector_metadata.history_size))
            .collect_into(&mut sectors_to_check);
        for (sector_index, history_size) in sectors_to_check.drain(..) {
            if let Some(expires_at) = sectors_expire_at.get(&sector_index).copied() {
                trace!(
                    %sector_index,
                    %history_size,
                    %expires_at,
                    "Checking sector for expiration"
                );
                // +1 means we will start replotting a bit before it actually expires to avoid
                // storing expired sectors
                if expires_at <= (archived_segment_header.segment_index() + SegmentIndex::ONE) {
                    debug!(
                        %sector_index,
                        %history_size,
                        %expires_at,
                        "Sector expires soon #1, scheduling replotting"
                    );

                    handlers.sector_update.call_simple(&(
                        sector_index,
                        SectorUpdate::Expiration(
                            if expires_at <= archived_segment_header.segment_index() {
                                SectorExpirationDetails::Expired
                            } else {
                                SectorExpirationDetails::AboutToExpire
                            },
                        ),
                    ));

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
                let maybe_sector_expiration_check_segment_commitment =
                    if let Some(segment_commitment) =
                        archived_segment_commitments_cache.get(&expiration_check_segment_index)
                    {
                        Some(*segment_commitment)
                    } else {
                        node_client
                            .segment_headers(vec![expiration_check_segment_index])
                            .await
                            .map_err(|error| PlottingError::FailedToGetSegmentHeader { error })?
                            .into_iter()
                            .next()
                            .flatten()
                            .map(|segment_header| {
                                let segment_commitment = segment_header.segment_commitment();

                                archived_segment_commitments_cache
                                    .push(expiration_check_segment_index, segment_commitment);
                                segment_commitment
                            })
                    };

                if let Some(sector_expiration_check_segment_commitment) =
                    maybe_sector_expiration_check_segment_commitment
                {
                    let sector_id = SectorId::new(public_key_hash, sector_index);
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
                    if expires_at <= (archived_segment_header.segment_index() + SegmentIndex::ONE) {
                        debug!(
                            %sector_index,
                            %history_size,
                            %expires_at,
                            "Sector expires soon #2, scheduling replotting"
                        );

                        handlers.sector_update.call_simple(&(
                            sector_index,
                            SectorUpdate::Expiration(
                                if expires_at <= archived_segment_header.segment_index() {
                                    SectorExpirationDetails::Expired
                                } else {
                                    SectorExpirationDetails::AboutToExpire
                                },
                            ),
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
                        sectors_expire_at.insert(sector_index, expires_at);
                    }
                }
            }
        }

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

            sectors_expire_at.remove(&sector_index);
        }

        if archived_segments_receiver.changed().await.is_err() {
            break;
        }
    }

    Ok(())
}
