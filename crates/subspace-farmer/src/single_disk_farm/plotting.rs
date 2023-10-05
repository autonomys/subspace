use crate::single_disk_farm::{
    BackgroundTaskError, Handlers, PlotMetadataHeader, RESERVED_PLOT_METADATA,
};
use crate::{node_client, NodeClient};
use atomic::Atomic;
use futures::channel::{mpsc, oneshot};
use futures::{select, FutureExt, SinkExt, StreamExt};
use lru::LruCache;
use parity_scale_codec::Encode;
use parking_lot::RwLock;
use rayon::ThreadPool;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::num::{NonZeroU16, NonZeroUsize};
use std::ops::Range;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Blake2b256Hash, HistorySize, PieceOffset, PublicKey, SectorId, SectorIndex, SegmentHeader,
    SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::plotting;
use subspace_farmer_components::plotting::{
    plot_sector, PieceGetter, PieceGetterRetryPolicy, PlottedSector,
};
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_proof_of_space::Table;
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::{debug, info, trace, warn};

const FARMER_APP_INFO_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Size of the cache of archived segments for the purposes of faster sector expiration checks.
const ARCHIVED_SEGMENTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).expect("Not zero; qed");
/// Get piece retry attempts number.
const PIECE_GETTER_RETRY_NUMBER: NonZeroU16 = NonZeroU16::new(3).expect("Not zero; qed");

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
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Low-level plotting error
    #[error("Low-level plotting error: {0}")]
    LowLevel(#[from] plotting::PlottingError),
}

pub(super) struct PlottingOptions<NC, PG> {
    pub(super) public_key: PublicKey,
    pub(super) node_client: NC,
    pub(super) pieces_in_sector: u16,
    pub(super) sector_size: usize,
    pub(super) sector_metadata_size: usize,
    pub(super) metadata_header: PlotMetadataHeader,
    pub(super) plot_file: Arc<File>,
    pub(super) metadata_file: File,
    pub(super) sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) piece_getter: PG,
    pub(super) kzg: Kzg,
    pub(super) erasure_coding: ErasureCoding,
    pub(super) handlers: Arc<Handlers>,
    pub(super) modifying_sector_index: Arc<RwLock<Option<SectorIndex>>>,
    pub(super) target_sector_count: u16,
    pub(super) sectors_to_plot_receiver: mpsc::Receiver<(SectorIndex, oneshot::Sender<()>)>,
    pub(super) plotting_thread_pool: Arc<ThreadPool>,
    pub(super) replotting_thread_pool: Arc<ThreadPool>,
}

/// Starts plotting process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn plotting<NC, PG, PosTable>(
    plotting_options: PlottingOptions<NC, PG>,
) -> Result<(), PlottingError>
where
    NC: NodeClient,
    PG: PieceGetter + Clone + Send + 'static,
    PosTable: Table,
{
    let PlottingOptions {
        public_key,
        node_client,
        pieces_in_sector,
        sector_size,
        sector_metadata_size,
        mut metadata_header,
        plot_file,
        metadata_file,
        sectors_metadata,
        piece_getter,
        kzg,
        erasure_coding,
        handlers,
        modifying_sector_index,
        target_sector_count,
        mut sectors_to_plot_receiver,
        plotting_thread_pool,
        replotting_thread_pool,
    } = plotting_options;

    let mut table_generator = PosTable::generator();
    // TODO: Concurrency
    while let Some((sector_index, _acknowledgement_sender)) = sectors_to_plot_receiver.next().await
    {
        trace!(%sector_index, "Preparing to plot sector");

        let maybe_old_sector_metadata = sectors_metadata.read().get(sector_index as usize).cloned();
        let replotting = maybe_old_sector_metadata.is_some();

        if replotting {
            debug!(%sector_index, "Replotting sector");
        } else {
            debug!(%sector_index, "Plotting sector");
        }

        // This `loop` is a workaround for edge-case in local setup if expiration is configured to
        // 1. In that scenario we get replotting notification essentially straight from block import
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

        // Inform others that this sector is being modified
        modifying_sector_index.write().replace(sector_index);

        let sector;
        let sector_metadata;
        let plotted_sector;

        (sector, sector_metadata, table_generator, plotted_sector) = {
            let mut sector = Vec::new();
            let mut sector_metadata = Vec::new();

            let piece_getter = piece_getter.clone();
            let kzg = kzg.clone();
            let erasure_coding = erasure_coding.clone();

            let plotting_fn = move || {
                tokio::task::block_in_place(move || {
                    let plot_sector_fut = plot_sector::<_, PosTable>(
                        &public_key,
                        sector_index,
                        &piece_getter,
                        PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
                        &farmer_app_info.protocol_info,
                        &kzg,
                        &erasure_coding,
                        pieces_in_sector,
                        &mut sector,
                        &mut sector_metadata,
                        &mut table_generator,
                    );

                    Handle::current()
                        .block_on(plot_sector_fut)
                        .map(|plotted_sector| {
                            (sector, sector_metadata, table_generator, plotted_sector)
                        })
                })
            };

            if replotting {
                replotting_thread_pool.install(plotting_fn)?
            } else {
                plotting_thread_pool.install(plotting_fn)?
            }
        };

        plot_file.write_all_at(&sector, (sector_index as usize * sector_size) as u64)?;
        metadata_file.write_all_at(
            &sector_metadata,
            RESERVED_PLOT_METADATA + (u64::from(sector_index) * sector_metadata_size as u64),
        )?;

        if sector_index + 1 > metadata_header.plotted_sector_count {
            metadata_header.plotted_sector_count = sector_index + 1;
            metadata_file.write_all_at(&metadata_header.encode(), 0)?;
        }
        {
            let mut sectors_metadata = sectors_metadata.write();
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
                    let mut piece_indexes = Vec::with_capacity(usize::from(pieces_in_sector));
                    (PieceOffset::ZERO..)
                        .take(usize::from(pieces_in_sector))
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
        modifying_sector_index.write().take();

        if replotting {
            info!(%sector_index, "Sector replotted successfully");
        } else {
            info!(
                %sector_index,
                "Sector plotted successfully ({:.2}%)",
                (sector_index + 1) as f32 / target_sector_count as f32 * 100.0
            );
        }

        handlers
            .sector_plotted
            .call_simple(&(plotted_sector, maybe_old_plotted_sector));
    }

    Ok(())
}

pub(super) struct PlottingSchedulerOptions<NC> {
    pub(super) public_key_hash: Blake2b256Hash,
    pub(super) sectors_indices_left_to_plot: Range<SectorIndex>,
    pub(super) target_sector_count: SectorIndex,
    pub(super) last_archived_segment_index: SegmentIndex,
    pub(super) min_sector_lifetime: HistorySize,
    pub(super) node_client: NC,
    pub(super) sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) sectors_to_plot_sender: mpsc::Sender<(SectorIndex, oneshot::Sender<()>)>,
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
        sectors_metadata,
        sectors_to_plot_sender,
    } = plotting_scheduler_options;

    // Create a proxy channel with atomically updatable last archived segment that
    // allows to not buffer messages from RPC subscription, but also access the most
    // recent value at any time
    let last_archived_segment = Atomic::new(
        node_client
            .segment_headers(vec![last_archived_segment_index])
            .await
            .map_err(|error| PlottingError::FailedToGetSegmentHeader { error })?
            .into_iter()
            .next()
            .flatten()
            .ok_or(PlottingError::MissingArchivedSegmentHeader {
                segment_index: last_archived_segment_index,
            })?,
    );
    let (mut archived_segments_sender, archived_segments_receiver) = mpsc::channel(0);
    archived_segments_sender
        .try_send(())
        .expect("No messages were sent yet, there is capacity for one message; qed");

    let read_archived_segments_notifications_fut = read_archived_segments_notifications(
        &node_client,
        &last_archived_segment,
        archived_segments_sender,
    );

    let (sectors_to_plot_proxy_sender, sectors_to_plot_proxy_receiver) = mpsc::channel(0);

    let pause_plotting_if_node_not_synced_fut = pause_plotting_if_node_not_synced(
        &node_client,
        sectors_to_plot_proxy_receiver,
        sectors_to_plot_sender,
    );

    let send_plotting_notifications_fut = send_plotting_notifications(
        public_key_hash,
        sectors_indices_left_to_plot,
        target_sector_count,
        min_sector_lifetime,
        &node_client,
        sectors_metadata,
        &last_archived_segment,
        archived_segments_receiver,
        sectors_to_plot_proxy_sender,
    );

    select! {
        result = pause_plotting_if_node_not_synced_fut.fuse() => {
            result
        }
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
    last_archived_segment: &Atomic<SegmentHeader>,
    mut archived_segments_sender: mpsc::Sender<()>,
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

        last_archived_segment.store(segment_header, Ordering::SeqCst);
        // Just a notification such that receiving side can read updated
        // `last_archived_segment` (whatever it happens to be right now)
        if let Err(error) = archived_segments_sender.try_send(()) {
            if error.is_disconnected() {
                return Ok(());
            }
        }
    }

    Ok(())
}

async fn pause_plotting_if_node_not_synced<NC>(
    node_client: &NC,
    sectors_to_plot_proxy_receiver: mpsc::Receiver<(SectorIndex, oneshot::Sender<()>)>,
    mut sectors_to_plot_sender: mpsc::Sender<(SectorIndex, oneshot::Sender<()>)>,
) -> Result<(), BackgroundTaskError>
where
    NC: NodeClient,
{
    let mut node_sync_status_change_notifications = node_client
        .subscribe_node_sync_status_change()
        .await
        .map_err(|error| PlottingError::FailedToSubscribeArchivedSegments { error })?;

    let Some(mut node_sync_status) = node_sync_status_change_notifications.next().await else {
        return Ok(());
    };

    let mut sectors_to_plot_proxy_receiver = sectors_to_plot_proxy_receiver.fuse();
    let mut node_sync_status_change_notifications = node_sync_status_change_notifications.fuse();

    'outer: loop {
        // Pause proxying of sectors to plot until we get notification that node is synced
        if !node_sync_status.is_synced() {
            info!("Node is not synced yet, pausing plotting until sync status changes");

            loop {
                if node_sync_status.is_synced() {
                    info!("Node is synced, resuming plotting");
                    continue 'outer;
                }

                match node_sync_status_change_notifications.next().await {
                    Some(new_node_sync_status) => {
                        node_sync_status = new_node_sync_status;
                    }
                    None => {
                        // Subscription ended, nothing left to do
                        return Ok(());
                    }
                }
            }
        }

        select! {
            maybe_sector_to_plot = sectors_to_plot_proxy_receiver.next() => {
                let Some(sector_to_plot) = maybe_sector_to_plot else {
                    // Subscription ended, nothing left to do
                    return Ok(());
                };

                if let Err(_error) = sectors_to_plot_sender.send(sector_to_plot).await {
                    // Receiver disconnected, nothing left to do
                    return Ok(());
                }
            },

            maybe_node_sync_status = node_sync_status_change_notifications.next() => {
                match maybe_node_sync_status {
                    Some(new_node_sync_status) => {
                        node_sync_status = new_node_sync_status;
                    }
                    None => {
                        // Subscription ended, nothing left to do
                        return Ok(());
                    }
                }
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_plotting_notifications<NC>(
    public_key_hash: Blake2b256Hash,
    sectors_indices_left_to_plot: Range<SectorIndex>,
    target_sector_count: SectorIndex,
    min_sector_lifetime: HistorySize,
    node_client: &NC,
    sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    last_archived_segment: &Atomic<SegmentHeader>,
    mut archived_segments_receiver: mpsc::Receiver<()>,
    mut sectors_to_plot_sender: mpsc::Sender<(SectorIndex, oneshot::Sender<()>)>,
) -> Result<(), BackgroundTaskError>
where
    NC: NodeClient,
{
    // Finish initial plotting if some sectors were not plotted fully yet
    for sector_index in sectors_indices_left_to_plot {
        let (acknowledgement_sender, acknowledgement_receiver) = oneshot::channel();
        if let Err(error) = sectors_to_plot_sender
            .send((sector_index, acknowledgement_sender))
            .await
        {
            warn!(%error, "Failed to send sector index for initial plotting");
            return Ok(());
        }

        // We do not care if message was sent back or sender was just dropped
        let _ = acknowledgement_receiver.await;
    }

    let mut sectors_expire_at = HashMap::with_capacity(usize::from(target_sector_count));

    let mut sector_indices_to_replot = Vec::new();
    let mut sectors_to_check = Vec::with_capacity(usize::from(target_sector_count));
    let mut archived_segment_commitments_cache = LruCache::new(ARCHIVED_SEGMENTS_CACHE_SIZE);

    while let Some(()) = archived_segments_receiver.next().await {
        let archived_segment_header = last_archived_segment.load(Ordering::SeqCst);
        trace!(
            segment_index = %archived_segment_header.segment_index(),
            "New archived segment received",
        );

        // It is fine to take a synchronous read lock here because the only time
        // write lock is taken is during plotting, which we know doesn't happen
        // right now. We copy data here because `.read()`'s guard is not `Send`.
        sectors_metadata
            .read()
            .iter()
            .map(|sector_metadata| (sector_metadata.sector_index, sector_metadata.history_size))
            .collect_into(&mut sectors_to_check);
        for (sector_index, history_size) in sectors_to_check.drain(..) {
            if let Some(sector_expire_at) = sectors_expire_at.get(&sector_index) {
                trace!(
                    %sector_index,
                    %history_size,
                    %sector_expire_at,
                    "Checking sector for expiration"
                );
                // +1 means we will start replotting a bit before it actually expires to avoid
                // storing expired sectors
                if *sector_expire_at
                    <= (archived_segment_header.segment_index() + SegmentIndex::ONE)
                {
                    debug!(
                        %sector_index,
                        %history_size,
                        %sector_expire_at,
                        "Sector expires soon #1, scheduling replotting"
                    );
                    // Time to replot
                    sector_indices_to_replot.push(sector_index);
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

                    trace!(
                        %sector_index,
                        %history_size,
                        sector_expire_at = %expiration_history_size.segment_index(),
                        "Determined sector expiration segment index"
                    );
                    // +1 means we will start replotting a bit before it actually expires to avoid
                    // storing expired sectors
                    if expiration_history_size.segment_index()
                        <= (archived_segment_header.segment_index() + SegmentIndex::ONE)
                    {
                        debug!(
                            %sector_index,
                            %history_size,
                            sector_expire_at = %expiration_history_size.segment_index(),
                            "Sector expires soon #2, scheduling replotting"
                        );
                        // Time to replot
                        sector_indices_to_replot.push(sector_index);
                    } else {
                        trace!(
                            %sector_index,
                            %history_size,
                            sector_expire_at = %expiration_history_size.segment_index(),
                            "Sector expires later, remembering sector expiration"
                        );
                        // Store expiration so we don't have to recalculate it later
                        sectors_expire_at
                            .insert(sector_index, expiration_history_size.segment_index());
                    }
                }
            }
        }

        for sector_index in sector_indices_to_replot.iter() {
            let (acknowledgement_sender, acknowledgement_receiver) = oneshot::channel();
            if let Err(error) = sectors_to_plot_sender
                .send((*sector_index, acknowledgement_sender))
                .await
            {
                warn!(%error, "Failed to send sector index for replotting");
                return Ok(());
            }

            // We do not care if message was sent back or sender was just dropped
            let _ = acknowledgement_receiver.await;

            sectors_expire_at.remove(sector_index);
        }

        sector_indices_to_replot.clear();
    }

    Ok(())
}
