//! Farming-related utilities
//!
//! These utilities do not expose the whole farming workflow, but rather small bits of it that can
//! be useful externally (for example for benchmarking purposes in CLI).

pub mod rayon_files;

use crate::farm::{
    AuditingDetails, FarmingError, FarmingNotification, ProvingDetails, ProvingResult,
};
use crate::node_client::NodeClient;
use crate::single_disk_farm::metrics::SingleDiskFarmMetrics;
use crate::single_disk_farm::Handlers;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use rayon::ThreadPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::pos::PosSeed;
use subspace_core_primitives::sectors::SectorIndex;
use subspace_core_primitives::segments::{HistorySize, SegmentIndex};
use subspace_core_primitives::solutions::{Solution, SolutionRange};
use subspace_core_primitives::PublicKey;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::{audit_plot_sync, AuditingError};
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::{SectorMetadata, SectorMetadataChecksummed};
use subspace_farmer_components::ReadAtSync;
use subspace_kzg::Kzg;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use tracing::{debug, error, info, trace, warn, Span};

/// How many non-fatal errors should happen in a row before farm is considered non-operational
const NON_FATAL_ERROR_LIMIT: usize = 10;

pub(super) async fn slot_notification_forwarder<NC>(
    node_client: &NC,
    mut slot_info_forwarder_sender: mpsc::Sender<SlotInfo>,
    metrics: Option<Arc<SingleDiskFarmMetrics>>,
) -> Result<(), FarmingError>
where
    NC: NodeClient,
{
    info!("Subscribing to slot info notifications");

    let mut slot_info_notifications = node_client
        .subscribe_slot_info()
        .await
        .map_err(|error| FarmingError::FailedToSubscribeSlotInfo { error })?;

    while let Some(slot_info) = slot_info_notifications.next().await {
        debug!(?slot_info, "New slot");

        let slot = slot_info.slot_number;

        // Error means farmer is still solving for previous slot, which is too late, and we need to
        // skip this slot
        if slot_info_forwarder_sender.try_send(slot_info).is_err() {
            if let Some(metrics) = &metrics {
                metrics.skipped_slots.inc();
            }
            debug!(%slot, "Slow farming, skipping slot");
        }
    }

    Err(FarmingError::SlotNotificationStreamEnded)
}

/// Plot audit options
#[derive(Debug)]
pub struct PlotAuditOptions<'a, 'b, PosTable>
where
    PosTable: Table,
{
    /// Public key of the farm
    pub public_key: &'a PublicKey,
    /// Reward address to use for solutions
    pub reward_address: &'a PublicKey,
    /// Slot info for the audit
    pub slot_info: SlotInfo,
    /// Metadata of all sectors plotted so far
    pub sectors_metadata: &'a [SectorMetadataChecksummed],
    /// Kzg instance
    pub kzg: &'a Kzg,
    /// Erasure coding instance
    pub erasure_coding: &'a ErasureCoding,
    /// Optional sector that is currently being modified (for example replotted) and should not be
    /// audited
    pub sectors_being_modified: &'b HashSet<SectorIndex>,
    /// Mode of reading chunks during proving
    pub read_sector_record_chunks_mode: ReadSectorRecordChunksMode,
    /// Proof of space table generator
    pub table_generator: &'a Mutex<PosTable::Generator>,
}

impl<PosTable> Clone for PlotAuditOptions<'_, '_, PosTable>
where
    PosTable: Table,
{
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<PosTable> Copy for PlotAuditOptions<'_, '_, PosTable> where PosTable: Table {}

/// Plot auditing implementation
#[derive(Debug)]
pub struct PlotAudit<Plot>(Plot)
where
    Plot: ReadAtSync;

impl<'a, Plot> PlotAudit<Plot>
where
    Plot: ReadAtSync + 'a,
{
    /// Create new instance
    pub fn new(plot: Plot) -> Self {
        Self(plot)
    }

    /// Audit this plot
    #[allow(clippy::type_complexity)]
    pub fn audit<'b, PosTable>(
        &'a self,
        options: PlotAuditOptions<'a, 'b, PosTable>,
    ) -> Result<
        Vec<(
            SectorIndex,
            impl ProvableSolutions<Item = Result<Solution<PublicKey>, ProvingError>>
            + use<'a, PosTable, Plot>,
        )>,
        AuditingError,
    >
    where
        PosTable: Table,
    {
        let PlotAuditOptions {
            public_key,
            reward_address,
            slot_info,
            sectors_metadata,
            kzg,
            erasure_coding,
            sectors_being_modified,
            read_sector_record_chunks_mode: mode,
            table_generator,
        } = options;

        let audit_results = audit_plot_sync(
            public_key,
            &slot_info.global_challenge,
            slot_info.voting_solution_range,
            &self.0,
            sectors_metadata,
            sectors_being_modified,
        )?;

        Ok(audit_results
            .into_iter()
            .filter_map(|audit_results| {
                let sector_index = audit_results.sector_index;

                let sector_solutions = audit_results.solution_candidates.into_solutions(
                    reward_address,
                    kzg,
                    erasure_coding,
                    mode,
                    |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
                );

                let sector_solutions = match sector_solutions {
                    Ok(solutions) => solutions,
                    Err(error) => {
                        warn!(
                            %error,
                            %sector_index,
                            "Failed to turn solution candidates into solutions",
                        );

                        return None;
                    }
                };

                if sector_solutions.len() == 0 {
                    return None;
                }

                Some((sector_index, sector_solutions))
            })
            .collect())
    }
}

pub(super) struct FarmingOptions<NC, PlotAudit> {
    pub(super) public_key: PublicKey,
    pub(super) reward_address: PublicKey,
    pub(super) node_client: NC,
    pub(super) plot_audit: PlotAudit,
    pub(super) sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) kzg: Kzg,
    pub(super) erasure_coding: ErasureCoding,
    pub(super) handlers: Arc<Handlers>,
    pub(super) sectors_being_modified: Arc<AsyncRwLock<HashSet<SectorIndex>>>,
    pub(super) slot_info_notifications: mpsc::Receiver<SlotInfo>,
    pub(super) thread_pool: ThreadPool,
    pub(super) read_sector_record_chunks_mode: ReadSectorRecordChunksMode,
    pub(super) global_mutex: Arc<AsyncMutex<()>>,
    pub(super) metrics: Option<Arc<SingleDiskFarmMetrics>>,
}

/// Starts farming process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn farming<'a, PosTable, NC, Plot>(
    farming_options: FarmingOptions<NC, PlotAudit<Plot>>,
) -> Result<(), FarmingError>
where
    PosTable: Table,
    NC: NodeClient,
    Plot: ReadAtSync + 'a,
{
    let FarmingOptions {
        public_key,
        reward_address,
        node_client,
        plot_audit,
        sectors_metadata,
        kzg,
        erasure_coding,
        handlers,
        sectors_being_modified,
        mut slot_info_notifications,
        thread_pool,
        read_sector_record_chunks_mode,
        global_mutex,
        metrics,
    } = farming_options;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| FarmingError::FailedToGetFarmerInfo { error })?;

    // We assume that each slot is one second
    let farming_timeout = farmer_app_info.farming_timeout;

    let table_generator = Arc::new(Mutex::new(PosTable::generator()));
    let span = Span::current();

    let mut non_fatal_errors = 0;

    while let Some(slot_info) = slot_info_notifications.next().await {
        let slot = slot_info.slot_number;

        // Take mutex briefly to make sure farming is allowed right now
        global_mutex.lock().await;

        let mut problematic_sectors = Vec::new();
        let result: Result<(), FarmingError> = try {
            let start = Instant::now();
            let sectors_metadata = sectors_metadata.read().await;

            debug!(%slot, sector_count = %sectors_metadata.len(), "Reading sectors");

            let mut sectors_solutions = {
                let sectors_being_modified = &*sectors_being_modified.read().await;

                thread_pool.install(|| {
                    let _span_guard = span.enter();

                    plot_audit.audit(PlotAuditOptions::<PosTable> {
                        public_key: &public_key,
                        reward_address: &reward_address,
                        slot_info,
                        sectors_metadata: &sectors_metadata,
                        kzg: &kzg,
                        erasure_coding: &erasure_coding,
                        sectors_being_modified,
                        read_sector_record_chunks_mode,
                        table_generator: &table_generator,
                    })
                })?
            };

            sectors_solutions.sort_by(|a, b| {
                let a_solution_distance =
                    a.1.best_solution_distance().unwrap_or(SolutionRange::MAX);
                let b_solution_distance =
                    b.1.best_solution_distance().unwrap_or(SolutionRange::MAX);

                a_solution_distance.cmp(&b_solution_distance)
            });

            {
                let time = start.elapsed();
                if let Some(metrics) = &metrics {
                    metrics.auditing_time.observe(time.as_secs_f64());
                }
                handlers
                    .farming_notification
                    .call_simple(&FarmingNotification::Auditing(AuditingDetails {
                        sectors_count: sectors_metadata.len() as SectorIndex,
                        time,
                    }));
            }

            // Take mutex and hold until proving end to make sure nothing else major happens at the
            // same time
            let _proving_guard = global_mutex.lock().await;

            'solutions_processing: for (sector_index, mut sector_solutions) in sectors_solutions {
                if sector_solutions.is_empty() {
                    continue;
                }
                let mut start = Instant::now();
                while let Some(maybe_solution) = thread_pool.install(|| {
                    let _span_guard = span.enter();

                    sector_solutions.next()
                }) {
                    let solution = match maybe_solution {
                        Ok(solution) => solution,
                        Err(error) => {
                            if let Some(metrics) = &metrics {
                                metrics
                                    .observe_proving_time(&start.elapsed(), ProvingResult::Failed);
                            }
                            error!(
                                %slot,
                                %sector_index,
                                %error,
                                "Failed to prove, scheduling sector for replotting"
                            );
                            problematic_sectors.push(sector_index);
                            // Do not error completely as disk corruption or other reasons why
                            // proving might fail
                            start = Instant::now();
                            continue;
                        }
                    };

                    debug!(%slot, %sector_index, "Solution found");
                    trace!(?solution, "Solution found");

                    {
                        let time = start.elapsed();
                        if time >= farming_timeout {
                            if let Some(metrics) = &metrics {
                                metrics.observe_proving_time(&time, ProvingResult::Timeout);
                            }
                            handlers.farming_notification.call_simple(
                                &FarmingNotification::Proving(ProvingDetails {
                                    result: ProvingResult::Timeout,
                                    time,
                                }),
                            );
                            warn!(
                                %slot,
                                %sector_index,
                                "Proving for solution skipped due to farming time limit",
                            );

                            break 'solutions_processing;
                        }
                    }

                    let response = SolutionResponse {
                        slot_number: slot,
                        solution,
                    };

                    handlers.solution.call_simple(&response);

                    if let Err(error) = node_client.submit_solution_response(response).await {
                        let time = start.elapsed();
                        if let Some(metrics) = &metrics {
                            metrics.observe_proving_time(&time, ProvingResult::Rejected);
                        }
                        handlers
                            .farming_notification
                            .call_simple(&FarmingNotification::Proving(ProvingDetails {
                                result: ProvingResult::Rejected,
                                time,
                            }));
                        warn!(
                            %slot,
                            %sector_index,
                            %error,
                            "Failed to send solution to node, skipping further proving for this slot",
                        );
                        break 'solutions_processing;
                    }

                    let time = start.elapsed();
                    if let Some(metrics) = &metrics {
                        metrics.observe_proving_time(&time, ProvingResult::Success);
                    }
                    handlers
                        .farming_notification
                        .call_simple(&FarmingNotification::Proving(ProvingDetails {
                            result: ProvingResult::Success,
                            time,
                        }));
                    start = Instant::now();
                }
            }
        };

        if let Err(error) = result {
            if error.is_fatal() {
                return Err(error);
            }

            non_fatal_errors += 1;

            if non_fatal_errors >= NON_FATAL_ERROR_LIMIT {
                return Err(error);
            }

            warn!(
                %error,
                "Non-fatal farming error"
            );

            if let Some(metrics) = &metrics {
                metrics.note_farming_error(&error);
            }
            handlers
                .farming_notification
                .call_simple(&FarmingNotification::NonFatalError(Arc::new(error)));

            for sector_index in problematic_sectors.drain(..) {
                // Inform others that this sector is being modified
                sectors_being_modified.write().await.insert(sector_index);
                // Replace metadata with a dummy one, so it will be picked up for replotting next
                if let Some(existing_sector_metadata) = sectors_metadata
                    .write()
                    .await
                    .get_mut(sector_index as usize)
                {
                    *existing_sector_metadata = SectorMetadataChecksummed::from(SectorMetadata {
                        sector_index,
                        pieces_in_sector: existing_sector_metadata.pieces_in_sector,
                        s_bucket_sizes: Box::new([0; Record::NUM_S_BUCKETS]),
                        history_size: HistorySize::from(SegmentIndex::ZERO),
                    });
                }
                // Inform others that this sector is no longer being modified
                sectors_being_modified.write().await.remove(&sector_index);
            }
        } else {
            non_fatal_errors = 0;
        }
    }

    Ok(())
}
