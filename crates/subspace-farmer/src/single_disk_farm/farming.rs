pub mod rayon_files;

use crate::farm::{
    AuditingDetails, FarmingError, FarmingNotification, ProvingDetails, ProvingResult,
};
use crate::node_client::NodeClient;
use crate::single_disk_farm::Handlers;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use rayon::ThreadPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::{audit_plot_sync, AuditingError};
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_farmer_components::ReadAtSync;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use tracing::{debug, error, info, trace, warn, Span};

/// How many non-fatal errors should happen in a row before farm is considered non-operational
const NON_FATAL_ERROR_LIMIT: usize = 10;

pub(super) async fn slot_notification_forwarder<NC>(
    node_client: &NC,
    mut slot_info_forwarder_sender: mpsc::Sender<SlotInfo>,
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

        // Error means farmer is still solving for previous slot, which is too late and
        // we need to skip this slot
        if slot_info_forwarder_sender.try_send(slot_info).is_err() {
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

impl<'a, 'b, PosTable> Clone for PlotAuditOptions<'a, 'b, PosTable>
where
    PosTable: Table,
{
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, 'b, PosTable> Copy for PlotAuditOptions<'a, 'b, PosTable> where PosTable: Table {}

/// Plot auditing implementation
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

    pub fn audit<'b, PosTable>(
        &'a self,
        options: PlotAuditOptions<'a, 'b, PosTable>,
    ) -> Result<
        Vec<(
            SectorIndex,
            impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + 'a,
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

            handlers
                .farming_notification
                .call_simple(&FarmingNotification::Auditing(AuditingDetails {
                    sectors_count: sectors_metadata.len() as SectorIndex,
                    time: start.elapsed(),
                }));

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
                            error!(%slot, %sector_index, %error, "Failed to prove");
                            // Do not error completely as disk corruption or other reasons why
                            // proving might fail
                            start = Instant::now();
                            continue;
                        }
                    };

                    debug!(%slot, %sector_index, "Solution found");
                    trace!(?solution, "Solution found");

                    if start.elapsed() >= farming_timeout {
                        handlers
                            .farming_notification
                            .call_simple(&FarmingNotification::Proving(ProvingDetails {
                                result: ProvingResult::Timeout,
                                time: start.elapsed(),
                            }));
                        warn!(
                            %slot,
                            %sector_index,
                            "Proving for solution skipped due to farming time limit",
                        );

                        break 'solutions_processing;
                    }

                    let response = SolutionResponse {
                        slot_number: slot,
                        solution,
                    };

                    handlers.solution.call_simple(&response);

                    if let Err(error) = node_client.submit_solution_response(response).await {
                        handlers
                            .farming_notification
                            .call_simple(&FarmingNotification::Proving(ProvingDetails {
                                result: ProvingResult::Rejected,
                                time: start.elapsed(),
                            }));
                        warn!(
                            %slot,
                            %sector_index,
                            %error,
                            "Failed to send solution to node, skipping further proving for this slot",
                        );
                        break 'solutions_processing;
                    }

                    handlers
                        .farming_notification
                        .call_simple(&FarmingNotification::Proving(ProvingDetails {
                            result: ProvingResult::Success,
                            time: start.elapsed(),
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

            handlers
                .farming_notification
                .call_simple(&FarmingNotification::NonFatalError(Arc::new(error)));
        } else {
            non_fatal_errors = 0;
        }
    }

    Ok(())
}
