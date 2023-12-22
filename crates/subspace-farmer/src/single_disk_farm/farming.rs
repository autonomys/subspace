pub mod rayon_files;

use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_farm::{Handlers, SingleDiskFarmId};
use async_lock::RwLock;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use rayon::ThreadPoolBuildError;
use std::io;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_plot_sync;
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_farmer_components::{proving, ReadAtSync};
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Defines how much time took the audit in secs
    pub duration: f64,
    /// ID of the farm
    pub farm_id: SingleDiskFarmId,
    /// Number of sectors for this audit
    pub sectors_number: usize,
}

/// Errors that happen during farming
#[derive(Debug, Error)]
pub enum FarmingError {
    /// Failed to subscribe to slot info notifications
    #[error("Failed to subscribe to slot info notifications: {error}")]
    FailedToSubscribeSlotInfo {
        /// Lower-level error
        error: node_client::Error,
    },
    /// Failed to retrieve farmer info
    #[error("Failed to retrieve farmer info: {error}")]
    FailedToGetFarmerInfo {
        /// Lower-level error
        error: node_client::Error,
    },
    /// Low-level proving error
    #[error("Low-level proving error: {0}")]
    LowLevelProving(#[from] proving::ProvingError),
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Failed to create thread pool
    #[error("Failed to create thread pool: {0}")]
    FailedToCreateThreadPool(#[from] ThreadPoolBuildError),
}

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

    Ok(())
}

/// Plot audit options
#[derive(Debug)]
pub struct PlotAuditOptions<'a, PosTable>
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
    pub maybe_sector_being_modified: Option<SectorIndex>,
    /// Proof of space table generator
    pub table_generator: &'a Mutex<PosTable::Generator>,
}

impl<'a, PosTable> Clone for PlotAuditOptions<'a, PosTable>
where
    PosTable: Table,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, PosTable> Copy for PlotAuditOptions<'a, PosTable> where PosTable: Table {}

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

    pub fn audit<PosTable>(
        &'a self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> Vec<(
        SectorIndex,
        impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + 'a,
    )>
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
            maybe_sector_being_modified,
            table_generator,
        } = options;

        let audit_results = audit_plot_sync(
            public_key,
            &slot_info.global_challenge,
            slot_info.voting_solution_range,
            &self.0,
            sectors_metadata,
            maybe_sector_being_modified,
        );

        audit_results
            .into_iter()
            .filter_map(|audit_results| {
                let sector_index = audit_results.sector_index;

                let sector_solutions = audit_results.solution_candidates.into_solutions(
                    reward_address,
                    kzg,
                    erasure_coding,
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
            .collect()
    }
}

pub(super) struct FarmingOptions<NC, PlotAudit> {
    pub(super) public_key: PublicKey,
    pub(super) reward_address: PublicKey,
    pub(super) node_client: NC,
    pub(super) plot_audit: PlotAudit,
    pub(super) sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) kzg: Kzg,
    pub(super) erasure_coding: ErasureCoding,
    pub(super) handlers: Arc<Handlers>,
    pub(super) modifying_sector_index: Arc<RwLock<Option<SectorIndex>>>,
    pub(super) slot_info_notifications: mpsc::Receiver<SlotInfo>,
    pub(super) farm_id: SingleDiskFarmId,
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
        modifying_sector_index,
        mut slot_info_notifications,
        farm_id,
    } = farming_options;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| FarmingError::FailedToGetFarmerInfo { error })?;

    // We assume that each slot is one second
    let farming_timeout = farmer_app_info.farming_timeout;

    let table_generator = Arc::new(Mutex::new(PosTable::generator()));

    while let Some(slot_info) = slot_info_notifications.next().await {
        let start = Instant::now();
        let slot = slot_info.slot_number;
        let sectors_metadata = sectors_metadata.read().await;

        debug!(%slot, sector_count = %sectors_metadata.len(), "Reading sectors");

        let mut sectors_solutions = {
            let modifying_sector_guard = modifying_sector_index.read().await;
            let maybe_sector_being_modified = modifying_sector_guard.as_ref().copied();

            let start = Instant::now();

            let sectors_solutions = plot_audit.audit(PlotAuditOptions::<PosTable> {
                public_key: &public_key,
                reward_address: &reward_address,
                slot_info,
                sectors_metadata: &sectors_metadata,
                kzg: &kzg,
                erasure_coding: &erasure_coding,
                maybe_sector_being_modified,
                table_generator: &table_generator,
            });

            handlers.plot_audited.call_simple(&AuditEvent {
                duration: start.elapsed().as_secs_f64(),
                farm_id,
                sectors_number: sectors_metadata.len(),
            });

            sectors_solutions
        };

        sectors_solutions.sort_by(|a, b| {
            let a_solution_distance = a.1.best_solution_distance().unwrap_or(SolutionRange::MAX);
            let b_solution_distance = b.1.best_solution_distance().unwrap_or(SolutionRange::MAX);

            a_solution_distance.cmp(&b_solution_distance)
        });

        'solutions_processing: for (sector_index, sector_solutions) in sectors_solutions {
            for maybe_solution in sector_solutions {
                let solution = match maybe_solution {
                    Ok(solution) => solution,
                    Err(error) => {
                        error!(%slot, %sector_index, %error, "Failed to prove");
                        // Do not error completely as disk corruption or other reasons why
                        // proving might fail
                        continue;
                    }
                };

                debug!(%slot, %sector_index, "Solution found");
                trace!(?solution, "Solution found");

                if start.elapsed() >= farming_timeout {
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
                    warn!(
                        %slot,
                        %sector_index,
                        %error,
                        "Failed to send solution to node, skipping further proving for this slot",
                    );
                    break 'solutions_processing;
                }
            }
        }
    }

    Ok(())
}
