#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod monoio;
pub mod sync_fallback;

use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_farm::Handlers;
use async_lock::RwLock;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use rayon::ThreadPoolBuildError;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PublicKey, SectorIndex, Solution, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::proving;
use subspace_farmer_components::proving::ProvableSolutions;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

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

/// Auditing implementation used by farming
pub trait PlotAudit<'p> {
    fn audit<'a, PosTable>(
        &'p self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> impl Future<
        Output = Vec<(
            SectorIndex,
            impl ProvableSolutions<
                    Item = Result<Solution<PublicKey, PublicKey>, proving::ProvingError>,
                > + Unpin
                + 'a,
        )>,
    >
    where
        'p: 'a,
        PosTable: Table;
}

pub(super) struct FarmingOptions<'a, NC, PA> {
    pub(super) public_key: PublicKey,
    pub(super) reward_address: PublicKey,
    pub(super) node_client: NC,
    pub(super) plot_audit: &'a PA,
    pub(super) sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) kzg: Kzg,
    pub(super) erasure_coding: ErasureCoding,
    pub(super) handlers: Arc<Handlers>,
    pub(super) modifying_sector_index: Arc<RwLock<Option<SectorIndex>>>,
    pub(super) slot_info_notifications: mpsc::Receiver<SlotInfo>,
}

/// Starts farming process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn farming<'a, PosTable, NC, PA>(
    farming_options: FarmingOptions<'a, NC, PA>,
) -> Result<(), FarmingError>
where
    PosTable: Table,
    NC: NodeClient,
    PA: PlotAudit<'a>,
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

            plot_audit
                .audit(PlotAuditOptions::<PosTable> {
                    public_key: &public_key,
                    reward_address: &reward_address,
                    slot_info,
                    sectors_metadata: &sectors_metadata,
                    kzg: &kzg,
                    erasure_coding: &erasure_coding,
                    maybe_sector_being_modified,
                    table_generator: &table_generator,
                })
                .await
        };

        sectors_solutions.sort_by(|a, b| {
            let a_solution_distance = a.1.best_solution_distance().unwrap_or(SolutionRange::MAX);
            let b_solution_distance = b.1.best_solution_distance().unwrap_or(SolutionRange::MAX);

            a_solution_distance.cmp(&b_solution_distance)
        });

        'solutions_processing: for (sector_index, mut sector_solutions) in sectors_solutions {
            while let Some(maybe_solution) = sector_solutions.next().await {
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
