use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_farm::Handlers;
use crate::utils::AsyncJoinOnDrop;
use futures::channel::mpsc;
use futures::StreamExt;
#[cfg(windows)]
use memmap2::Mmap;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use rayon::ThreadPoolBuildError;
use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::proving;
use subspace_farmer_components::proving::ProvableSolutions;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
#[cfg(not(windows))]
use subspace_farmer_components::ReadAt;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

/// Errors that happen during farming
#[derive(Debug, Error)]
pub enum FarmingError {
    /// Failed to subscribe to slot info notifications
    #[error("Failed to substribe to slot info notifications: {error}")]
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

pub(super) struct FarmingOptions<'a, NC> {
    pub(super) public_key: PublicKey,
    pub(super) reward_address: PublicKey,
    pub(super) node_client: NC,
    pub(super) sector_size: usize,
    pub(super) plot_file: &'a File,
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
pub(super) async fn farming<PosTable, NC>(
    farming_options: FarmingOptions<'_, NC>,
) -> Result<(), FarmingError>
where
    PosTable: Table,
    NC: NodeClient,
{
    let FarmingOptions {
        public_key,
        reward_address,
        node_client,
        sector_size,
        plot_file,
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

    #[cfg(windows)]
    let plot_mmap = unsafe { Mmap::map(plot_file)? };
    let table_generator = Arc::new(Mutex::new(PosTable::generator()));

    while let Some(slot_info) = slot_info_notifications.next().await {
        let start = Instant::now();
        let slot = slot_info.slot_number;
        let sectors_metadata = sectors_metadata.read();
        let sector_count = sectors_metadata.len();

        debug!(%slot, %sector_count, "Reading sectors");

        #[cfg(not(windows))]
        let sectors = (0..sector_count)
            .into_par_iter()
            .map(|sector_index| plot_file.offset(sector_index * sector_size));
        // On Windows random read is horrible in terms of performance, memory-mapped I/O helps
        // TODO: Remove this once https://internals.rust-lang.org/t/introduce-write-all-at-read-exact-at-on-windows/19649
        //  or similar exists in standard library
        #[cfg(windows)]
        let sectors = plot_mmap.par_chunks_exact(sector_size);

        let sectors_solutions = {
            let modifying_sector_guard = modifying_sector_index.read();
            let maybe_sector_being_modified = modifying_sector_guard.as_ref().copied();

            let mut sectors_solutions = sectors_metadata
                .par_iter()
                .zip(sectors)
                .enumerate()
                .filter_map(|(sector_index, (sector_metadata, sector))| {
                    let sector_index = sector_index as u16;
                    if maybe_sector_being_modified == Some(sector_index) {
                        // Skip sector that is being modified right now
                        return None;
                    }
                    trace!(%slot, %sector_index, "Auditing sector");

                    let audit_results = audit_sector(
                        &public_key,
                        sector_index,
                        &slot_info.global_challenge,
                        slot_info.voting_solution_range,
                        sector,
                        sector_metadata,
                    )?;

                    Some((sector_index, audit_results.solution_candidates))
                })
                .filter_map(|(sector_index, solution_candidates)| {
                    let sector_solutions = match solution_candidates.into_solutions(
                        &reward_address,
                        &kzg,
                        &erasure_coding,
                        |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
                    ) {
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
                .collect::<Vec<_>>();

            sectors_solutions.sort_by(|a, b| {
                let a_solution_distance =
                    a.1.best_solution_distance().unwrap_or(SolutionRange::MAX);
                let b_solution_distance =
                    b.1.best_solution_distance().unwrap_or(SolutionRange::MAX);

                a_solution_distance.cmp(&b_solution_distance)
            });

            sectors_solutions
        };

        // Holds futures such that this function doesn't exit until all solutions were sent out
        let mut sending_solutions = Vec::new();

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
                    break 'solutions_processing;
                }

                let response = SolutionResponse {
                    slot_number: slot_info.slot_number,
                    solution,
                };

                handlers.solution.call_simple(&response);

                let sending_solution = tokio::task::spawn({
                    let node_client = node_client.clone();

                    async move {
                        if let Err(error) = node_client.submit_solution_response(response).await {
                            warn!(%error, "Failed to submit solutions response");
                        }
                    }
                });

                sending_solutions.push(AsyncJoinOnDrop::new(sending_solution));
            }
        }
    }

    Ok(())
}
