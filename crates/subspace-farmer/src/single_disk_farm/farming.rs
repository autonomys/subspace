use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_farm::Handlers;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuildError};
use std::fs::File;
use std::io;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::proving::ProvableSolutions;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_farmer_components::{proving, ReadAt};
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

/// Self-imposed limit for number of solutions that farmer will not go over per challenge.
///
/// Only useful for initial network bootstrapping where due to initial plot size there might be too
/// many solutions.
const SOLUTIONS_LIMIT: usize = 1;

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
    /// Failed to create memory mapping for metadata
    #[error("Failed to create memory mapping for metadata: {error}")]
    FailedToMapMetadata {
        /// Lower-level error
        error: io::Error,
    },
    /// Failed to submit solutions response
    #[error("Failed to submit solutions response: {error}")]
    FailedToSubmitSolutionsResponse {
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
    pub(super) thread_pool: Arc<ThreadPool>,
}

/// Starts farming process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
// False-positive, we do drop lock before .await
#[allow(clippy::await_holding_lock)]
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
        thread_pool,
    } = farming_options;

    let table_generator = Arc::new(Mutex::new(PosTable::generator()));

    while let Some(slot_info) = slot_info_notifications.next().await {
        let modifying_sector_index = Arc::clone(&modifying_sector_index);
        let sectors_metadata = Arc::clone(&sectors_metadata);
        let table_generator = Arc::clone(&table_generator);
        let kzg = kzg.clone();
        let erasure_coding = erasure_coding.clone();

        let response = thread_pool.install(move || {
            let slot = slot_info.slot_number;
            let sectors_metadata = sectors_metadata.read();
            let sector_count = sectors_metadata.len();

            debug!(%slot, %sector_count, "Reading sectors");

            let modifying_sector_guard = modifying_sector_index.read();
            let maybe_sector_being_modified = modifying_sector_guard.as_ref().copied();

            let sectors = (0..sector_count)
                .map(|sector_index| plot_file.offset(sector_index * sector_size))
                .collect::<Vec<_>>();

            let mut sectors_solutions = sectors_metadata
                .par_iter()
                .zip(&sectors)
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
                .collect::<Vec<_>>()
                .into_iter()
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

            let mut solutions = Vec::<Solution<PublicKey, PublicKey>>::new();

            for (sector_index, sector_solutions) in sectors_solutions {
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

                    solutions.push(solution);

                    if solutions.len() >= SOLUTIONS_LIMIT {
                        break;
                    }
                }

                if solutions.len() >= SOLUTIONS_LIMIT {
                    break;
                }
                // TODO: It is known that decoding is slow now and we'll only be
                //  able to decode a single sector within time slot reliably, in the
                //  future we may want allow more than one sector to be valid within
                //  the same disk plot.
                if !solutions.is_empty() {
                    break;
                }
            }

            SolutionResponse {
                slot_number: slot_info.slot_number,
                solutions,
            }
        });

        handlers.solution.call_simple(&response);
        node_client
            .submit_solution_response(response)
            .await
            .map_err(|error| FarmingError::FailedToSubmitSolutionsResponse { error })?;
    }

    Ok(())
}
