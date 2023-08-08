use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_plot::Handlers;
use futures::channel::mpsc;
use futures::StreamExt;
use memmap2::Mmap;
use parking_lot::RwLock;
use std::io;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PublicKey, SectorIndex, Solution};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::proving;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, trace};

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
}

/// Starts farming process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
// False-positive, we do drop lock before .await
#[allow(clippy::await_holding_lock)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn farming<NC, PosTable>(
    public_key: PublicKey,
    reward_address: PublicKey,
    node_client: NC,
    sector_size: usize,
    plot_mmap: Mmap,
    sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    handlers: Arc<Handlers>,
    modifying_sector_index: Arc<RwLock<Option<SectorIndex>>>,
    mut slot_info_notifications: mpsc::Receiver<SlotInfo>,
) -> Result<(), FarmingError>
where
    NC: NodeClient,
    PosTable: Table,
{
    let mut table_generator = PosTable::generator();

    while let Some(slot_info) = slot_info_notifications.next().await {
        let slot = slot_info.slot_number;
        let sectors_metadata = sectors_metadata.read();
        let sector_count = sectors_metadata.len();

        debug!(%slot, %sector_count, "Reading sectors");

        let modifying_sector_guard = modifying_sector_index.read();
        let maybe_sector_being_modified = modifying_sector_guard.as_ref().copied();
        let mut solutions = Vec::<Solution<PublicKey, PublicKey>>::new();

        for ((sector_index, sector_metadata), sector) in (0..)
            .zip(&*sectors_metadata)
            .zip(plot_mmap.chunks_exact(sector_size))
        {
            if maybe_sector_being_modified == Some(sector_index) {
                // Skip sector that is being modified right now
                continue;
            }
            trace!(%slot, %sector_index, "Auditing sector");

            let maybe_solution_candidates = audit_sector(
                &public_key,
                sector_index,
                &slot_info.global_challenge,
                slot_info.voting_solution_range,
                sector,
                sector_metadata,
            );
            let Some(solution_candidates) = maybe_solution_candidates else {
                continue;
            };

            for maybe_solution in solution_candidates.into_iter::<_, PosTable>(
                &reward_address,
                &kzg,
                &erasure_coding,
                &mut table_generator,
            )? {
                let solution = match maybe_solution {
                    Ok(solution) => solution,
                    Err(error) => {
                        error!(%slot, %sector_index, %error, "Failed to prove");
                        // Do not error completely on disk corruption or other
                        // reasons why proving might fail
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

        drop(sectors_metadata);
        drop(modifying_sector_guard);

        let response = SolutionResponse {
            slot_number: slot_info.slot_number,
            solutions,
        };
        handlers.solution.call_simple(&response);
        node_client
            .submit_solution_response(response)
            .await
            .map_err(|error| FarmingError::FailedToSubmitSolutionsResponse { error })?;
    }

    Ok(())
}
