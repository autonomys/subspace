use crate::single_disk_farm::farming::PlotAuditOptions;
use futures::FutureExt;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution};
use subspace_farmer_components::auditing::audit_plot_sync;
use subspace_farmer_components::proving::ProvableSolutions;
use subspace_farmer_components::{proving, ReadAtSync};
use subspace_proof_of_space::{Table, TableGenerator};
use tracing::warn;

/// Plot auditing, default synchronous implementation
pub fn audit_plot<'a, PosTable, S>(
    options: PlotAuditOptions<'a, PosTable, S>,
) -> Vec<(
    SectorIndex,
    impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, proving::ProvingError>> + 'a,
)>
where
    PosTable: Table,
    S: ReadAtSync + 'a,
{
    let PlotAuditOptions {
        public_key,
        reward_address,
        slot_info,
        sectors_metadata,
        kzg,
        erasure_coding,
        plot,
        maybe_sector_being_modified,
        table_generator,
    } = options;

    let audit_results = audit_plot_sync(
        public_key,
        &slot_info.global_challenge,
        slot_info.voting_solution_range,
        plot,
        sectors_metadata,
        maybe_sector_being_modified,
    );

    audit_results
        .into_iter()
        .filter_map(|audit_results| {
            let sector_index = audit_results.sector_index;

            let sector_solutions_fut = audit_results.solution_candidates.into_solutions(
                reward_address,
                kzg,
                erasure_coding,
                |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
            );

            let sector_solutions = match sector_solutions_fut
                .now_or_never()
                .expect("Implementation of the sector is synchronous here; qed")
            {
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
