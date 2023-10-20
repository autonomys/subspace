use crate::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use futures::FutureExt;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution};
use subspace_farmer_components::auditing::audit_plot_sync;
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::ReadAtSync;
use subspace_proof_of_space::{Table, TableGenerator};
use tracing::warn;

/// Plot auditing, default synchronous implementation
pub struct SyncPlotAudit<Plot>(Plot)
where
    Plot: ReadAtSync;

impl<'p, Plot> PlotAudit<'p> for SyncPlotAudit<Plot>
where
    Plot: ReadAtSync + 'p,
{
    async fn audit<'a, PosTable>(
        &'p self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> Vec<(
        SectorIndex,
        impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + Unpin + 'a,
    )>
    where
        'p: 'a,
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
}

impl<Plot> SyncPlotAudit<Plot>
where
    Plot: ReadAtSync,
{
    /// Create new instance
    pub fn new(plot: Plot) -> Self {
        Self(plot)
    }
}
