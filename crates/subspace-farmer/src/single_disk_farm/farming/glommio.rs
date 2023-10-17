use crate::single_disk_farm::farming::PlotAuditOptions;
use async_lock::Semaphore;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use glommio::io::DmaFile;
use std::io;
use std::rc::Rc;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution};
use subspace_farmer_components::auditing::audit_plot_async;
use subspace_farmer_components::proving::ProvableSolutions;
use subspace_farmer_components::{proving, AsyncReadBytes, ReadAtAsync};
use subspace_proof_of_space::{Table, TableGenerator};
use tracing::warn;

pub struct GlommioFile<'a> {
    file: &'a Rc<DmaFile>,
    semaphore: Semaphore,
}

impl ReadAtAsync for GlommioFile<'_> {
    async fn read_at<B>(&self, mut buf: B, offset: usize) -> io::Result<B>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static,
    {
        let _permit = self.semaphore.acquire().await;
        let read_result = self
            .file
            .read_at(offset as u64, buf.as_mut().len())
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to read with glommio: {error}"),
                )
            })?;
        buf.as_mut().copy_from_slice(&read_result);
        Ok(buf)
    }
}

impl<'a> GlommioFile<'a> {
    pub fn new(file: &'a Rc<DmaFile>, io_concurrency: usize) -> Self {
        Self {
            file,
            semaphore: Semaphore::new(io_concurrency),
        }
    }
}

/// Plot auditing completely asynchronously user [`glommio`] runtime leveraging Linux's `io_uring`
/// API.
///
/// `io_concurrency` should be set to `ring_depth` of glommio's `LocalExecutor` if this is the only
/// function using it, otherwise code may panic with too many request.
pub async fn audit_plot_glommio<'a, PosTable>(
    options: PlotAuditOptions<'a, PosTable, GlommioFile<'a>>,
) -> Vec<(
    SectorIndex,
    impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, proving::ProvingError>> + 'a,
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
        plot,
        maybe_sector_being_modified,
        table_generator,
    } = options;

    let audit_results_fut = audit_plot_async(
        public_key,
        &slot_info.global_challenge,
        slot_info.voting_solution_range,
        plot,
        sectors_metadata,
        maybe_sector_being_modified,
    );

    audit_results_fut
        .await
        .into_iter()
        .map(|audit_results| async move {
            let sector_index = audit_results.sector_index;

            let sector_solutions_fut = audit_results.solution_candidates.into_solutions(
                reward_address,
                kzg,
                erasure_coding,
                |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
            );

            let sector_solutions = match sector_solutions_fut.await {
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
        .collect::<FuturesUnordered<_>>()
        .filter_map(|value| async move { value })
        .collect()
        .await
}
