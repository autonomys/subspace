use crate::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use async_lock::Semaphore;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use monoio::blocking::{BlockingTask, ThreadPool};
use monoio::buf::IoBufMut;
use monoio::fs::File;
use monoio::{LegacyDriver, RuntimeBuilder};
use std::io;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution};
use subspace_farmer_components::auditing::audit_plot_async;
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::{AsyncReadBytes, ReadAtAsync};
use subspace_proof_of_space::{Table, TableGenerator};
use tracing::warn;

/// Re-export of platform-specific [`monoio`] runtime
#[cfg(target_os = "linux")]
pub type MonoioRuntime = monoio::FusionRuntime<monoio::IoUringDriver, LegacyDriver>;

/// Build platform-specific [`monoio`] runtime
#[cfg(target_os = "linux")]
pub fn build_monoio_runtime() -> io::Result<MonoioRuntime> {
    RuntimeBuilder::<monoio::FusionDriver>::new()
        .attach_thread_pool(Box::new(RayonThreadPool))
        .build()
}

/// Re-export of platform-specific [`monoio`] runtime
#[cfg(target_os = "macos")]
pub type MonoioRuntime = monoio::Runtime<LegacyDriver>;

/// Build platform-specific [`monoio`] runtime
#[cfg(target_os = "macos")]
pub fn build_monoio_runtime() -> io::Result<MonoioRuntime> {
    RuntimeBuilder::<LegacyDriver>::new()
        .attach_thread_pool(Box::new(RayonThreadPool))
        .build()
}

/// Wrapper to use rayon's thread pool with [`monoio`]
struct RayonThreadPool;

impl ThreadPool for RayonThreadPool {
    fn schedule_task(&self, task: BlockingTask) {
        rayon::spawn(move || {
            task.run();
        });
    }
}

struct AsyncReadBytesWrapper<B>(B)
where
    B: AsMut<[u8]> + Unpin + 'static;

unsafe impl<B> IoBufMut for AsyncReadBytesWrapper<B>
where
    B: AsMut<[u8]> + Unpin + 'static,
{
    #[inline]
    fn write_ptr(&mut self) -> *mut u8 {
        self.0.as_mut().as_mut_ptr()
    }

    #[inline]
    fn bytes_total(&mut self) -> usize {
        self.0.as_mut().len()
    }

    #[inline]
    unsafe fn set_init(&mut self, _: usize) {}
}

/// Wrapper data structure for readable file used with [`monoio`]-based auditing implementation
pub struct MonoioFile<'a> {
    file: &'a File,
    semaphore: Semaphore,
}

impl ReadAtAsync for MonoioFile<'_> {
    async fn read_at<B>(&self, buf: B, offset: usize) -> io::Result<B>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static,
    {
        let _permit = self.semaphore.acquire().await;
        let (read_result, AsyncReadBytesWrapper(buf)) = self
            .file
            .read_exact_at(AsyncReadBytesWrapper(buf), offset as u64)
            .await;

        read_result.map(|()| buf)
    }
}

impl<'a> MonoioFile<'a> {
    pub fn new(file: &'a File, io_concurrency: usize) -> Self {
        Self {
            file,
            semaphore: Semaphore::new(io_concurrency),
        }
    }
}

/// Plot auditing asynchronously using [`monoio`] runtime
pub struct MonoioPlotAudit<'f>(MonoioFile<'f>);

impl<'f> PlotAudit<'f> for MonoioPlotAudit<'f> {
    async fn audit<'a, PosTable>(
        &'f self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> Vec<(
        SectorIndex,
        impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + Unpin + 'a,
    )>
    where
        'f: 'a,
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

        let audit_results_fut = audit_plot_async(
            public_key,
            &slot_info.global_challenge,
            slot_info.voting_solution_range,
            &self.0,
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
}

impl<'f> MonoioPlotAudit<'f> {
    /// Create new instance
    pub fn new(file: MonoioFile<'f>) -> Self {
        Self(file)
    }
}
