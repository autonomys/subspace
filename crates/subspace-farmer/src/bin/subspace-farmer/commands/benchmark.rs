use crate::PosTable;
use anyhow::anyhow;
use clap::Subcommand;
use criterion::{black_box, BatchSize, Criterion, Throughput};
use futures::FutureExt;
#[cfg(windows)]
use memmap2::Mmap;
use parking_lot::Mutex;
use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Record, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_farm::farming::sync_fallback::SyncPlotAudit;
use subspace_farmer::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_farmer_components::sector::sector_size;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::SlotInfo;

/// Arguments for benchmark
#[derive(Debug, Subcommand)]
pub(crate) enum BenchmarkArgs {
    /// Audit benchmark
    Audit {
        /// Disk farm to audit
        ///
        /// Example:
        ///   /path/to/directory
        disk_farm: PathBuf,
        #[arg(long, default_value_t = 10)]
        sample_size: usize,
    },
}

pub(crate) fn benchmark(benchmark_args: BenchmarkArgs) -> anyhow::Result<()> {
    match benchmark_args {
        BenchmarkArgs::Audit {
            disk_farm,
            sample_size,
        } => audit(disk_farm, sample_size),
    }
}

fn audit(disk_farm: PathBuf, sample_size: usize) -> anyhow::Result<()> {
    let (single_disk_farm_info, disk_farm) = match SingleDiskFarm::collect_summary(disk_farm) {
        SingleDiskFarmSummary::Found { info, directory } => (info, directory),
        SingleDiskFarmSummary::NotFound { directory } => {
            return Err(anyhow!(
                "No single disk farm info found, make sure {} is a valid path to the farm and \
                process have permissions to access it",
                directory.display()
            ));
        }
        SingleDiskFarmSummary::Error { directory, error } => {
            return Err(anyhow!(
                "Failed to open single disk farm info, make sure {} is a valid path to the farm \
                and process have permissions to access it: {error}",
                directory.display()
            ));
        }
    };

    let sector_size = sector_size(single_disk_farm_info.pieces_in_sector());
    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let table_generator = Mutex::new(PosTable::generator());

    let sectors_metadata = SingleDiskFarm::read_all_sectors_metadata(&disk_farm)
        .map_err(|error| anyhow::anyhow!("Failed to read sectors metadata: {error}"))?;

    let mut criterion = Criterion::default().sample_size(sample_size);
    {
        let mut group = criterion.benchmark_group("audit");
        group.throughput(Throughput::Bytes(
            sector_size as u64 * sectors_metadata.len() as u64,
        ));
        {
            let plot_file = OpenOptions::new()
                .read(true)
                .open(disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            #[cfg(windows)]
            let plot_mmap = unsafe { Mmap::map(&plot_file)? };

            group.bench_function("plot/sync", |b| {
                #[cfg(not(windows))]
                let plot = &plot_file;
                #[cfg(windows)]
                let plot = &*plot_mmap;

                let sync_plot_audit = SyncPlotAudit::new(plot);

                b.iter_batched(
                    rand::random,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge,
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            maybe_sector_being_modified: None,
                            table_generator: &table_generator,
                        };

                        black_box(
                            sync_plot_audit
                                .audit(black_box(options))
                                .now_or_never()
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use criterion::async_executor::AsyncExecutor;
            use monoio::fs::File;
            use std::cell::RefCell;
            use std::future::Future;
            use subspace_farmer::single_disk_farm::farming::monoio::{
                build_monoio_runtime, MonoioFile, MonoioPlotAudit, MonoioRuntime,
            };

            struct MonoioAsyncExecutor<'a>(&'a RefCell<MonoioRuntime>);

            impl AsyncExecutor for MonoioAsyncExecutor<'_> {
                fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
                    self.0.borrow_mut().block_on(future)
                }
            }

            impl<'a> MonoioAsyncExecutor<'a> {
                fn new(runtime: &'a RefCell<MonoioRuntime>) -> Self {
                    Self(runtime)
                }
            }

            /// SATA devices only support 32, for NVMe it is also sufficient at capacities we're
            /// working with
            const IO_CONCURRENCY: usize = 32;

            let runtime =
                RefCell::new(build_monoio_runtime().map_err(|error| {
                    anyhow::anyhow!("Failed to create monoio runtime: {error}")
                })?);
            let file = runtime
                .borrow_mut()
                .block_on(File::open(disk_farm.join(SingleDiskFarm::PLOT_FILE)))
                .map_err(|error| anyhow::anyhow!("Failed to open plot with monoio: {error}"))?;

            group.bench_function("plot/monoio", |b| {
                let file = MonoioFile::new(&file, IO_CONCURRENCY);

                let monoio_plot_audit = MonoioPlotAudit::new(file);

                b.to_async(MonoioAsyncExecutor::new(&runtime)).iter_batched(
                    rand::random,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge,
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            maybe_sector_being_modified: None,
                            table_generator: &table_generator,
                        };

                        black_box(monoio_plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });

            runtime.borrow_mut().block_on(file.close()).unwrap();
        }
    }

    criterion.final_summary();

    Ok(())
}
