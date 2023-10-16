use crate::PosTable;
use anyhow::anyhow;
use clap::Subcommand;
use criterion::async_executor::AsyncExecutor;
use criterion::{black_box, BatchSize, Criterion, Throughput};
#[cfg(windows)]
use memmap2::Mmap;
use parking_lot::Mutex;
use std::fs::OpenOptions;
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Record, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_farm::farming::{plot_audit, PlotAuditOptions};
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_farmer_components::sector::sector_size;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::SlotInfo;
use tokio::runtime::Handle;

struct TokioAsyncExecutor(Handle);

impl AsyncExecutor for TokioAsyncExecutor {
    fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        tokio::task::block_in_place(|| self.0.block_on(future))
    }
}

impl TokioAsyncExecutor {
    fn new() -> Self {
        Self(Handle::current())
    }
}

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

pub(crate) async fn benchmark(benchmark_args: BenchmarkArgs) -> anyhow::Result<()> {
    match benchmark_args {
        BenchmarkArgs::Audit {
            disk_farm,
            sample_size,
        } => audit(disk_farm, sample_size).await,
    }
}

async fn audit(disk_farm: PathBuf, sample_size: usize) -> anyhow::Result<()> {
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

    let plot_file = OpenOptions::new()
        .read(true)
        .open(disk_farm.join(SingleDiskFarm::PLOT_FILE))
        .map_err(|error| anyhow::anyhow!("Failed to open single disk farm: {error}"))?;
    #[cfg(windows)]
    let plot_mmap = unsafe { Mmap::map(&plot_file)? };

    let mut criterion = Criterion::default().sample_size(sample_size);
    criterion
        .benchmark_group("audit")
        .throughput(Throughput::Bytes(
            sector_size as u64 * sectors_metadata.len() as u64,
        ))
        .bench_function("plot", |b| {
            b.to_async(TokioAsyncExecutor::new()).iter_batched(
                rand::random,
                |global_challenge| {
                    let options = PlotAuditOptions::<PosTable> {
                        public_key: single_disk_farm_info.public_key(),
                        reward_address: single_disk_farm_info.public_key(),
                        sector_size,
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
                        #[cfg(not(windows))]
                        plot_file: &plot_file,
                        #[cfg(windows)]
                        plot_mmap: &plot_mmap,
                        maybe_sector_being_modified: None,
                        table_generator: &table_generator,
                    };

                    black_box(plot_audit(black_box(options)))
                },
                BatchSize::SmallInput,
            )
        });

    criterion.final_summary();

    Ok(())
}
