use crate::PosTable;
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use criterion::{black_box, BatchSize, Criterion, Throughput};
use parking_lot::Mutex;
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Blake3Hash, Record, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_farm::direct_io_file::DirectIoFile;
use subspace_farmer::single_disk_farm::farming::rayon_files::RayonFiles;
use subspace_farmer::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmInfo, SingleDiskFarmSummary,
};
use subspace_farmer::utils::{recommended_number_of_farming_threads, tokio_rayon_spawn_handler};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::sector_size;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::SlotInfo;

#[derive(Debug, Parser)]
pub(crate) struct AuditOptions {
    /// Number of samples to collect for benchmarking purposes
    #[arg(long, default_value_t = 10)]
    sample_size: usize,
    /// Also run `single` benchmark (only useful for developers, not used by default)
    #[arg(long)]
    with_single: bool,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of logical CPUs
    /// available on UMA system and number of logical CPUs in first NUMA node on NUMA system, but
    /// not more than 32 threads
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
    /// Disk farm to audit
    ///
    /// Example:
    ///   /path/to/directory
    disk_farm: PathBuf,
    /// Optional filter for benchmarks, must correspond to a part of benchmark name in order for benchmark to run
    filter: Option<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct ProveOptions {
    /// Number of samples to collect for benchmarking purposes
    #[arg(long, default_value_t = 10)]
    sample_size: usize,
    /// Also run `single` benchmark (only useful for developers, not used by default)
    #[arg(long)]
    with_single: bool,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of logical CPUs
    /// available on UMA system and number of logical CPUs in first NUMA node on NUMA system, but
    /// not more than 32 threads
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
    /// Disk farm to prove
    ///
    /// Example:
    ///   /path/to/directory
    disk_farm: PathBuf,
    /// Optional filter for benchmarks, must correspond to a part of benchmark name in order for benchmark to run
    filter: Option<String>,
    /// Limit number of sectors audited to specified number, this limits amount of memory used by benchmark (normal
    /// farming process doesn't use this much RAM)
    #[arg(long)]
    limit_sector_count: Option<usize>,
}

/// Arguments for benchmark
#[derive(Debug, Subcommand)]
pub(crate) enum BenchmarkArgs {
    /// Auditing benchmark
    Audit(AuditOptions),
    /// Proving benchmark
    Prove(ProveOptions),
}

fn create_thread_pool(
    farming_thread_pool_size: Option<NonZeroUsize>,
) -> Result<ThreadPool, ThreadPoolBuildError> {
    let farming_thread_pool_size = farming_thread_pool_size
        .map(|farming_thread_pool_size| farming_thread_pool_size.get())
        .unwrap_or_else(recommended_number_of_farming_threads);

    ThreadPoolBuilder::new()
        .thread_name(|thread_index| format!("benchmark.{thread_index}"))
        .num_threads(farming_thread_pool_size)
        .spawn_handler(tokio_rayon_spawn_handler())
        .build()
}

pub(crate) fn benchmark(benchmark_args: BenchmarkArgs) -> anyhow::Result<()> {
    match benchmark_args {
        BenchmarkArgs::Audit(audit_options) => {
            let thread_pool = create_thread_pool(audit_options.farming_thread_pool_size)?;
            thread_pool.install(|| audit(audit_options))
        }
        BenchmarkArgs::Prove(prove_options) => {
            let thread_pool = create_thread_pool(prove_options.farming_thread_pool_size)?;
            thread_pool.install(|| prove(prove_options))
        }
    }
}

fn audit(audit_options: AuditOptions) -> anyhow::Result<()> {
    let single_disk_farm_info =
        match SingleDiskFarm::collect_summary(audit_options.disk_farm.clone()) {
            SingleDiskFarmSummary::Found { info, directory: _ } => info,
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

    match single_disk_farm_info {
        SingleDiskFarmInfo::V0 { .. } => {
            audit_inner::<PosTable>(audit_options, single_disk_farm_info)
        }
    }
}

fn audit_inner<PosTable>(
    audit_options: AuditOptions,
    single_disk_farm_info: SingleDiskFarmInfo,
) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let AuditOptions {
        sample_size,
        with_single,
        farming_thread_pool_size: _,
        disk_farm,
        filter,
    } = audit_options;

    let sector_size = sector_size(single_disk_farm_info.pieces_in_sector());
    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
    let table_generator = Mutex::new(PosTable::generator());

    let sectors_metadata = SingleDiskFarm::read_all_sectors_metadata(&disk_farm)
        .map_err(|error| anyhow::anyhow!("Failed to read sectors metadata: {error}"))?;

    let mut criterion = Criterion::default().sample_size(sample_size);
    if let Some(filter) = filter {
        criterion = criterion.with_filter(filter);
    }
    {
        let mut group = criterion.benchmark_group("audit");
        group.throughput(Throughput::Bytes(
            sector_size as u64 * sectors_metadata.len() as u64,
        ));
        if with_single {
            let plot = OpenOptions::new()
                .read(true)
                .open(disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);

            group.bench_function("plot/single", |b| {
                b.iter_batched(
                    rand::random::<[u8; 32]>,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge: Blake3Hash::from(global_challenge),
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            sectors_being_modified: &HashSet::default(),
                            read_sector_record_chunks_mode:
                                ReadSectorRecordChunksMode::ConcurrentChunks,
                            table_generator: &table_generator,
                        };

                        black_box(plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        {
            let plot = RayonFiles::open_with(
                &disk_farm.join(SingleDiskFarm::PLOT_FILE),
                DirectIoFile::open,
            )
            .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);

            group.bench_function("plot/rayon/unbuffered", |b| {
                b.iter_batched(
                    rand::random::<[u8; 32]>,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge: Blake3Hash::from(global_challenge),
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            sectors_being_modified: &HashSet::default(),
                            read_sector_record_chunks_mode:
                                ReadSectorRecordChunksMode::ConcurrentChunks,
                            table_generator: &table_generator,
                        };

                        black_box(plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        {
            let plot = RayonFiles::open(&disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);

            group.bench_function("plot/rayon/regular", |b| {
                b.iter_batched(
                    rand::random::<[u8; 32]>,
                    |global_challenge| {
                        let options = PlotAuditOptions::<PosTable> {
                            public_key: single_disk_farm_info.public_key(),
                            reward_address: single_disk_farm_info.public_key(),
                            slot_info: SlotInfo {
                                slot_number: 0,
                                global_challenge: Blake3Hash::from(global_challenge),
                                // No solution will be found, pure audit
                                solution_range: SolutionRange::MIN,
                                // No solution will be found, pure audit
                                voting_solution_range: SolutionRange::MIN,
                            },
                            sectors_metadata: &sectors_metadata,
                            kzg: &kzg,
                            erasure_coding: &erasure_coding,
                            sectors_being_modified: &HashSet::default(),
                            read_sector_record_chunks_mode:
                                ReadSectorRecordChunksMode::ConcurrentChunks,
                            table_generator: &table_generator,
                        };

                        black_box(plot_audit.audit(black_box(options)))
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    criterion.final_summary();

    Ok(())
}

fn prove(prove_options: ProveOptions) -> anyhow::Result<()> {
    let single_disk_farm_info =
        match SingleDiskFarm::collect_summary(prove_options.disk_farm.clone()) {
            SingleDiskFarmSummary::Found { info, directory: _ } => info,
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

    match single_disk_farm_info {
        SingleDiskFarmInfo::V0 { .. } => {
            prove_inner::<PosTable>(prove_options, single_disk_farm_info)
        }
    }
}

fn prove_inner<PosTable>(
    prove_options: ProveOptions,
    single_disk_farm_info: SingleDiskFarmInfo,
) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let ProveOptions {
        sample_size,
        with_single,
        farming_thread_pool_size: _,
        disk_farm,
        filter,
        limit_sector_count,
    } = prove_options;

    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
    let table_generator = Mutex::new(PosTable::generator());

    let mut sectors_metadata = SingleDiskFarm::read_all_sectors_metadata(&disk_farm)
        .map_err(|error| anyhow::anyhow!("Failed to read sectors metadata: {error}"))?;
    if let Some(limit_sector_count) = limit_sector_count {
        sectors_metadata.truncate(limit_sector_count);
    };

    let mut criterion = Criterion::default().sample_size(sample_size);
    if let Some(filter) = filter {
        criterion = criterion.with_filter(filter);
    }
    {
        let mut group = criterion.benchmark_group("prove");
        if with_single {
            let plot = OpenOptions::new()
                .read(true)
                .open(disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);
            let mut options = PlotAuditOptions::<PosTable> {
                public_key: single_disk_farm_info.public_key(),
                reward_address: single_disk_farm_info.public_key(),
                slot_info: SlotInfo {
                    slot_number: 0,
                    global_challenge: Blake3Hash::from(rand::random::<[u8; 32]>()),
                    // Solution is guaranteed to be found
                    solution_range: SolutionRange::MAX,
                    // Solution is guaranteed to be found
                    voting_solution_range: SolutionRange::MAX,
                },
                sectors_metadata: &sectors_metadata,
                kzg: &kzg,
                erasure_coding: &erasure_coding,
                sectors_being_modified: &HashSet::default(),
                read_sector_record_chunks_mode: ReadSectorRecordChunksMode::ConcurrentChunks,
                table_generator: &table_generator,
            };

            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/single/concurrent-chunks", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });

            options.read_sector_record_chunks_mode = ReadSectorRecordChunksMode::WholeSector;
            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/single/whole-sector", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        {
            let plot = RayonFiles::open_with(
                &disk_farm.join(SingleDiskFarm::PLOT_FILE),
                DirectIoFile::open,
            )
            .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);
            let mut options = PlotAuditOptions::<PosTable> {
                public_key: single_disk_farm_info.public_key(),
                reward_address: single_disk_farm_info.public_key(),
                slot_info: SlotInfo {
                    slot_number: 0,
                    global_challenge: Blake3Hash::from(rand::random::<[u8; 32]>()),
                    // Solution is guaranteed to be found
                    solution_range: SolutionRange::MAX,
                    // Solution is guaranteed to be found
                    voting_solution_range: SolutionRange::MAX,
                },
                sectors_metadata: &sectors_metadata,
                kzg: &kzg,
                erasure_coding: &erasure_coding,
                sectors_being_modified: &HashSet::default(),
                read_sector_record_chunks_mode: ReadSectorRecordChunksMode::ConcurrentChunks,
                table_generator: &table_generator,
            };

            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/rayon/unbuffered/concurrent-chunks", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });

            options.read_sector_record_chunks_mode = ReadSectorRecordChunksMode::WholeSector;
            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/rayon/unbuffered/whole-sector", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        {
            let plot = RayonFiles::open(&disk_farm.join(SingleDiskFarm::PLOT_FILE))
                .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);
            let mut options = PlotAuditOptions::<PosTable> {
                public_key: single_disk_farm_info.public_key(),
                reward_address: single_disk_farm_info.public_key(),
                slot_info: SlotInfo {
                    slot_number: 0,
                    global_challenge: Blake3Hash::from(rand::random::<[u8; 32]>()),
                    // Solution is guaranteed to be found
                    solution_range: SolutionRange::MAX,
                    // Solution is guaranteed to be found
                    voting_solution_range: SolutionRange::MAX,
                },
                sectors_metadata: &sectors_metadata,
                kzg: &kzg,
                erasure_coding: &erasure_coding,
                sectors_being_modified: &HashSet::default(),
                read_sector_record_chunks_mode: ReadSectorRecordChunksMode::ConcurrentChunks,
                table_generator: &table_generator,
            };

            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/rayon/regular/concurrent-chunks", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });

            options.read_sector_record_chunks_mode = ReadSectorRecordChunksMode::WholeSector;
            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/rayon/regular/whole-sector", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge =
                            Blake3Hash::from(rand::random::<[u8; 32]>());
                        audit_results = plot_audit.audit(options).unwrap();

                        audit_results.pop().unwrap()
                    },
                    |(_sector_index, mut provable_solutions)| {
                        while black_box(provable_solutions.next()).is_none() {
                            // Try to create one solution and exit
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    criterion.final_summary();

    Ok(())
}
