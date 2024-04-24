use crate::PosTable;
use anyhow::anyhow;
use clap::Subcommand;
use criterion::{black_box, BatchSize, Criterion, Throughput};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Record, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_farm::farming::rayon_files::RayonFiles;
use subspace_farmer::single_disk_farm::farming::{PlotAudit, PlotAuditOptions};
use subspace_farmer::single_disk_farm::unbuffered_io_file_windows::UnbufferedIoFileWindows;
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::sector_size;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::SlotInfo;

/// Arguments for benchmark
#[derive(Debug, Subcommand)]
pub(crate) enum BenchmarkArgs {
    /// Auditing benchmark
    Audit {
        /// Number of samples to collect for benchmarking purposes
        #[arg(long, default_value_t = 10)]
        sample_size: usize,
        /// Also run `single` benchmark (only useful for developers, not used by default)
        #[arg(long)]
        with_single: bool,
        /// Disk farm to audit
        ///
        /// Example:
        ///   /path/to/directory
        disk_farm: PathBuf,
        /// Optional filter for benchmarks, must correspond to a part of benchmark name in order for benchmark to run
        filter: Option<String>,
    },
    /// Proving benchmark
    Prove {
        /// Number of samples to collect for benchmarking purposes
        #[arg(long, default_value_t = 10)]
        sample_size: usize,
        /// Also run `single` benchmark (only useful for developers, not used by default)
        #[arg(long)]
        with_single: bool,
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
    },
}

pub(crate) fn benchmark(benchmark_args: BenchmarkArgs) -> anyhow::Result<()> {
    match benchmark_args {
        BenchmarkArgs::Audit {
            sample_size,
            with_single,
            disk_farm,
            filter,
        } => audit(sample_size, with_single, disk_farm, filter),
        BenchmarkArgs::Prove {
            sample_size,
            with_single,
            disk_farm,
            filter,
            limit_sector_count,
        } => prove(
            sample_size,
            with_single,
            disk_farm,
            filter,
            limit_sector_count,
        ),
    }
}

fn audit(
    sample_size: usize,
    with_single: bool,
    disk_farm: PathBuf,
    filter: Option<String>,
) -> anyhow::Result<()> {
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
        if cfg!(windows) {
            let plot = RayonFiles::open_with(
                &disk_farm.join(SingleDiskFarm::PLOT_FILE),
                UnbufferedIoFileWindows::open,
            )
            .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);

            group.bench_function("plot/rayon/unbuffered", |b| {
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

fn prove(
    sample_size: usize,
    with_single: bool,
    disk_farm: PathBuf,
    filter: Option<String>,
    limit_sector_count: Option<usize>,
) -> anyhow::Result<()> {
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

    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
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
                    global_challenge: rand::random(),
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
                table_generator: &Mutex::new(PosTable::generator()),
            };

            let mut audit_results = plot_audit.audit(options).unwrap();

            group.bench_function("plot/single/concurrent-chunks", |b| {
                b.iter_batched(
                    || {
                        if let Some(result) = audit_results.pop() {
                            return result;
                        }

                        options.slot_info.global_challenge = rand::random();
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

                        options.slot_info.global_challenge = rand::random();
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
        if cfg!(windows) {
            let plot = RayonFiles::open_with(
                &disk_farm.join(SingleDiskFarm::PLOT_FILE),
                UnbufferedIoFileWindows::open,
            )
            .map_err(|error| anyhow::anyhow!("Failed to open plot: {error}"))?;
            let plot_audit = PlotAudit::new(&plot);
            let mut options = PlotAuditOptions::<PosTable> {
                public_key: single_disk_farm_info.public_key(),
                reward_address: single_disk_farm_info.public_key(),
                slot_info: SlotInfo {
                    slot_number: 0,
                    global_challenge: rand::random(),
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

                        options.slot_info.global_challenge = rand::random();
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

                        options.slot_info.global_challenge = rand::random();
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
                    global_challenge: rand::random(),
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

                        options.slot_info.global_challenge = rand::random();
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

                        options.slot_info.global_challenge = rand::random();
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
