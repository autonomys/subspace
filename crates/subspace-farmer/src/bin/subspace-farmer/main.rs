#![feature(
    duration_constructors,
    extract_if,
    hash_extract_if,
    let_chains,
    type_changing_struct_update
)]

mod commands;
mod utils;

use clap::Parser;
use std::path::PathBuf;
use std::process::exit;
use std::{fs, panic};
use subspace_farmer::single_disk_farm::{ScrubTarget, SingleDiskFarm};
use subspace_proof_of_space::chia::ChiaTable;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type PosTable = ChiaTable;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start a farmer, does plotting and farming
    Farm(commands::farm::FarmingArgs),
    /// Farming cluster
    Cluster(commands::cluster::ClusterArgs),
    /// Run various benchmarks
    #[clap(subcommand)]
    Benchmark(commands::benchmark::BenchmarkArgs),
    /// Print information about farm and its content
    Info {
        /// One or more farm located at specified path.
        ///
        /// Example:
        ///   /path/to/directory
        disk_farms: Vec<PathBuf>,
    },
    /// Checks the farm for corruption and repairs errors (caused by disk errors or something else)
    Scrub {
        /// One or more farm located at specified path.
        ///
        /// Example:
        ///   /path/to/directory
        disk_farms: Vec<PathBuf>,
        /// Disable farm locking, for example if file system doesn't support it
        #[arg(long)]
        disable_farm_locking: bool,
        /// Scrub target
        ///
        /// Possible values are: `all`, `metadata`, `plot` and `cache`
        #[arg(long, default_value_t = ScrubTarget::All)]
        target: ScrubTarget,
        /// Check for errors, but do not attempt to correct them
        #[arg(long)]
        dry_run: bool,
    },
    /// Wipes the farm
    Wipe {
        /// One or more farm located at specified path.
        ///
        /// Example:
        ///   /path/to/directory
        disk_farms: Vec<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Exit on panics, rather than unwinding. Unwinding can hang the tokio runtime waiting for
    // stuck tasks or threads.
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214, also on
                //  Windows terminal doesn't support the same colors as bash does
                .with_ansi(if cfg!(windows) {
                    false
                } else {
                    supports_color::on(supports_color::Stream::Stderr).is_some()
                })
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();
    utils::raise_fd_limit();

    let command = Command::parse();

    match command {
        Command::Farm(farming_args) => {
            commands::farm::farm::<PosTable>(farming_args).await?;
        }
        Command::Cluster(cluster_args) => {
            commands::cluster::cluster::<PosTable>(cluster_args).await?;
        }
        Command::Benchmark(benchmark_args) => {
            commands::benchmark::benchmark(benchmark_args)?;
        }
        Command::Info { disk_farms } => {
            if disk_farms.is_empty() {
                info!("No farm was specified, so there is nothing to do");
            } else {
                commands::info(disk_farms);
            }
        }
        Command::Scrub {
            disk_farms,
            disable_farm_locking,
            target,
            dry_run,
        } => {
            if disk_farms.is_empty() {
                info!("No farm was specified, so there is nothing to do");
            } else {
                commands::scrub(&disk_farms, disable_farm_locking, target, dry_run);
            }
        }
        Command::Wipe { disk_farms } => {
            for disk_farm in &disk_farms {
                if !disk_farm.exists() {
                    panic!("Directory {} doesn't exist", disk_farm.display());
                }
            }

            for disk_farm in &disk_farms {
                if disk_farm.join("known_addresses.bin").exists() {
                    info!("Wiping known addresses");
                    let _ = fs::remove_file(disk_farm.join("known_addresses.bin"));
                }

                SingleDiskFarm::wipe(disk_farm)?;
            }

            if disk_farms.is_empty() {
                info!("No farm was specified, so there is nothing to do");
            } else {
                info!("Done");
            }
        }
    }
    Ok(())
}
