#![feature(const_option, type_changing_struct_update)]

mod commands;
mod utils;

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use subspace_farmer::single_disk_farm::SingleDiskFarm;
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
        Command::Scrub { disk_farms } => {
            if disk_farms.is_empty() {
                info!("No farm was specified, so there is nothing to do");
            } else {
                commands::scrub(&disk_farms);
            }
        }
        Command::Wipe { disk_farms } => {
            for disk_farm in &disk_farms {
                if !disk_farm.exists() {
                    panic!("Directory {} doesn't exist", disk_farm.display());
                }
            }

            for disk_farm in &disk_farms {
                // TODO: Delete this section once we don't have shared data anymore
                info!("Wiping shared data");
                let _ = fs::remove_file(disk_farm.join("known_addresses_db"));
                let _ = fs::remove_file(disk_farm.join("known_addresses.bin"));
                let _ = fs::remove_file(disk_farm.join("piece_cache_db"));
                let _ = fs::remove_file(disk_farm.join("providers_db"));

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
