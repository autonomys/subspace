#![feature(type_changing_struct_update)]

mod commands;
mod ss58;
mod utils;

use crate::utils::get_usable_plot_space;
use anyhow::Result;
use bytesize::ByteSize;
use clap::{ArgEnum, Parser, ValueHint};
use ss58::parse_ss58_reward_address;
use std::fs;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::str::FromStr;
use subspace_core_primitives::PublicKey;
use subspace_farmer::single_disk_plot::SingleDiskPlot;
use subspace_networking::libp2p::Multiaddr;
use tempfile::TempDir;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(all(
    target_arch = "x86_64",
    target_vendor = "unknown",
    target_os = "linux",
    target_env = "gnu"
))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Arguments for farmer
#[derive(Debug, Parser)]
struct FarmingArgs {
    /// WebSocket RPC URL of the Subspace node to connect to
    #[clap(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Address for farming rewards
    #[clap(long, parse(try_from_str = parse_ss58_reward_address))]
    reward_address: PublicKey,
    /// Maximum plot size in human readable format (e.g. 10GB, 2TiB) or just bytes (e.g. 4096).
    #[clap(long, default_value_t)]
    plot_size: ByteSize,
    /// Number of major concurrent operations to allow for disk
    #[clap(long, default_value = "2")]
    disk_concurrency: NonZeroU16,
    /// Disable farming
    #[clap(long)]
    disable_farming: bool,
    /* ****** DSN parameters ******/
    /// Enable DSN and use DSN piece provider for plotting
    #[clap(long)]
    enable_dsn: bool,
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[clap(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported.
    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/40333")]
    listen_on: Vec<Multiaddr>,
    /// Record cache size in items.
    #[clap(long, default_value_t = 32768)]
    record_cache_size: usize,
    /// Record cache DB path.
    #[clap(long)]
    record_cache_db_path: Option<String>,
}

#[derive(Debug, Clone, Copy, ArgEnum)]
enum WriteToDisk {
    Nothing,
    Everything,
}

impl Default for WriteToDisk {
    fn default() -> Self {
        Self::Everything
    }
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    /// Wipes plot and identity
    Wipe,
    /// Start a farmer using previously created plot
    Farm(FarmingArgs),
    /// Print information about farm and its content
    Info,
    // TODO: Update or remove
    // /// Benchmark disk in order to see a throughput of the disk for plotting
    // Bench {
    //     /// Maximum plot size in human readable format (e.g. 10GB, 2TiB) or just bytes (e.g. 4096).
    //     #[clap(long)]
    //     plot_size: ByteSize,
    //     /// Number of major concurrent operations to allow for disk
    //     #[clap(long, default_value = "2")]
    //     disk_concurrency: NonZeroU16,
    //     /// How much things to write on disk (the more we write during benchmark, the more accurate
    //     /// it is)
    //     #[clap(arg_enum, long, default_value_t)]
    //     write_to_disk: WriteToDisk,
    //     /// Amount of data to plot for benchmarking.
    //     ///
    //     /// Only `G` and `T` endings are supported.
    //     #[clap(long)]
    //     write_pieces_size: ByteSize,
    //     /// Skip recommitment benchmark
    //     #[clap(long)]
    //     no_recommitments: bool,
    // },
}

#[derive(Debug)]
struct DiskFarm {
    /// Path to directory where data is stored.
    directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    allocated_plotting_space: u64,
}

impl FromStr for DiskFarm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(',').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err("Must contain 3 coma-separated components".to_string());
        }

        let mut plot_directory = None;
        let mut allocated_plotting_space = None;

        for part in parts {
            let part = part.splitn(2, '=').collect::<Vec<_>>();
            if part.len() != 2 {
                return Err("Each component must contain = separating key from value".to_string());
            }

            let key = *part.first().expect("Length checked above; qed");
            let value = *part.get(1).expect("Length checked above; qed");

            match key {
                "path" => {
                    plot_directory.replace(
                        PathBuf::try_from(value).map_err(|error| {
                            format!("Failed to parse `path` \"{value}\": {error}")
                        })?,
                    );
                }
                "size" => {
                    allocated_plotting_space.replace(
                        value
                            .parse::<ByteSize>()
                            .map_err(|error| {
                                format!("Failed to parse `size` \"{value}\": {error}")
                            })?
                            .as_u64(),
                    );
                }
                key => {
                    return Err(format!(
                        "Key \"{key}\" is not supported, only `path` or `size`"
                    ));
                }
            }
        }

        Ok(DiskFarm {
            directory: plot_directory.ok_or({
                "`path` key is required with path to directory where plots will be stored"
            })?,
            allocated_plotting_space: allocated_plotting_space.ok_or({
                "`size` key is required with path to directory where plots will be stored"
            })?,
        })
    }
}

#[derive(Debug, Parser)]
#[clap(about, version)]
struct Command {
    #[clap(subcommand)]
    subcommand: Subcommand,
    /// Base path for data storage instead of platform-specific default
    #[clap(
        long,
        default_value_os_t = utils::default_base_path(),
        value_hint = ValueHint::FilePath,
        conflicts_with = "farm",
        conflicts_with = "tmp"
    )]
    base_path: PathBuf,
    /// Specify single plot located at specified path, can be specified multiple times to use
    /// multiple disks.
    ///
    /// Format is coma-separated string like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max plot size in human readable format (e.g. 10GB, 2TiB) or just bytes.
    /// TODO: Update overhead number here or account for it automatically
    /// Note that `size` is how much data will be plotted, you also need to account for metadata,
    /// which right now occupies up to 8% of the disk space.
    #[clap(long, conflicts_with = "base-path", conflicts_with = "tmp")]
    farm: Vec<DiskFarm>,
    /// Run temporary farmer, this will create a temporary directory for storing farmer data that
    /// will be delete at the end of the process
    #[clap(long, conflicts_with = "base-path", conflicts_with = "farm")]
    tmp: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            fmt::layer().with_span_events(FmtSpan::CLOSE).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .init();
    utils::raise_fd_limit();

    let command = Command::parse();

    let (base_path, _tmp_directory) = if command.tmp {
        let tmp_directory = TempDir::new()?;
        (tmp_directory.as_ref().to_path_buf(), Some(tmp_directory))
    } else {
        (command.base_path, None)
    };

    match command.subcommand {
        Subcommand::Wipe => {
            let disk_farms = if command.farm.is_empty() {
                if !base_path.exists() {
                    info!("Done");

                    return Ok(());
                }

                // TODO: Support wiping of old disk plots for backwards compatibility

                vec![DiskFarm {
                    directory: base_path,
                    allocated_plotting_space: get_usable_plot_space(0),
                }]
            } else {
                for farm in &command.farm {
                    if !farm.directory.exists() {
                        panic!("Directory {} doesn't exist", farm.directory.display());
                    }
                }

                command.farm
            };

            for farm in &disk_farms {
                SingleDiskPlot::wipe(&farm.directory)?;
            }

            info!("Done");
        }
        Subcommand::Farm(farming_args) => {
            let disk_farms = if command.farm.is_empty() {
                if !base_path.exists() {
                    fs::create_dir_all(&base_path).unwrap_or_else(|error| {
                        panic!(
                            "Failed to create data directory {:?}: {:?}",
                            base_path, error
                        )
                    });
                }

                let plot_size = farming_args.plot_size.as_u64();

                if plot_size < 1024 * 1024 {
                    return Err(anyhow::anyhow!(
                        "Plot size is too low ({0} bytes). Did you mean {0}G or {0}T?",
                        plot_size
                    ));
                }

                vec![DiskFarm {
                    directory: base_path,
                    allocated_plotting_space: get_usable_plot_space(plot_size),
                }]
            } else {
                for farm in &command.farm {
                    if !farm.directory.exists() {
                        panic!("Directory {} doesn't exist", farm.directory.display());
                    }
                }

                command.farm
            };

            commands::farm_multi_disk(disk_farms, farming_args).await?;
        }
        Subcommand::Info => {
            let disk_farms = if command.farm.is_empty() {
                vec![DiskFarm {
                    directory: base_path,
                    allocated_plotting_space: get_usable_plot_space(0),
                }]
            } else {
                command.farm
            };

            commands::info(disk_farms);
        } // TODO: Update or remove
          // Subcommand::Bench {
          //     plot_size,
          //     disk_concurrency,
          //     write_to_disk,
          //     write_pieces_size,
          //     no_recommitments,
          // } => {
          //     let disk_farms = if command.farm.is_empty() {
          //         if !base_path.exists() {
          //             fs::create_dir_all(&base_path).unwrap_or_else(|error| {
          //                 panic!(
          //                     "Failed to create data directory {:?}: {:?}",
          //                     base_path, error
          //                 )
          //             });
          //         }
          //
          //         let plot_size = plot_size.as_u64();
          //
          //         if plot_size < 1024 * 1024 {
          //             return Err(anyhow::anyhow!(
          //                 "Plot size is too low ({0} bytes). Did you mean {0}G or {0}T?",
          //                 plot_size
          //             ));
          //         }
          //
          //         vec![DiskFarm {
          //             directory: base_path.clone(),
          //             metadata_directory: base_path,
          //             allocated_plotting_space: get_usable_plot_space(plot_size),
          //         }]
          //     } else {
          //         for farm in &command.farm {
          //             if !farm.directory.exists() {
          //                 panic!("Plot directory {} doesn't exist", farm.directory.display());
          //             }
          //             if !farm.metadata_directory.exists() {
          //                 panic!(
          //                     "Metadata directory {} doesn't exist",
          //                     farm.metadata_directory.display()
          //                 );
          //             }
          //         }
          //
          //         command.farm
          //     };
          //
          //     commands::bench(
          //         disk_farms,
          //         disk_concurrency,
          //         write_to_disk,
          //         write_pieces_size.as_u64(),
          //         !no_recommitments,
          //     )
          //     .await?
          // }
    }
    Ok(())
}
