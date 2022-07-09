mod commands;
mod ss58;
mod utils;

use anyhow::Result;
use clap::{ArgEnum, Parser, ValueHint};
use ss58::parse_ss58_reward_address;
use std::fs;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::str::FromStr;
use subspace_core_primitives::PublicKey;
use subspace_farmer::single_disk_farm::SingleDiskFarm;
use subspace_networking::libp2p::Multiaddr;
use tempfile::TempDir;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use utils::parse_human_readable_size;

#[derive(Debug, Clone, Copy, ArgEnum)]
enum ArchivingFrom {
    /// Sync from node using RPC endpoint (recommended)
    Rpc,
    /// Sync from node using DSN (experimental)
    Dsn,
}

impl Default for ArchivingFrom {
    fn default() -> Self {
        Self::Rpc
    }
}

/// Arguments for farmer
#[derive(Debug, Parser)]
struct FarmingArgs {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[clap(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported, subspace networking is disabled when none specified.
    #[clap(long)]
    listen_on: Vec<Multiaddr>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[clap(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Host and port where built-in WebSocket RPC server should listen for incoming connections
    #[clap(long, short, default_value = "127.0.0.1:9955")]
    ws_server_listen_addr: SocketAddr,
    /// Address for farming rewards
    #[clap(long, parse(try_from_str = parse_ss58_reward_address))]
    reward_address: PublicKey,
    /// Maximum plot size in human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
    ///
    /// Only `G` and `T` endings are supported.
    #[clap(long, parse(try_from_str = parse_human_readable_size))]
    plot_size: u64,
    /// Maximum single plot size in bytes human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
    ///
    /// Only `G` and `T` endings are supported.
    ///
    /// Only a developer testing flag, not helpful for normal users.
    #[clap(long, parse(try_from_str = parse_human_readable_size))]
    max_plot_size: Option<u64>,
    /// Number of major concurrent operations to allow for disk
    #[clap(long, default_value = "2")]
    disk_concurrency: NonZeroU16,
    /// Archive data from
    #[clap(arg_enum, long, default_value_t)]
    archiving: ArchivingFrom,
    /// Use dsn for syncing
    #[clap(long)]
    dsn_sync: bool,
    /// Disable farming
    #[clap(long)]
    disable_farming: bool,
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
    /// Benchmark disk in order to see a throughput of the disk for plotting
    Bench {
        /// Maximum plot size in human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
        ///
        /// Only `G` and `T` endings are supported.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        plot_size: u64,
        /// Maximum single plot size in bytes human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
        ///
        /// Only `G` and `T` endings are supported.
        ///
        /// Only a developer testing flag, as it might be needed for testing.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        max_plot_size: Option<u64>,
        /// How much things to write on disk (the more we write during benchmark, the more accurate
        /// it is)
        #[clap(arg_enum, long, default_value_t)]
        write_to_disk: WriteToDisk,
        /// Amount of data to plot for benchmarking.
        ///
        /// Only `G` and `T` endings are supported.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        write_pieces_size: u64,
        /// Skip recommitment benchmark
        #[clap(long)]
        no_recommitments: bool,
    },
}

#[derive(Debug)]
struct DiskFarm {
    /// Path to directory where plots are stored, typically HDD.
    plot_directory: PathBuf,
    /// Path to directory for storing metadata, typically SSD.
    metadata_directory: PathBuf,
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
        let mut metadata_directory = None;
        let mut allocated_plotting_space = None;

        for part in parts {
            let part = part.splitn(2, '=').collect::<Vec<_>>();
            if part.len() != 2 {
                return Err("Each component must contain = separating key from value".to_string());
            }

            let key = *part.first().expect("Length checked above; qed");
            let value = *part.get(1).expect("Length checked above; qed");

            match key {
                "hdd" => {
                    plot_directory.replace(
                        PathBuf::try_from(value).map_err(|error| {
                            format!("Failed to parse `hdd` \"{value}\": {error}")
                        })?,
                    );
                }
                "ssd" => {
                    metadata_directory.replace(
                        PathBuf::try_from(value).map_err(|error| {
                            format!("Failed to parse `ssd` \"{value}\": {error}")
                        })?,
                    );
                }
                "size" => {
                    allocated_plotting_space.replace(
                        parse_human_readable_size(value).map_err(|error| {
                            format!("Failed to parse `size` \"{value}\": {error}")
                        })?,
                    );
                }
                key => {
                    return Err(format!(
                        "Key \"{key}\" is not supported, only `hdd`, `ssd` or `size`"
                    ));
                }
            }
        }

        Ok(DiskFarm {
            plot_directory: plot_directory.ok_or({
                "`hdd` key is required with path to directory where plots will be stored"
            })?,
            metadata_directory: metadata_directory.ok_or({
                "`ssd` key is required with path to directory where metadata will be stored"
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
    /// Specify single disk farm consisting (typically) from HDD (used for storing plot) and SSD
    /// (used for storing various metadata with frequent random access), can be specified multiple
    /// times to use multiple disks.
    ///
    /// Format is coma-separated string like this:
    ///
    ///   hdd=/path/to/plot-directory,ssd=/path/to/metadata-directory,size=5T
    ///
    /// `size` is max plot size in human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
    /// Note that `size` is how much data will be plotted, you also need to account for metadata,
    /// which right now occupies up to 8% of the disk space.
    ///
    /// The same path can be specified for both `hdd` and `ssd` if you want, the same `ssd` path can
    /// be shared by multiple `hdd`s as well:
    ///
    ///   --farm hdd=/hdd1,ssd=/ssd,size=5T --farm hdd=/hdd2,ssd=/ssd,size=5T
    #[clap(long, conflicts_with = "base-path", conflicts_with = "tmp")]
    farm: Vec<DiskFarm>,
    /// Run temporary farmer, this will create a temporary directory for storing farmer data that
    /// will be delete at the end of the process
    #[clap(long, conflicts_with = "base-path", conflicts_with = "farm")]
    tmp: bool,
}

// TODO: Add graceful shutdown handling, without it temporary directory may be left not deleted
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

    let command = Command::parse();

    let (base_path, _tmp_directory) = if command.tmp {
        let tmp_directory = TempDir::new()?;
        (tmp_directory.as_ref().to_path_buf(), Some(tmp_directory))
    } else {
        (command.base_path, None)
    };

    match command.subcommand {
        Subcommand::Wipe => {
            if command.farm.is_empty() {
                commands::wipe(&base_path)?;
            } else {
                for farm in &command.farm {
                    SingleDiskFarm::wipe(&farm.plot_directory, &farm.metadata_directory)?;
                }
            }

            info!("Done");
        }
        Subcommand::Farm(farming_args) => {
            if command.farm.is_empty() {
                if !base_path.exists() {
                    fs::create_dir_all(&base_path).unwrap_or_else(|error| {
                        panic!(
                            "Failed to create data directory {:?}: {:?}",
                            base_path, error
                        )
                    });
                }

                commands::farm_legacy(base_path, farming_args).await?;
            } else {
                for farm in &command.farm {
                    if !farm.plot_directory.exists() {
                        panic!(
                            "Plot directory {} doesn't exist",
                            farm.plot_directory.display()
                        );
                    }
                    if !farm.metadata_directory.exists() {
                        panic!(
                            "Metadata directory {} doesn't exist",
                            farm.metadata_directory.display()
                        );
                    }
                }
                commands::farm_multi_disk(command.farm, farming_args).await?;
            }
        }
        Subcommand::Bench {
            plot_size,
            max_plot_size,
            write_to_disk,
            write_pieces_size,
            no_recommitments,
        } => {
            if command.farm.is_empty() {
                if !base_path.exists() {
                    fs::create_dir_all(&base_path).unwrap_or_else(|error| {
                        panic!(
                            "Failed to create data directory {:?}: {:?}",
                            base_path, error
                        )
                    });
                }

                commands::bench(
                    base_path,
                    plot_size,
                    max_plot_size,
                    write_to_disk,
                    write_pieces_size,
                    !no_recommitments,
                )
                .await?
            } else {
                unimplemented!()
            }
        }
    }
    Ok(())
}
