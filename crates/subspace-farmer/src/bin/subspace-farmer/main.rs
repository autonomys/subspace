#![feature(const_option, type_changing_struct_update)]

mod commands;
mod ss58;
mod utils;

use bytesize::ByteSize;
use clap::{Parser, ValueEnum, ValueHint};
use ss58::parse_ss58_reward_address;
use std::fs;
use std::num::{NonZeroU16, NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::str::FromStr;
use subspace_core_primitives::PublicKey;
use subspace_farmer::single_disk_farm::SingleDiskFarm;
use subspace_networking::libp2p::Multiaddr;
use subspace_proof_of_space::chia::ChiaTable;
use tempfile::TempDir;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

type PosTable = ChiaTable;

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
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: PublicKey,
    /// Maximum number of pieces in sector (can override protocol value to something lower).
    #[arg(long)]
    max_pieces_in_sector: Option<u16>,
    /// Number of major concurrent operations to allow for disk
    #[arg(long, default_value = "2")]
    disk_concurrency: NonZeroU16,
    /// Disable farming
    #[arg(long)]
    disable_farming: bool,
    /// DSN parameters
    #[clap(flatten)]
    dsn: DsnArgs,
    /// Number of plots that can be plotted concurrently, impacts RAM usage.
    #[arg(long, default_value = "10")]
    max_concurrent_plots: NonZeroUsize,
    /// Percentage of plot dedicated for caching purposes, 99% max.
    #[arg(long, default_value = "1", value_parser = cache_percentage_parser)]
    cache_percentage: NonZeroU8,
    /// Do not print info about configured farms on startup.
    #[arg(long)]
    no_info: bool,
}

fn cache_percentage_parser(s: &str) -> anyhow::Result<NonZeroU8> {
    let cache_percentage = NonZeroU8::from_str(s)?;

    if cache_percentage.get() > 99 {
        return Err(anyhow::anyhow!("Cache percentage can't exceed 100"));
    }

    Ok(cache_percentage)
}

/// Arguments for DSN
#[derive(Debug, Parser)]
struct DsnArgs {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30533")]
    listen_on: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
    #[arg(long, default_value_t = false)]
    enable_private_ips: bool,
    /// Multiaddrs of reserved nodes to maintain a connection to, multiple are supported
    #[arg(long)]
    reserved_peers: Vec<Multiaddr>,
    /// Defines max established incoming connection limit.
    #[arg(long, default_value_t = 50)]
    in_connections: u32,
    /// Defines max established outgoing swarm connection limit.
    #[arg(long, default_value_t = 50)]
    out_connections: u32,
    /// Defines max pending incoming connection limit.
    #[arg(long, default_value_t = 50)]
    pending_in_connections: u32,
    /// Defines max pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 50)]
    pending_out_connections: u32,
    /// Defines target total (in and out) connection number that should be maintained.
    #[arg(long, default_value_t = 50)]
    target_connections: u32,
    /// Known external addresses
    #[arg(long, alias = "external-address")]
    external_addresses: Vec<Multiaddr>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WriteToDisk {
    Nothing,
    Everything,
}

impl Default for WriteToDisk {
    #[inline]
    fn default() -> Self {
        Self::Everything
    }
}

#[allow(clippy::large_enum_variant)] // we allow large function parameter list and enums
#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    /// Wipes the farm
    Wipe,
    /// Start a farmer, does plotting and farming
    Farm(FarmingArgs),
    /// Print information about farm and its content
    Info,
    /// Checks the farm for corruption and repairs errors (caused by disk errors or something else)
    Scrub,
}

#[derive(Debug, Clone)]
struct DiskFarm {
    /// Path to directory where data is stored.
    directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    allocated_plotting_space: u64,
}

impl FromStr for DiskFarm {
    type Err = String;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        let parts = s.split(',').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err("Must contain 2 coma-separated components".to_string());
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
    /// Specify single plot located at specified path, can be specified multiple times to use
    /// multiple disks.
    ///
    /// Format is coma-separated string like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure not not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime).
    #[arg(long)]
    farm: Vec<DiskFarm>,
    /// Run temporary farmer with specified plot size in human readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory for storing farmer data that
    /// will be deleted at the end of the process.
    #[arg(long, conflicts_with = "farm")]
    tmp: Option<ByteSize>,
    /// Enables the "development mode". Toggles flags like `--enable-private-ips`
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214
                .with_ansi(supports_color::on(supports_color::Stream::Stderr).is_some())
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();
    utils::raise_fd_limit();

    let command = Command::parse();

    let (disk_farms, _tmp_directory) = if let Some(plot_size) = command.tmp {
        let tmp_directory = TempDir::new()?;
        (
            vec![DiskFarm {
                directory: tmp_directory.as_ref().to_path_buf(),
                allocated_plotting_space: plot_size.as_u64(),
            }],
            Some(tmp_directory),
        )
    } else {
        (command.farm, None)
    };

    match command.subcommand {
        Subcommand::Wipe => {
            for farm in &disk_farms {
                if !farm.directory.exists() {
                    panic!("Directory {} doesn't exist", farm.directory.display());
                }
            }

            for farm in &disk_farms {
                // TODO: Delete this section once we don't have shared data anymore
                info!("Wiping shared data");
                let _ = fs::remove_file(farm.directory.join("known_addresses_db"));
                let _ = fs::remove_file(farm.directory.join("known_addresses.bin"));
                let _ = fs::remove_file(farm.directory.join("piece_cache_db"));
                let _ = fs::remove_file(farm.directory.join("providers_db"));

                SingleDiskFarm::wipe(&farm.directory)?;
            }

            info!("Done");
        }
        Subcommand::Farm(mut farming_args) => {
            for farm in &disk_farms {
                if !farm.directory.exists() {
                    if let Err(error) = fs::create_dir(&farm.directory) {
                        panic!(
                            "Directory {} doesn't exist and can't be created: {}",
                            farm.directory.display(),
                            error
                        );
                    }
                }
            }

            // Override the `--enable_private_ips` flag with `--dev`
            farming_args.dsn.enable_private_ips =
                farming_args.dsn.enable_private_ips || command.dev;

            commands::farm_multi_disk::<PosTable>(disk_farms, farming_args).await?;
        }
        Subcommand::Info => {
            commands::info(disk_farms);
        }
        Subcommand::Scrub => {
            let disk_farms = disk_farms
                .into_iter()
                .map(|disk_farm| disk_farm.directory)
                .collect::<Vec<_>>();
            commands::scrub(&disk_farms);
        }
    }
    Ok(())
}
