#![feature(const_option, type_changing_struct_update)]

mod commands;
mod utils;

use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::str::FromStr;
use subspace_core_primitives::PublicKey;
use subspace_farmer::single_disk_farm::SingleDiskFarm;
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_networking::libp2p::Multiaddr;
use subspace_proof_of_space::chia::ChiaTable;
use tracing::{info, warn};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type PosTable = ChiaTable;

fn available_parallelism() -> usize {
    match std::thread::available_parallelism() {
        Ok(parallelism) => parallelism.get(),
        Err(error) => {
            warn!(
                %error,
                "Unable to identify available parallelism, you might want to configure thread pool sizes with CLI \
                options manually"
            );

            0
        }
    }
}

/// Arguments for farmer
#[derive(Debug, Parser)]
struct FarmingArgs {
    /// One or more farm located at specified path, each with its own allocated space.
    ///
    /// In case of multiple disks, it is recommended to specify them individually rather than using
    /// RAID 0, that way farmer will be able to better take advantage of concurrency of individual
    /// drives.
    ///
    /// Format for each farm is coma-separated list of strings like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure not not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime).
    disk_farms: Vec<DiskFarm>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: PublicKey,
    /// Percentage of allocated space dedicated for caching purposes, 99% max
    #[arg(long, default_value = "1", value_parser = cache_percentage_parser)]
    cache_percentage: NonZeroU8,
    /// Sets some flags that are convenient during development, currently `--enable-private-ips`.
    #[arg(long)]
    dev: bool,
    /// Run temporary farmer with specified plot size in human readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory for storing farmer data that
    /// will be deleted at the end of the process.
    #[arg(long, conflicts_with = "disk_farms")]
    tmp: Option<ByteSize>,
    /// Maximum number of pieces in sector (can override protocol value to something lower).
    ///
    /// This will make plotting of individual sectors faster, decrease load on CPU proving, but also
    /// proportionally increase amount of disk reads during audits since every sector needs to be
    /// audited and there will be more of them.
    ///
    /// This is primarily for development and not recommended to use by regular users.
    #[arg(long)]
    max_pieces_in_sector: Option<u16>,
    /// DSN parameters
    #[clap(flatten)]
    dsn: DsnArgs,
    /// Do not print info about configured farms on startup
    #[arg(long)]
    no_info: bool,
    /// Defines endpoints for the prometheus metrics server. It doesn't start without at least
    /// one specified endpoint. Format: 127.0.0.1:8080
    #[arg(long, alias = "metrics-endpoint")]
    metrics_endpoints: Vec<SocketAddr>,
    /// Defines how many sectors farmer will download concurrently, allows to limit memory usage of
    /// the plotting process, increasing beyond 2 makes practical sense due to limited networking
    /// concurrency and will likely result in slower plotting overall
    #[arg(long, default_value = "2")]
    sector_downloading_concurrency: NonZeroUsize,
    /// Defines how many sectors farmer will encode concurrently, should generally never be set to
    /// more than 1 because it will most likely result in slower plotting overall
    #[arg(long, default_value = "1")]
    sector_encoding_concurrency: NonZeroUsize,
    /// Allows to enable farming during initial plotting. Not used by default because plotting is so
    /// intense on CPU and memory that farming will likely not work properly, yet it will
    /// significantly impact plotting speed, delaying the time when farming can actually work
    /// properly.
    #[arg(long)]
    farm_during_initial_plotting: bool,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of CPU cores available in
    /// the system
    #[arg(long, default_value_t = available_parallelism())]
    farming_thread_pool_size: usize,
    /// Size of thread pool used for plotting, defaults to number of CPU cores available in the
    /// system. This thread pool is global for all farms and generally doesn't need to be changed.
    #[arg(long, default_value_t = available_parallelism())]
    plotting_thread_pool_size: usize,
    /// Size of thread pool used for replotting, typically smaller pool than for plotting to not
    /// affect farming as much, defaults to half of the number of CPU cores available in the system.
    /// This thread pool is global for all farms and generally doesn't need to be changed.
    #[arg(long, default_value_t = available_parallelism() / 2)]
    replotting_thread_pool_size: usize,
}

fn cache_percentage_parser(s: &str) -> anyhow::Result<NonZeroU8> {
    let cache_percentage = NonZeroU8::from_str(s)?;

    if cache_percentage.get() > 99 {
        return Err(anyhow::anyhow!("Cache percentage can't exceed 99"));
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
    #[arg(long, default_values_t = [
        "/ip4/0.0.0.0/udp/30533/quic-v1".parse::<Multiaddr>().expect("Manual setting"),
        "/ip4/0.0.0.0/tcp/30533".parse::<Multiaddr>().expect("Manual setting"),
    ])]
    listen_on: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in
    /// Kademlia DHT.
    #[arg(long, default_value_t = false)]
    enable_private_ips: bool,
    /// Multiaddrs of reserved nodes to maintain a connection to, multiple are supported
    #[arg(long)]
    reserved_peers: Vec<Multiaddr>,
    /// Defines max established incoming connection limit.
    #[arg(long, default_value_t = 50)]
    in_connections: u32,
    /// Defines max established outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    out_connections: u32,
    /// Defines max pending incoming connection limit.
    #[arg(long, default_value_t = 50)]
    pending_in_connections: u32,
    /// Defines max pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pending_out_connections: u32,
    /// Defines target total (in and out) connection number that should be maintained.
    #[arg(long, default_value_t = 50)]
    target_connections: u32,
    /// Known external addresses
    #[arg(long, alias = "external-address")]
    external_addresses: Vec<Multiaddr>,
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start a farmer, does plotting and farming
    Farm(FarmingArgs),
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
        Command::Farm(farming_args) => {
            commands::farm::<PosTable>(farming_args).await?;
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
    }
    Ok(())
}
