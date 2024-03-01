mod dsn;
mod metrics;

use crate::commands::farm::dsn::configure_dsn;
use crate::commands::farm::metrics::{FarmerMetrics, SectorState};
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use backoff::ExponentialBackoff;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{FutureExt, StreamExt};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, fs};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PublicKey, Record, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::farmer_cache::FarmerCache;
use subspace_farmer::single_disk_farm::farming::FarmingNotification;
use subspace_farmer::single_disk_farm::{
    SectorExpirationDetails, SectorPlottingDetails, SectorUpdate, SingleDiskFarm,
    SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::farmer_piece_getter::{DsnCacheRetryPolicy, FarmerPieceGetter};
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::plotted_pieces::PlottedPieces;
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    all_cpu_cores, create_plotting_thread_pool_manager, parse_cpu_cores_sets,
    recommended_number_of_farming_threads, run_future_in_dedicated_thread,
    thread_pool_core_indices, AsyncJoinOnDrop, CpuCoreSet,
};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use thread_priority::ThreadPriority;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, info_span, warn};
use zeroize::Zeroizing;

/// Get piece retry attempts number.
const PIECE_GETTER_MAX_RETRIES: u16 = 7;
/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);

fn should_farm_during_initial_plotting() -> bool {
    let total_cpu_cores = all_cpu_cores()
        .iter()
        .flat_map(|set| set.cpu_cores())
        .count();
    total_cpu_cores > 8
}

/// Plotting thread priority
#[derive(Debug, Parser, Copy, Clone)]
enum PlottingThreadPriority {
    /// Minimum priority
    Min,
    /// Default priority
    Default,
    /// Max priority (not recommended)
    Max,
}

impl FromStr for PlottingThreadPriority {
    type Err = String;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        match s {
            "min" => Ok(Self::Min),
            "default" => Ok(Self::Default),
            "max" => Ok(Self::Max),
            s => Err(format!("Thread priority {s} is not valid")),
        }
    }
}

impl fmt::Display for PlottingThreadPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Min => "min",
            Self::Default => "default",
            Self::Max => "max",
        })
    }
}

impl From<PlottingThreadPriority> for Option<ThreadPriority> {
    fn from(value: PlottingThreadPriority) -> Self {
        match value {
            PlottingThreadPriority::Min => Some(ThreadPriority::Min),
            PlottingThreadPriority::Default => None,
            PlottingThreadPriority::Max => Some(ThreadPriority::Max),
        }
    }
}

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(crate) struct FarmingArgs {
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
    /// Sets some flags that are convenient during development, currently `--allow-private-ips`.
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
    #[arg(long, aliases = ["metrics-endpoint", "metrics-endpoints"])]
    prometheus_listen_on: Vec<SocketAddr>,
    /// Defines how many sectors farmer will download concurrently, allows to limit memory usage of
    /// the plotting process, defaults to `--sector-encoding-concurrency` + 1 to download future
    /// sector ahead of time.
    ///
    /// Increase will result in higher memory usage.
    #[arg(long)]
    sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Defines how many sectors farmer will encode concurrently, defaults to 1 on UMA system and
    /// number of NUMA nodes on NUMA system or L3 cache groups on large CPUs. It is further
    /// restricted by
    /// `--sector-downloading-concurrency` and setting this option higher than
    /// `--sector-downloading-concurrency` will have no effect.
    ///
    /// Increase will result in higher memory usage.
    #[arg(long)]
    sector_encoding_concurrency: Option<NonZeroUsize>,
    /// Defines how many record farmer will encode in a single sector concurrently, defaults to one
    /// record per 2 cores, but not more than 8 in total. Higher concurrency means higher memory
    /// usage and typically more efficient CPU utilization.
    #[arg(long)]
    record_encoding_concurrency: Option<NonZeroUsize>,
    /// Allows to enable farming during initial plotting. Not used by default on machines with 8 or
    /// less logical cores because plotting is so intense on CPU and memory that farming will likely
    /// not work properly, yet it will significantly impact plotting speed, delaying the time when
    /// farming can actually start properly.
    #[arg(long, default_value_t = should_farm_during_initial_plotting(), action = clap::ArgAction::Set)]
    farm_during_initial_plotting: bool,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of logical CPUs
    /// available on UMA system and number of logical CPUs in first NUMA node on NUMA system, but
    /// not more than 32 threads
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
    /// Size of one thread pool used for plotting, defaults to number of logical CPUs available
    /// on UMA system and number of logical CPUs available in NUMA node on NUMA system or L3 cache
    /// groups on large CPUs.
    ///
    /// Number of thread pools is defined by `--sector-encoding-concurrency` option, different
    /// thread pools might have different number of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    plotting_thread_pool_size: Option<NonZeroUsize>,
    /// Specify exact CPU cores to be used for plotting bypassing any custom logic farmer might use
    /// otherwise. It replaces both `--sector-encoding-concurrency` and
    /// `--plotting-thread-pool-size` options if specified. Requires `--replotting-cpu-cores` to be
    /// specified with the same number of CPU cores groups (or not specified at all, in which case
    /// it'll use the same thread pool as plotting).
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["sector_encoding_concurrency", "plotting_thread_pool_size"])]
    plotting_cpu_cores: Option<String>,
    /// Size of one thread pool used for replotting, typically smaller pool than for plotting
    /// to not affect farming as much, defaults to half of the number of logical CPUs available on
    /// UMA system and number of logical CPUs available in NUMA node on NUMA system or L3 cache
    /// groups on large CPUs.
    ///
    /// Number of thread pools is defined by `--sector-encoding-concurrency` option, different
    /// thread pools might have different number of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    replotting_thread_pool_size: Option<NonZeroUsize>,
    /// Specify exact CPU cores to be used for replotting bypassing any custom logic farmer might
    /// use otherwise. It replaces `--replotting-thread_pool_size` options if specified. Requires
    /// `--plotting-cpu-cores` to be specified with the same number of CPU cores groups.
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["sector_encoding_concurrency", "replotting_thread_pool_size"])]
    replotting_cpu_cores: Option<String>,
    /// Plotting thread priority, by default de-prioritizes plotting threads in order to make sure
    /// farming is successful and computer can be used comfortably for other things
    #[arg(long, default_value_t = PlottingThreadPriority::Min)]
    plotting_thread_priority: PlottingThreadPriority,
    /// Disable farm locking, for example if file system doesn't support it
    #[arg(long)]
    disable_farm_locking: bool,
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
    Multiaddr::from(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    .with(Protocol::Udp(30533))
    .with(Protocol::QuicV1),
    Multiaddr::from(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    .with(Protocol::Udp(30533))
    .with(Protocol::QuicV1),
    Multiaddr::from(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    .with(Protocol::Tcp(30533)),
    Multiaddr::from(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    .with(Protocol::Tcp(30533))
    ])]
    listen_on: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in
    /// Kademlia DHT.
    #[arg(long, default_value_t = false)]
    allow_private_ips: bool,
    /// Multiaddrs of reserved nodes to maintain a connection to, multiple are supported
    #[arg(long)]
    reserved_peers: Vec<Multiaddr>,
    /// Defines max established incoming connection limit.
    #[arg(long, default_value_t = 300)]
    in_connections: u32,
    /// Defines max established outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    out_connections: u32,
    /// Defines max pending incoming connection limit.
    #[arg(long, default_value_t = 100)]
    pending_in_connections: u32,
    /// Defines max pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pending_out_connections: u32,
    /// Known external addresses
    #[arg(long, alias = "external-address")]
    external_addresses: Vec<Multiaddr>,
    /// Defines whether we should run blocking Kademlia bootstrap() operation before other requests.
    #[arg(long, default_value_t = false)]
    disable_bootstrap_on_start: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DiskFarm {
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
                    plot_directory.replace(PathBuf::from(value));
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

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm<PosTable>(farming_args: FarmingArgs) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let signal = shutdown_signal();

    let FarmingArgs {
        node_rpc_url,
        reward_address,
        max_pieces_in_sector,
        mut dsn,
        cache_percentage,
        no_info,
        dev,
        tmp,
        mut disk_farms,
        prometheus_listen_on,
        sector_downloading_concurrency,
        sector_encoding_concurrency,
        record_encoding_concurrency,
        farm_during_initial_plotting,
        farming_thread_pool_size,
        plotting_thread_pool_size,
        plotting_cpu_cores,
        replotting_thread_pool_size,
        replotting_cpu_cores,
        plotting_thread_priority,
        disable_farm_locking,
    } = farming_args;

    // Override flags with `--dev`
    dsn.allow_private_ips = dsn.allow_private_ips || dev;
    dsn.disable_bootstrap_on_start = dsn.disable_bootstrap_on_start || dev;

    let _tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = tempfile::Builder::new()
            .prefix("subspace-farmer-")
            .tempdir()?;

        disk_farms = vec![DiskFarm {
            directory: tmp_directory.as_ref().to_path_buf(),
            allocated_plotting_space: plot_size.as_u64(),
        }];

        Some(tmp_directory)
    } else {
        if disk_farms.is_empty() {
            return Err(anyhow!("There must be at least one disk farm provided"));
        }

        for farm in &disk_farms {
            if !farm.directory.exists() {
                if let Err(error) = fs::create_dir(&farm.directory) {
                    return Err(anyhow!(
                        "Directory {} doesn't exist and can't be created: {}",
                        farm.directory.display(),
                        error
                    ));
                }
            }
        }
        None
    };

    let plotted_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let first_farm_directory = &disk_farms
        .first()
        .expect("Disk farm collection is not be empty as checked above; qed")
        .directory;

    let identity = Identity::open_or_create(first_farm_directory)
        .map_err(|error| anyhow!("Failed to open or create identity: {error}"))?;
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();

    let (farmer_cache, farmer_cache_worker) = FarmerCache::new(node_client.clone(), peer_id);

    // Metrics
    let mut prometheus_metrics_registry = Registry::default();
    let farmer_metrics = FarmerMetrics::new(&mut prometheus_metrics_registry);
    let should_start_prometheus_server = !prometheus_listen_on.is_empty();

    let (node, mut node_runner) = {
        if dsn.bootstrap_nodes.is_empty() {
            dsn.bootstrap_nodes = farmer_app_info.dsn_bootstrap_nodes.clone();
        }

        configure_dsn(
            hex::encode(farmer_app_info.genesis_hash),
            first_farm_directory,
            keypair,
            dsn,
            Arc::downgrade(&plotted_pieces),
            node_client.clone(),
            farmer_cache.clone(),
            should_start_prometheus_server.then_some(&mut prometheus_metrics_registry),
        )?
    };

    let _prometheus_worker = if should_start_prometheus_server {
        let prometheus_task = start_prometheus_metrics_server(
            prometheus_listen_on,
            RegistryAdapter::PrometheusClient(prometheus_metrics_registry),
        )?;

        let join_handle = tokio::spawn(prometheus_task);
        Some(AsyncJoinOnDrop::new(join_handle, true))
    } else {
        None
    };

    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let validator = Some(SegmentCommitmentPieceValidator::new(
        node.clone(),
        node_client.clone(),
        kzg.clone(),
    ));
    let piece_provider = PieceProvider::new(node.clone(), validator.clone());

    let piece_getter = FarmerPieceGetter::new(
        piece_provider,
        farmer_cache.clone(),
        node_client.clone(),
        Arc::clone(&plotted_pieces),
        DsnCacheRetryPolicy {
            max_retries: PIECE_GETTER_MAX_RETRIES,
            backoff: ExponentialBackoff {
                initial_interval: GET_PIECE_INITIAL_INTERVAL,
                max_interval: GET_PIECE_MAX_INTERVAL,
                // Try until we get a valid piece
                max_elapsed_time: None,
                multiplier: 1.75,
                ..ExponentialBackoff::default()
            },
        },
    );

    let farmer_cache_worker_fut = run_future_in_dedicated_thread(
        {
            let future = farmer_cache_worker.run(piece_getter.downgrade());

            move || future
        },
        "farmer-cache-worker".to_string(),
    )?;

    let mut single_disk_farms = Vec::with_capacity(disk_farms.len());
    let max_pieces_in_sector = match max_pieces_in_sector {
        Some(max_pieces_in_sector) => {
            if max_pieces_in_sector > farmer_app_info.protocol_info.max_pieces_in_sector {
                warn!(
                    protocol_value = farmer_app_info.protocol_info.max_pieces_in_sector,
                    desired_value = max_pieces_in_sector,
                    "Can't set max pieces in sector higher than protocol value, using protocol \
                    value"
                );

                farmer_app_info.protocol_info.max_pieces_in_sector
            } else {
                max_pieces_in_sector
            }
        }
        None => farmer_app_info.protocol_info.max_pieces_in_sector,
    };

    let mut plotting_thread_pool_core_indices;
    let mut replotting_thread_pool_core_indices;
    if let Some(plotting_cpu_cores) = plotting_cpu_cores {
        plotting_thread_pool_core_indices = parse_cpu_cores_sets(&plotting_cpu_cores)
            .map_err(|error| anyhow::anyhow!("Failed to parse `--plotting-cpu-cores`: {error}"))?;
        replotting_thread_pool_core_indices = match replotting_cpu_cores {
            Some(replotting_cpu_cores) => {
                parse_cpu_cores_sets(&replotting_cpu_cores).map_err(|error| {
                    anyhow::anyhow!("Failed to parse `--replotting-cpu-cores`: {error}")
                })?
            }
            None => plotting_thread_pool_core_indices.clone(),
        };
        if plotting_thread_pool_core_indices.len() != replotting_thread_pool_core_indices.len() {
            return Err(anyhow::anyhow!(
                "Number of plotting thread pools ({}) is not the same as for replotting ({})",
                plotting_thread_pool_core_indices.len(),
                replotting_thread_pool_core_indices.len()
            ));
        }
    } else {
        plotting_thread_pool_core_indices =
            thread_pool_core_indices(plotting_thread_pool_size, sector_encoding_concurrency);
        replotting_thread_pool_core_indices = {
            let mut replotting_thread_pool_core_indices =
                thread_pool_core_indices(replotting_thread_pool_size, sector_encoding_concurrency);
            if replotting_thread_pool_size.is_none() {
                // The default behavior is to use all CPU cores, but for replotting we just want half
                replotting_thread_pool_core_indices
                    .iter_mut()
                    .for_each(|set| set.truncate(set.cpu_cores().len() / 2));
            }
            replotting_thread_pool_core_indices
        };

        if plotting_thread_pool_core_indices.len() > 1 {
            info!(
                l3_cache_groups = %plotting_thread_pool_core_indices.len(),
                "Multiple L3 cache groups detected"
            );

            if plotting_thread_pool_core_indices.len() > disk_farms.len() {
                plotting_thread_pool_core_indices =
                    CpuCoreSet::regroup(&plotting_thread_pool_core_indices, disk_farms.len());
                replotting_thread_pool_core_indices =
                    CpuCoreSet::regroup(&replotting_thread_pool_core_indices, disk_farms.len());

                info!(
                    farms_count = %disk_farms.len(),
                    "Regrouped CPU cores to match number of farms, more farms may leverage CPU more efficiently"
                );
            }
        }
    }

    let downloading_semaphore = Arc::new(Semaphore::new(
        sector_downloading_concurrency
            .map(|sector_downloading_concurrency| sector_downloading_concurrency.get())
            .unwrap_or(plotting_thread_pool_core_indices.len() + 1),
    ));

    let record_encoding_concurrency = record_encoding_concurrency.unwrap_or_else(|| {
        let cpu_cores = plotting_thread_pool_core_indices
            .first()
            .expect("Guaranteed to have some CPU cores; qed");

        NonZeroUsize::new((cpu_cores.cpu_cores().len() / 2).max(1).min(8)).expect("Not zero; qed")
    });

    let plotting_thread_pool_manager = create_plotting_thread_pool_manager(
        plotting_thread_pool_core_indices
            .into_iter()
            .zip(replotting_thread_pool_core_indices),
        plotting_thread_priority.into(),
    )?;
    let farming_thread_pool_size = farming_thread_pool_size
        .map(|farming_thread_pool_size| farming_thread_pool_size.get())
        .unwrap_or_else(recommended_number_of_farming_threads);

    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        debug!(url = %node_rpc_url, %disk_farm_index, "Connecting to node RPC");
        let node_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_farm_fut = SingleDiskFarm::new::<_, _, PosTable>(
            SingleDiskFarmOptions {
                directory: disk_farm.directory.clone(),
                farmer_app_info: farmer_app_info.clone(),
                allocated_space: disk_farm.allocated_plotting_space,
                max_pieces_in_sector,
                node_client,
                reward_address,
                kzg: kzg.clone(),
                erasure_coding: erasure_coding.clone(),
                piece_getter: piece_getter.clone(),
                cache_percentage,
                downloading_semaphore: Arc::clone(&downloading_semaphore),
                record_encoding_concurrency,
                farm_during_initial_plotting,
                farming_thread_pool_size,
                plotting_thread_pool_manager: plotting_thread_pool_manager.clone(),
                disable_farm_locking,
            },
            disk_farm_index,
        );

        let single_disk_farm = match single_disk_farm_fut.await {
            Ok(single_disk_farm) => single_disk_farm,
            Err(SingleDiskFarmError::InsufficientAllocatedSpace {
                min_space,
                allocated_space,
            }) => {
                return Err(anyhow::anyhow!(
                    "Allocated space {} ({}) is not enough, minimum is ~{} (~{}, {} bytes to be \
                    exact)",
                    bytesize::to_string(allocated_space, true),
                    bytesize::to_string(allocated_space, false),
                    bytesize::to_string(min_space, true),
                    bytesize::to_string(min_space, false),
                    min_space
                ));
            }
            Err(error) => {
                return Err(error.into());
            }
        };

        if !no_info {
            let info = single_disk_farm.info();
            println!("Single disk farm {disk_farm_index}:");
            println!("  ID: {}", info.id());
            println!("  Genesis hash: 0x{}", hex::encode(info.genesis_hash()));
            println!("  Public key: 0x{}", hex::encode(info.public_key()));
            println!(
                "  Allocated space: {} ({})",
                bytesize::to_string(info.allocated_space(), true),
                bytesize::to_string(info.allocated_space(), false)
            );
            println!("  Directory: {}", disk_farm.directory.display());
        }

        single_disk_farms.push(single_disk_farm);
    }

    // Acknowledgement is not necessary
    drop(
        farmer_cache
            .replace_backing_caches(
                single_disk_farms
                    .iter()
                    .map(|single_disk_farm| single_disk_farm.piece_cache())
                    .collect(),
                single_disk_farms
                    .iter()
                    .map(|single_disk_farm| single_disk_farm.plot_cache())
                    .collect(),
            )
            .await,
    );
    drop(farmer_cache);

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_farms
        .iter()
        .map(|single_disk_farm| single_disk_farm.piece_reader())
        .collect::<Vec<_>>();

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    {
        let mut future_plotted_pieces = PlottedPieces::new(piece_readers);

        for (disk_farm_index, single_disk_farm) in single_disk_farms.iter().enumerate() {
            let disk_farm_index = disk_farm_index.try_into().map_err(|_error| {
                anyhow!(
                    "More than 256 plots are not supported, consider running multiple farmer \
                    instances"
                )
            })?;

            (0 as SectorIndex..)
                .zip(single_disk_farm.plotted_sectors().await)
                .for_each(
                    |(sector_index, plotted_sector_result)| match plotted_sector_result {
                        Ok(plotted_sector) => {
                            future_plotted_pieces.add_sector(disk_farm_index, &plotted_sector);
                        }
                        Err(error) => {
                            error!(
                                %error,
                                %disk_farm_index,
                                %sector_index,
                                "Failed reading plotted sector on startup, skipping"
                            );
                        }
                    },
                );
        }

        plotted_pieces.lock().replace(future_plotted_pieces);
    }

    info!("Finished collecting already plotted pieces successfully");

    let total_and_plotted_sectors = single_disk_farms
        .iter()
        .map(|single_disk_farm| async {
            let total_sector_count = single_disk_farm.total_sectors_count();
            let plotted_sectors_count = single_disk_farm.plotted_sectors_count().await;

            (total_sector_count, plotted_sectors_count)
        })
        .collect::<FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await;

    let mut single_disk_farms_stream = single_disk_farms
        .into_iter()
        .enumerate()
        .zip(total_and_plotted_sectors)
        .map(|((disk_farm_index, single_disk_farm), sector_counts)| {
            let disk_farm_index = disk_farm_index.try_into().expect(
                "More than 256 plots are not supported, this is checked above already; qed",
            );
            let plotted_pieces = Arc::clone(&plotted_pieces);
            let span = info_span!("", %disk_farm_index);

            // Collect newly plotted pieces
            let on_plotted_sector_callback =
                move |plotted_sector: &PlottedSector,
                      maybe_old_plotted_sector: &Option<PlottedSector>| {
                    let _span_guard = span.enter();

                    {
                        let mut plotted_pieces = plotted_pieces.lock();
                        let plotted_pieces = plotted_pieces
                            .as_mut()
                            .expect("Initial value was populated above; qed");

                        if let Some(old_plotted_sector) = &maybe_old_plotted_sector {
                            plotted_pieces.delete_sector(disk_farm_index, old_plotted_sector);
                        }
                        plotted_pieces.add_sector(disk_farm_index, plotted_sector);
                    }
                };

            let (total_sector_count, plotted_sectors_count) = sector_counts;
            farmer_metrics.update_sectors_total(
                single_disk_farm.id(),
                total_sector_count - plotted_sectors_count,
                SectorState::NotPlotted,
            );
            farmer_metrics.update_sectors_total(
                single_disk_farm.id(),
                plotted_sectors_count,
                SectorState::Plotted,
            );
            single_disk_farm
                .on_sector_update(Arc::new({
                    let single_disk_farm_id = *single_disk_farm.id();
                    let farmer_metrics = farmer_metrics.clone();

                    move |(_sector_index, sector_state)| match sector_state {
                        SectorUpdate::Plotting(SectorPlottingDetails::Starting { .. }) => {
                            farmer_metrics.sector_plotting.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Downloading) => {
                            farmer_metrics.sector_downloading.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Downloaded(time)) => {
                            farmer_metrics
                                .observe_sector_downloading_time(&single_disk_farm_id, time);
                            farmer_metrics.sector_downloaded.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Encoding) => {
                            farmer_metrics.sector_encoding.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Encoded(time)) => {
                            farmer_metrics.observe_sector_encoding_time(&single_disk_farm_id, time);
                            farmer_metrics.sector_encoded.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Writing) => {
                            farmer_metrics.sector_writing.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Written(time)) => {
                            farmer_metrics.observe_sector_writing_time(&single_disk_farm_id, time);
                            farmer_metrics.sector_written.inc();
                        }
                        SectorUpdate::Plotting(SectorPlottingDetails::Finished {
                            plotted_sector,
                            old_plotted_sector,
                            time,
                        }) => {
                            on_plotted_sector_callback(plotted_sector, old_plotted_sector);
                            farmer_metrics.observe_sector_plotting_time(&single_disk_farm_id, time);
                            farmer_metrics.sector_plotted.inc();
                            farmer_metrics
                                .update_sector_state(&single_disk_farm_id, SectorState::Plotted);
                        }
                        SectorUpdate::Expiration(SectorExpirationDetails::AboutToExpire) => {
                            farmer_metrics.update_sector_state(
                                &single_disk_farm_id,
                                SectorState::AboutToExpire,
                            );
                        }
                        SectorUpdate::Expiration(SectorExpirationDetails::Expired) => {
                            farmer_metrics
                                .update_sector_state(&single_disk_farm_id, SectorState::Expired);
                        }
                        SectorUpdate::Expiration(SectorExpirationDetails::Determined {
                            ..
                        }) => {
                            // Not interested in here
                        }
                    }
                }))
                .detach();

            single_disk_farm
                .on_farming_notification(Arc::new({
                    let single_disk_farm_id = *single_disk_farm.id();
                    let farmer_metrics = farmer_metrics.clone();

                    move |farming_notification| match farming_notification {
                        FarmingNotification::Auditing(auditing_details) => {
                            farmer_metrics.observe_auditing_time(
                                &single_disk_farm_id,
                                &auditing_details.time,
                            );
                        }
                        FarmingNotification::Proving(proving_details) => {
                            farmer_metrics.observe_proving_time(
                                &single_disk_farm_id,
                                &proving_details.time,
                                proving_details.result,
                            );
                        }
                        FarmingNotification::NonFatalError(error) => {
                            farmer_metrics.note_farming_error(&single_disk_farm_id, error);
                        }
                    }
                }))
                .detach();

            single_disk_farm.run()
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskFarm`
    // event handlers
    drop(plotted_pieces);

    let farm_fut = run_future_in_dedicated_thread(
        move || async move {
            while let Some(result) = single_disk_farms_stream.next().await {
                let id = result?;

                info!(%id, "Farm exited successfully");
            }
            anyhow::Ok(())
        },
        "farmer-farm".to_string(),
    )?;

    let networking_fut = run_future_in_dedicated_thread(
        move || async move { node_runner.run().await },
        "farmer-networking".to_string(),
    )?;

    // This defines order in which things are dropped
    let networking_fut = networking_fut;
    let farm_fut = farm_fut;
    let farmer_cache_worker_fut = farmer_cache_worker_fut;

    let networking_fut = pin!(networking_fut);
    let farm_fut = pin!(farm_fut);
    let farmer_cache_worker_fut = pin!(farmer_cache_worker_fut);

    futures::select!(
        // Signal future
        _ = signal.fuse() => {},

        // Networking future
        _ = networking_fut.fuse() => {
            info!("Node runner exited.")
        },

        // Farm future
        result = farm_fut.fuse() => {
            result??;
        },

        // Piece cache worker future
        _ = farmer_cache_worker_fut.fuse() => {
            info!("Farmer cache worker exited.")
        },
    );

    anyhow::Ok(())
}

fn derive_libp2p_keypair(schnorrkel_sk: &schnorrkel::SecretKey) -> Keypair {
    let mut secret_bytes = Zeroizing::new(schnorrkel_sk.to_ed25519_bytes());

    let keypair = ed25519::Keypair::from(
        ed25519::SecretKey::try_from_bytes(&mut secret_bytes.as_mut()[..32])
            .expect("Secret key is exactly 32 bytes in size; qed"),
    );

    Keypair::from(keypair)
}
