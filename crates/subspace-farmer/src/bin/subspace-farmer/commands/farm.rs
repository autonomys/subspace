use crate::commands::shared::network::{NetworkArgs, configure_network};
use crate::commands::shared::{DiskFarm, PlottingThreadPriority, derive_libp2p_keypair};
use anyhow::anyhow;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock, Semaphore};
use backoff::ExponentialBackoff;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt, select};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::pieces::Record;
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::farm::plotted_pieces::PlottedPieces;
use subspace_farmer::farm::{PlottedSectors, SectorPlottingDetails, SectorUpdate};
use subspace_farmer::farmer_cache::{FarmerCache, FarmerCaches};
use subspace_farmer::farmer_piece_getter::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::farmer_piece_getter::{DsnCacheRetryPolicy, FarmerPieceGetter};
use subspace_farmer::node_client::NodeClient;
use subspace_farmer::node_client::caching_proxy_node_client::CachingProxyNodeClient;
use subspace_farmer::node_client::rpc_node_client::RpcNodeClient;
use subspace_farmer::plotter::Plotter;
use subspace_farmer::plotter::cpu::CpuPlotter;
#[cfg(feature = "_gpu")]
use subspace_farmer::plotter::gpu::GpuPlotter;
#[cfg(feature = "cuda")]
use subspace_farmer::plotter::gpu::cuda::CudaRecordsEncoder;
#[cfg(feature = "rocm")]
use subspace_farmer::plotter::gpu::rocm::RocmRecordsEncoder;
use subspace_farmer::plotter::pool::PoolPlotter;
use subspace_farmer::single_disk_farm::identity::Identity;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    create_plotting_thread_pool_manager, parse_cpu_cores_sets,
    recommended_number_of_farming_threads, thread_pool_core_indices,
};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_kzg::Kzg;
use subspace_metrics::{RegistryAdapter, start_prometheus_metrics_server};
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_process::{AsyncJoinOnDrop, run_future_in_dedicated_thread, shutdown_signal};
use subspace_proof_of_space::Table;
use tracing::{Instrument, error, info, info_span, warn};

/// Get piece retry attempts number.
const PIECE_GETTER_MAX_RETRIES: u16 = 7;
/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);
/// NOTE: for large gaps between the plotted part and the end of the file plot cache will result in
/// very long period of writing zeroes on Windows, see https://stackoverflow.com/q/78058306/3806795
const MAX_SPACE_PLEDGED_FOR_PLOT_CACHE_ON_WINDOWS: u64 = 7 * 1024 * 1024 * 1024 * 1024;
const FARM_ERROR_PRINT_INTERVAL: Duration = Duration::from_secs(30);
const PLOTTING_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Multiplier on top of outgoing connections number for piece downloading purposes
const PIECE_PROVIDER_MULTIPLIER: usize = 10;

type FarmIndex = u8;

#[derive(Debug, Parser)]
struct CpuPlottingOptions {
    /// How many sectors a farmer will download concurrently. Limits memory usage of
    /// the plotting process. Defaults to `--cpu-sector-encoding-concurrency` + 1 to download future
    /// sector ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    cpu_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// How many sectors a farmer will encode concurrently. Defaults to 1 on UMA system and
    /// number of NUMA nodes on NUMA system or L3 cache groups on large CPUs. It is further
    /// restricted by
    /// `--cpu-sector-downloading-concurrency` and setting this option higher than
    /// `--cpu-sector-downloading-concurrency` will have no effect.
    ///
    /// CPU plotting is disabled by default if GPU plotting is detected.
    ///
    /// Increasing this value will cause higher memory usage. Set to 0 to disable CPU plotting.
    #[arg(long)]
    cpu_sector_encoding_concurrency: Option<usize>,
    /// How many records a farmer will encode in a single sector concurrently. Defaults to one
    /// record per 2 cores, but not more than 8 in total. Higher concurrency means higher memory
    /// usage and typically more efficient CPU utilization.
    #[arg(long)]
    cpu_record_encoding_concurrency: Option<NonZeroUsize>,
    /// Size of one thread pool used for plotting. Defaults to the number of logical CPUs available
    /// on UMA system and number of logical CPUs available in NUMA node on NUMA system or L3 cache
    /// groups on large CPUs.
    ///
    /// Number of thread pools is defined by `--cpu-sector-encoding-concurrency` option, different
    /// thread pools might have different number of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    cpu_plotting_thread_pool_size: Option<NonZeroUsize>,
    /// Set the exact CPU cores to be used for plotting bypassing any custom farmer logic.
    /// Replaces both `--cpu-sector-encoding-concurrency` and
    /// `--cpu-plotting-thread-pool-size` options. Requires `--cpu-replotting-cores` to
    /// be specified with the same number of CPU cores groups (or not specified at all, in which
    /// case it'll use the same thread pool as plotting).
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["cpu_sector_encoding_concurrency", "cpu_plotting_thread_pool_size"])]
    cpu_plotting_cores: Option<String>,
    /// Size of one thread pool used for replotting, typically smaller pool than for plotting
    /// to not affect farming as much. Defaults to half the number of logical CPUs on UMA systems,
    /// half the number of logical CPUs in the local NUMA node on NUMA systems, or half the L3
    /// cache group on large CPUs.
    ///
    /// Number of thread pools is defined by `--cpu-sector-encoding-concurrency` option, different
    /// thread pools might have different number of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    cpu_replotting_thread_pool_size: Option<NonZeroUsize>,
    /// Set the exact CPU cores to be used for replotting, bypassing any custom farmer logic.
    /// Replaces `--cpu-replotting-thread-pool-size` option if specified.
    /// Requires `--cpu-plotting-cores` to be specified with the same number of CPU cores groups.
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["cpu_sector_encoding_concurrency", "cpu_replotting_thread_pool_size"])]
    cpu_replotting_cores: Option<String>,
    /// Plotting thread priority, by default de-prioritizes plotting threads in order to make sure
    /// farming is successful and computer can be used comfortably for other things.  Can be set to
    /// "min", "max" or "default".
    #[arg(long, default_value_t = PlottingThreadPriority::Min)]
    cpu_plotting_thread_priority: PlottingThreadPriority,
}

#[cfg(feature = "cuda")]
#[derive(Debug, Parser)]
struct CudaPlottingOptions {
    /// How many sectors farmer will download concurrently during plotting with CUDA GPUs.
    /// Limits memory usage of the plotting process. Defaults to the number of CUDA GPUs * 3,
    /// to download future sectors ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    cuda_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Set the exact GPUs to be used for plotting instead of using all GPUs (default behavior).
    ///
    /// GPUs are coma-separated: `--cuda-gpus 0,1,3`. Use an empty string to disable CUDA
    /// GPUs.
    #[arg(long)]
    cuda_gpus: Option<String>,
}

#[cfg(feature = "rocm")]
#[derive(Debug, Parser)]
struct RocmPlottingOptions {
    /// How many sectors farmer will download concurrently during plotting with ROCm GPUs.
    /// Limits memory usage of the plotting process. Defaults to the number of ROCm GPUs * 3,
    /// to download future sectors ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    rocm_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Set the exact GPUs to be used for plotting instead of using all GPUs (default behavior).
    ///
    /// GPUs are coma-separated: `--rocm-gpus 0,1,3`. Use an empty string to disable ROCm
    /// GPUs.
    #[arg(long)]
    rocm_gpus: Option<String>,
}

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(crate) struct FarmingArgs {
    /// One or more farms located at specified paths, each with its own allocated space.
    ///
    /// In case of multiple disks, it is recommended to specify them individually rather than using
    /// RAID 0, that way farmer will be able to better take advantage of concurrency of individual
    /// drives.
    ///
    /// The format for each farm is coma-separated list of strings like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human-readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure to not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime). Optionally, `record-chunks-mode` can be
    /// set to `ConcurrentChunks` (default) or `WholeSector`.
    disk_farms: Vec<DiskFarm>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: Option<PublicKey>,
    /// Percentage of allocated space dedicated for caching purposes, 99% max
    #[arg(long, default_value = "1", value_parser = cache_percentage_parser)]
    cache_percentage: NonZeroU8,
    /// Sets some flags that are convenient during development, currently `--allow-private-ips` and
    /// `--reward-address` (if not specified explicitly)
    #[arg(long)]
    dev: bool,
    /// Run a temporary farmer with a plot size in human-readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096). This will create a temporary directory that will be deleted at the
    /// end of the process.
    #[arg(long, conflicts_with = "disk_farms")]
    tmp: Option<ByteSize>,
    /// Maximum number of pieces in a sector (can override protocol value to something lower).
    ///
    /// This will make plotting of individual sectors faster, decrease load on CPU proving, but also
    /// proportionally increase amount of disk reads during audits since every sector needs to be
    /// audited and there will be more of them.
    ///
    /// This is primarily for development and not recommended for regular users.
    #[arg(long)]
    max_pieces_in_sector: Option<u16>,
    /// Network parameters
    #[clap(flatten)]
    network_args: NetworkArgs,
    /// Do not print info about configured farms on startup
    #[arg(long)]
    no_info: bool,
    /// Endpoints for the prometheus metrics server. It doesn't start without at least
    /// one specified endpoint. Format: 127.0.0.1:8080
    #[arg(long)]
    prometheus_listen_on: Vec<SocketAddr>,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving). Defaults to the number of logical CPUs
    /// on UMA systems, or the number of logical CPUs in first NUMA node on NUMA systems, but
    /// limited to 32 threads.
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
    /// Plotting options only used by CPU plotter
    #[clap(flatten)]
    cpu_plotting_options: CpuPlottingOptions,
    /// Plotting options only used by CUDA GPU plotter
    #[cfg(feature = "cuda")]
    #[clap(flatten)]
    cuda_plotting_options: CudaPlottingOptions,
    /// Plotting options only used by ROCm GPU plotter
    #[cfg(feature = "rocm")]
    #[clap(flatten)]
    rocm_plotting_options: RocmPlottingOptions,
    /// How many sectors a will be plotted concurrently per farm.
    ///
    /// Defaults to 2, but can be decreased if there is a large number of farms available to
    /// decrease peak memory usage, especially with slow disks, or slightly increased to utilize all
    /// compute available in case of a single farm.
    ///
    /// Increasing this value is not recommended and can result in excessive RAM usage due to more
    /// sectors being stuck in-flight if writes to farm disk are too slow.
    #[arg(long, default_value = "2")]
    max_plotting_sectors_per_farm: NonZeroUsize,
    /// Enable plot cache.
    ///
    /// Plot cache uses unplotted space as additional cache improving plotting speeds, especially
    /// for small farmers.
    ///
    /// On Windows enabled by default if total plotting space doesn't exceed 7TiB, for other OSs
    /// enabled by default regardless of farm size.
    #[arg(long)]
    plot_cache: Option<bool>,
    /// Disable farm locking, for example if file system doesn't support it
    #[arg(long)]
    disable_farm_locking: bool,
    /// Whether to create missing farms during start.
    ///
    /// If set to `false` farmer will exit with error if one of the farms doesn't already exist.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    create: bool,
    /// Exit on farm error.
    ///
    /// By default, farmer will continue running if there are still other working farms.
    #[arg(long)]
    exit_on_farm_error: bool,
}

fn cache_percentage_parser(s: &str) -> anyhow::Result<NonZeroU8> {
    let cache_percentage = NonZeroU8::from_str(s)?;

    if cache_percentage.get() > 99 {
        return Err(anyhow!("Cache percentage can't exceed 99"));
    }

    Ok(cache_percentage)
}

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm<PosTable>(farming_args: FarmingArgs) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let signal = shutdown_signal("farmer");

    let FarmingArgs {
        node_rpc_url,
        reward_address,
        max_pieces_in_sector,
        mut network_args,
        cache_percentage,
        no_info,
        dev,
        tmp,
        mut disk_farms,
        prometheus_listen_on,
        farming_thread_pool_size,
        cpu_plotting_options,
        #[cfg(feature = "cuda")]
        cuda_plotting_options,
        #[cfg(feature = "rocm")]
        rocm_plotting_options,
        max_plotting_sectors_per_farm,
        plot_cache,
        disable_farm_locking,
        create,
        exit_on_farm_error,
    } = farming_args;

    let plot_cache = plot_cache.unwrap_or_else(|| {
        !cfg!(windows)
            || disk_farms
                .iter()
                .map(|farm| farm.allocated_space)
                .sum::<u64>()
                <= MAX_SPACE_PLEDGED_FOR_PLOT_CACHE_ON_WINDOWS
    });

    // Override flags with `--dev`
    network_args.allow_private_ips = network_args.allow_private_ips || dev;
    let reward_address = match reward_address {
        Some(reward_address) => reward_address,
        None => {
            if dev {
                // `//Alice`
                PublicKey::from([
                    0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04,
                    0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56,
                    0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
                ])
            } else {
                return Err(anyhow!("`--reward-address` is required"));
            }
        }
    };

    let _tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = tempfile::Builder::new()
            .prefix("subspace-farmer-")
            .tempdir()
            .map_err(|error| anyhow!("Failed to create temporary directory: {error}"))?;

        disk_farms = vec![DiskFarm {
            directory: tmp_directory.as_ref().to_path_buf(),
            allocated_space: plot_size.as_u64(),
            read_sector_record_chunks_mode: Some(ReadSectorRecordChunksMode::ConcurrentChunks),
        }];

        Some(tmp_directory)
    } else {
        if disk_farms.is_empty() {
            return Err(anyhow!("There must be at least one disk farm provided"));
        }

        for farm in &disk_farms {
            if !farm.directory.exists()
                && let Err(error) = fs::create_dir(&farm.directory)
            {
                return Err(anyhow!(
                    "Directory {} doesn't exist and can't be created: {}",
                    farm.directory.display(),
                    error
                ));
            }
        }
        None
    };

    let plotted_pieces = Arc::new(AsyncRwLock::new(PlottedPieces::default()));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = RpcNodeClient::new(&node_rpc_url)
        .await
        .map_err(|error| anyhow!("Failed to connect to node RPC: {error}"))?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow!("Failed to get farmer app info: {error}"))?;

    let first_farm_directory = &disk_farms
        .first()
        .expect("Disk farm collection is not be empty as checked above; qed")
        .directory;

    let identity = if create {
        Identity::open_or_create(first_farm_directory)
            .map_err(|error| anyhow!("Failed to open or create identity: {error}"))?
    } else {
        Identity::open(first_farm_directory)
            .map_err(|error| anyhow!("Failed to open identity of the first farm: {error}"))?
            .ok_or_else(|| {
                anyhow!(
                    "Failed to open identity of the first farm: Farm doesn't exist and creation \
                    was explicitly disabled"
                )
            })?
    };
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();

    let mut registry = Registry::with_prefix("subspace_farmer");
    let should_start_prometheus_server = !prometheus_listen_on.is_empty();

    let (farmer_cache, farmer_cache_worker) =
        FarmerCache::new(node_client.clone(), peer_id, Some(&mut registry));
    let farmer_caches = FarmerCaches::from(farmer_cache.clone());

    let node_client = CachingProxyNodeClient::new(node_client)
        .await
        .map_err(|error| anyhow!("Failed to create caching proxy node client: {error}"))?;

    let out_connections = network_args.out_connections;
    let (node, mut node_runner) = {
        if network_args.bootstrap_nodes.is_empty() {
            network_args
                .bootstrap_nodes
                .clone_from(&farmer_app_info.dsn_bootstrap_nodes);
        }

        configure_network(
            hex::encode(farmer_app_info.genesis_hash),
            first_farm_directory,
            keypair,
            network_args,
            Arc::downgrade(&plotted_pieces),
            node_client.clone(),
            farmer_caches.clone(),
            should_start_prometheus_server.then_some(&mut registry),
        )
        .map_err(|error| anyhow!("Failed to configure networking: {error}"))?
    };

    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
    let piece_provider = PieceProvider::new(
        node.clone(),
        SegmentCommitmentPieceValidator::new(node.clone(), node_client.clone(), kzg.clone()),
        Arc::new(Semaphore::new(
            out_connections as usize * PIECE_PROVIDER_MULTIPLIER,
        )),
    );

    let piece_getter = FarmerPieceGetter::new(
        piece_provider,
        farmer_caches,
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
            // Piece cache worker uses piece getter, while piece getter uses piece cache, which
            // piece cache worker depends on. Use weak reference to break the cycle and allow worker
            // to exit when last piece cache instance is dropped.
            let future = farmer_cache_worker.run(piece_getter.downgrade());

            move || future
        },
        "farmer-cache-worker".to_string(),
    )?;

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

    let farming_thread_pool_size = farming_thread_pool_size
        .map(|farming_thread_pool_size| farming_thread_pool_size.get())
        .unwrap_or_else(recommended_number_of_farming_threads);
    let global_mutex = Arc::default();

    let mut plotters = Vec::<Box<dyn Plotter + Send + Sync>>::new();

    #[cfg(feature = "cuda")]
    {
        let maybe_cuda_plotter = init_cuda_plotter(
            cuda_plotting_options,
            piece_getter.clone(),
            Arc::clone(&global_mutex),
            kzg.clone(),
            erasure_coding.clone(),
            &mut registry,
        )?;

        if let Some(cuda_plotter) = maybe_cuda_plotter {
            plotters.push(Box::new(cuda_plotter));
        }
    }
    #[cfg(feature = "rocm")]
    {
        let maybe_rocm_plotter = init_rocm_plotter(
            rocm_plotting_options,
            piece_getter.clone(),
            Arc::clone(&global_mutex),
            kzg.clone(),
            erasure_coding.clone(),
            &mut registry,
        )?;

        if let Some(rocm_plotter) = maybe_rocm_plotter {
            plotters.push(Box::new(rocm_plotter));
        }
    }
    {
        let cpu_sector_encoding_concurrency = cpu_plotting_options.cpu_sector_encoding_concurrency;
        let maybe_cpu_plotter = init_cpu_plotter::<_, PosTable>(
            cpu_plotting_options,
            piece_getter.clone(),
            Arc::clone(&global_mutex),
            kzg.clone(),
            erasure_coding.clone(),
            &mut registry,
        )?;

        if let Some(cpu_plotter) = maybe_cpu_plotter {
            if !plotters.is_empty() && cpu_sector_encoding_concurrency.is_none() {
                info!("CPU plotting was disabled due to detected faster plotting with GPU");
            } else {
                plotters.push(Box::new(cpu_plotter));
            }
        }
    }
    let plotter = Arc::new(PoolPlotter::new(plotters, PLOTTING_RETRY_INTERVAL));

    let (farms, plotting_delay_senders) = {
        let info_mutex = &AsyncMutex::new(());
        let (plotting_delay_senders, plotting_delay_receivers) = (0..disk_farms.len())
            .map(|_| oneshot::channel())
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let registry = &Mutex::new(&mut registry);

        let mut farms = Vec::with_capacity(disk_farms.len());
        let mut farms_stream = disk_farms
            .into_iter()
            .zip(plotting_delay_receivers)
            .enumerate()
            .map(|(farm_index, (disk_farm, plotting_delay_receiver))| {
                let node_client = node_client.clone();
                let farmer_app_info = farmer_app_info.clone();
                let kzg = kzg.clone();
                let erasure_coding = erasure_coding.clone();
                let plotter = Arc::clone(&plotter);
                let global_mutex = Arc::clone(&global_mutex);

                async move {
                    let farm_fut = SingleDiskFarm::new::<_, PosTable>(
                        SingleDiskFarmOptions {
                            directory: disk_farm.directory.clone(),
                            farmer_app_info,
                            allocated_space: disk_farm.allocated_space,
                            max_pieces_in_sector,
                            node_client,
                            reward_address,
                            plotter,
                            kzg,
                            erasure_coding,
                            cache_percentage: cache_percentage.get(),
                            farming_thread_pool_size,
                            plotting_delay: Some(plotting_delay_receiver),
                            global_mutex,
                            max_plotting_sectors_per_farm,
                            disable_farm_locking,
                            read_sector_record_chunks_mode: disk_farm
                                .read_sector_record_chunks_mode
                                .unwrap_or(ReadSectorRecordChunksMode::ConcurrentChunks),
                            registry: Some(registry),
                            create,
                        },
                        farm_index,
                    );

                    let farm = match farm_fut.await {
                        Ok(farm) => farm,
                        Err(SingleDiskFarmError::InsufficientAllocatedSpace {
                            min_space,
                            allocated_space,
                        }) => {
                            return (
                                farm_index,
                                Err(anyhow!(
                                    "Allocated space {} ({}) is not enough, minimum is ~{} (~{}, \
                                    {} bytes to be exact)",
                                    bytesize::to_string(allocated_space, true),
                                    bytesize::to_string(allocated_space, false),
                                    bytesize::to_string(min_space, true),
                                    bytesize::to_string(min_space, false),
                                    min_space
                                )),
                            );
                        }
                        Err(error) => {
                            return (farm_index, Err(error.into()));
                        }
                    };

                    if !no_info {
                        let _info_guard = info_mutex.lock().await;

                        let info = farm.info();
                        info!("Farm {farm_index}:");
                        info!("  ID: {}", info.id());
                        info!("  Genesis hash: 0x{}", hex::encode(info.genesis_hash()));
                        info!("  Public key: 0x{}", hex::encode(info.public_key()));
                        info!(
                            "  Allocated space: {} ({})",
                            bytesize::to_string(info.allocated_space(), true),
                            bytesize::to_string(info.allocated_space(), false)
                        );
                        info!("  Directory: {}", disk_farm.directory.display());
                    }

                    (farm_index, Ok(farm))
                }
                .instrument(info_span!("", %farm_index))
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((farm_index, farm)) = farms_stream.next().await {
            if let Err(error) = &farm {
                let span = info_span!("", %farm_index);
                let _span_guard = span.enter();

                error!(%error, "Farm creation failed");
            }
            farms.push((farm_index, farm?));
        }

        // Restore order after unordered initialization
        farms.sort_unstable_by_key(|(farm_index, _farm)| *farm_index);

        let farms = farms
            .into_iter()
            .map(|(_farm_index, farm)| farm)
            .collect::<Vec<_>>();

        (farms, plotting_delay_senders)
    };

    {
        let handler_id = Arc::new(Mutex::new(None));
        // Wait for piece cache to read already cached contents before starting plotting to improve
        // cache hit ratio
        handler_id
            .lock()
            .replace(farmer_cache.on_sync_progress(Arc::new({
                let handler_id = Arc::clone(&handler_id);
                let plotting_delay_senders = Mutex::new(plotting_delay_senders);

                move |_progress| {
                    for plotting_delay_sender in plotting_delay_senders.lock().drain(..) {
                        // Doesn't matter if receiver is gone
                        let _ = plotting_delay_sender.send(());
                    }

                    // Unsubscribe from this event
                    handler_id.lock().take();
                }
            })));
    }
    farmer_cache
        .replace_backing_caches(
            farms
                .iter()
                .map(|farm| Arc::new(farm.piece_cache()) as Arc<_>)
                .collect(),
            if plot_cache {
                farms
                    .iter()
                    .map(|farm| Arc::new(farm.plot_cache()) as Arc<_>)
                    .collect()
            } else {
                Vec::new()
            },
        )
        .await;
    drop(farmer_cache);

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    for (farm_index, farm) in farms.iter().enumerate() {
        let mut plotted_pieces = plotted_pieces.write().await;
        let farm_index = farm_index.try_into().map_err(|_error| {
            anyhow!(
                "More than 256 plots are not supported, consider running multiple farmer \
                instances"
            )
        })?;

        plotted_pieces.add_farm(farm_index, Arc::new(farm.piece_reader()));

        let plotted_sectors = farm.plotted_sectors();
        let mut plotted_sectors = plotted_sectors.get().await.map_err(|error| {
            anyhow!("Failed to get plotted sectors for farm {farm_index}: {error}")
        })?;

        while let Some(plotted_sector_result) = plotted_sectors.next().await {
            plotted_pieces.add_sector(
                farm_index,
                &plotted_sector_result.map_err(|error| {
                    anyhow!(
                        "Failed reading plotted sector on startup for farm {farm_index}: {error}"
                    )
                })?,
            )
        }
    }

    info!("Finished collecting already plotted pieces successfully");

    let mut farms_stream = (FarmIndex::MIN..)
        .zip(farms)
        .map(|(farm_index, farm)| {
            let plotted_pieces = Arc::clone(&plotted_pieces);
            let span = info_span!("", %farm_index);

            farm.on_sector_update(Arc::new(move |(_sector_index, sector_state)| {
                // Collect newly plotted pieces
                if let SectorUpdate::Plotting(SectorPlottingDetails::Finished {
                    plotted_sector,
                    old_plotted_sector,
                    time: _,
                }) = sector_state
                {
                    let _span_guard = span.enter();

                    let mut plotted_pieces = plotted_pieces.write_blocking();

                    if let Some(old_plotted_sector) = &old_plotted_sector {
                        plotted_pieces.delete_sector(farm_index, old_plotted_sector);
                    }
                    plotted_pieces.add_sector(farm_index, plotted_sector);
                }
            }))
            .detach();

            farm.run().map(move |result| (farm_index, result))
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskFarm`
    // event handlers
    drop(plotted_pieces);

    let _prometheus_worker = if should_start_prometheus_server {
        let prometheus_task = start_prometheus_metrics_server(
            prometheus_listen_on,
            RegistryAdapter::PrometheusClient(registry),
        )?;

        let join_handle = tokio::spawn(prometheus_task);
        Some(AsyncJoinOnDrop::new(join_handle, true))
    } else {
        None
    };

    let mut farm_errors = Vec::new();

    let farm_fut = run_future_in_dedicated_thread(
        move || async move {
            while let Some((farm_index, result)) = farms_stream.next().await {
                match result {
                    Ok(()) => {
                        info!(%farm_index, "Farm exited successfully");
                    }
                    Err(error) => {
                        error!(%farm_index, %error, "Farm exited with error");

                        if farms_stream.is_empty() || exit_on_farm_error {
                            return Err(error);
                        } else {
                            farm_errors.push(AsyncJoinOnDrop::new(
                                tokio::spawn(async move {
                                    loop {
                                        tokio::time::sleep(FARM_ERROR_PRINT_INTERVAL).await;

                                        error!(
                                            %farm_index,
                                            %error,
                                            "Farm errored and stopped"
                                        );
                                    }
                                }),
                                true,
                            ))
                        }
                    }
                }
            }
            anyhow::Ok(())
        },
        "farmer-farm".to_string(),
    )?;

    let networking_fut = run_future_in_dedicated_thread(
        move || async move { node_runner.run().await },
        "farmer-networking".to_string(),
    )?;

    // If a spawned future is running for a long time, it can block receiving exit signals.
    // Rather than hunting down every possible blocking future, we give the exit signal itself a
    // dedicated thread to run on.
    let exit_signal_select_fut = run_future_in_dedicated_thread(
        move || async move {
            // This defines order in which things are dropped
            let networking_fut = networking_fut;
            let farm_fut = farm_fut;
            let farmer_cache_worker_fut = farmer_cache_worker_fut;

            let networking_fut = pin!(networking_fut);
            let farm_fut = pin!(farm_fut);
            let farmer_cache_worker_fut = pin!(farmer_cache_worker_fut);

            select! {
                // Signal future
                _ = signal.fuse() => {}

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
            }

            anyhow::Ok(())
        },
        "farmer-exit-signal-select".to_string(),
    )?;

    exit_signal_select_fut.await??;

    anyhow::Ok(())
}

#[allow(clippy::type_complexity)]
fn init_cpu_plotter<PG, PosTable>(
    cpu_plotting_options: CpuPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<CpuPlotter<PG, PosTable>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
    PosTable: Table,
{
    let CpuPlottingOptions {
        cpu_sector_downloading_concurrency,
        cpu_sector_encoding_concurrency,
        cpu_record_encoding_concurrency,
        cpu_plotting_thread_pool_size,
        cpu_plotting_cores,
        cpu_replotting_thread_pool_size,
        cpu_replotting_cores,
        cpu_plotting_thread_priority,
    } = cpu_plotting_options;

    let cpu_sector_encoding_concurrency =
        if let Some(cpu_sector_encoding_concurrency) = cpu_sector_encoding_concurrency {
            match NonZeroUsize::new(cpu_sector_encoding_concurrency) {
                Some(cpu_sector_encoding_concurrency) => Some(cpu_sector_encoding_concurrency),
                None => {
                    info!("CPU plotting was explicitly disabled");
                    return Ok(None);
                }
            }
        } else {
            None
        };

    let plotting_thread_pool_core_indices;
    let replotting_thread_pool_core_indices;
    if let Some(cpu_plotting_cores) = cpu_plotting_cores {
        plotting_thread_pool_core_indices = parse_cpu_cores_sets(&cpu_plotting_cores)
            .map_err(|error| anyhow!("Failed to parse `--cpu-plotting-cores`: {error}"))?;
        replotting_thread_pool_core_indices = match cpu_replotting_cores {
            Some(cpu_replotting_cores) => parse_cpu_cores_sets(&cpu_replotting_cores)
                .map_err(|error| anyhow!("Failed to parse `--cpu-replotting-cores`: {error}"))?,
            None => plotting_thread_pool_core_indices.clone(),
        };
        if plotting_thread_pool_core_indices.len() != replotting_thread_pool_core_indices.len() {
            return Err(anyhow!(
                "Number of plotting thread pools ({}) is not the same as for replotting ({})",
                plotting_thread_pool_core_indices.len(),
                replotting_thread_pool_core_indices.len()
            ));
        }
    } else {
        plotting_thread_pool_core_indices = thread_pool_core_indices(
            cpu_plotting_thread_pool_size,
            cpu_sector_encoding_concurrency,
        );
        replotting_thread_pool_core_indices = {
            let mut replotting_thread_pool_core_indices = thread_pool_core_indices(
                cpu_replotting_thread_pool_size,
                cpu_sector_encoding_concurrency,
            );
            if cpu_replotting_thread_pool_size.is_none() {
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
        }
    }

    let cpu_downloading_semaphore = Arc::new(Semaphore::new(
        cpu_sector_downloading_concurrency
            .map(|cpu_sector_downloading_concurrency| cpu_sector_downloading_concurrency.get())
            .unwrap_or(plotting_thread_pool_core_indices.len() * 3),
    ));

    let cpu_record_encoding_concurrency = cpu_record_encoding_concurrency.unwrap_or_else(|| {
        let cpu_cores = plotting_thread_pool_core_indices
            .first()
            .expect("Guaranteed to have some CPU cores; qed");

        NonZeroUsize::new((cpu_cores.cpu_cores().len() / 2).clamp(1, 8)).expect("Not zero; qed")
    });

    info!(
        ?plotting_thread_pool_core_indices,
        ?replotting_thread_pool_core_indices,
        "Preparing plotting thread pools"
    );

    let plotting_thread_pool_manager = create_plotting_thread_pool_manager(
        plotting_thread_pool_core_indices
            .into_iter()
            .zip(replotting_thread_pool_core_indices),
        cpu_plotting_thread_priority.into(),
    )
    .map_err(|error| anyhow!("Failed to create thread pool manager: {error}"))?;

    let cpu_plotter = CpuPlotter::<_, PosTable>::new(
        piece_getter,
        cpu_downloading_semaphore,
        plotting_thread_pool_manager,
        cpu_record_encoding_concurrency,
        global_mutex,
        kzg,
        erasure_coding,
        Some(registry),
    );

    Ok(Some(cpu_plotter))
}

#[cfg(feature = "cuda")]
fn init_cuda_plotter<PG>(
    cuda_plotting_options: CudaPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<GpuPlotter<PG, CudaRecordsEncoder>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
{
    use std::collections::BTreeSet;
    use subspace_proof_of_space_gpu::cuda::cuda_devices;
    use tracing::debug;

    let CudaPlottingOptions {
        cuda_sector_downloading_concurrency,
        cuda_gpus,
    } = cuda_plotting_options;

    let mut cuda_devices = cuda_devices();
    let mut used_cuda_devices = (0..cuda_devices.len()).collect::<Vec<_>>();

    if let Some(cuda_gpus) = cuda_gpus {
        if cuda_gpus.is_empty() {
            info!("CUDA GPU plotting was explicitly disabled");
            return Ok(None);
        }

        let mut cuda_gpus_to_use = cuda_gpus
            .split(',')
            .map(|gpu_index| gpu_index.parse())
            .collect::<Result<BTreeSet<usize>, _>>()?;

        (used_cuda_devices, cuda_devices) = cuda_devices
            .into_iter()
            .enumerate()
            .filter(|(index, _cuda_device)| cuda_gpus_to_use.remove(index))
            .unzip();

        if !cuda_gpus_to_use.is_empty() {
            warn!(
                ?cuda_gpus_to_use,
                "Some CUDA GPUs were not found on the system"
            );
        }
    }

    if cuda_devices.is_empty() {
        debug!("No CUDA GPU devices found");
        return Ok(None);
    }

    info!(?used_cuda_devices, "Using CUDA GPUs");

    let cuda_downloading_semaphore = Arc::new(Semaphore::new(
        cuda_sector_downloading_concurrency
            .map(|cuda_sector_downloading_concurrency| cuda_sector_downloading_concurrency.get())
            .unwrap_or(cuda_devices.len() * 3),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            cuda_downloading_semaphore,
            cuda_devices
                .into_iter()
                .map(|cuda_device| CudaRecordsEncoder::new(cuda_device, Arc::clone(&global_mutex)))
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    anyhow::anyhow!("Failed to create CUDA records encoder: {error}")
                })?,
            global_mutex,
            kzg,
            erasure_coding,
            Some(registry),
        )
        .map_err(|error| anyhow::anyhow!("Failed to initialize CUDA plotter: {error}"))?,
    ))
}

#[cfg(feature = "rocm")]
fn init_rocm_plotter<PG>(
    rocm_plotting_options: RocmPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<GpuPlotter<PG, RocmRecordsEncoder>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
{
    use std::collections::BTreeSet;
    use subspace_proof_of_space_gpu::rocm::rocm_devices;
    use tracing::debug;

    let RocmPlottingOptions {
        rocm_sector_downloading_concurrency,
        rocm_gpus,
    } = rocm_plotting_options;

    let mut rocm_devices = rocm_devices();
    let mut used_rocm_devices = (0..rocm_devices.len()).collect::<Vec<_>>();

    if let Some(rocm_gpus) = rocm_gpus {
        if rocm_gpus.is_empty() {
            info!("ROCm GPU plotting was explicitly disabled");
            return Ok(None);
        }

        let mut rocm_gpus_to_use = rocm_gpus
            .split(',')
            .map(|gpu_index| gpu_index.parse())
            .collect::<Result<BTreeSet<usize>, _>>()?;

        (used_rocm_devices, rocm_devices) = rocm_devices
            .into_iter()
            .enumerate()
            .filter(|(index, _rocm_device)| rocm_gpus_to_use.remove(index))
            .unzip();

        if !rocm_gpus_to_use.is_empty() {
            warn!(
                ?rocm_gpus_to_use,
                "Some ROCm GPUs were not found on the system"
            );
        }
    }

    if rocm_devices.is_empty() {
        debug!("No ROCm GPU devices found");
        return Ok(None);
    }

    info!(?used_rocm_devices, "Using ROCm GPUs");

    let rocm_downloading_semaphore = Arc::new(Semaphore::new(
        rocm_sector_downloading_concurrency
            .map(|rocm_sector_downloading_concurrency| rocm_sector_downloading_concurrency.get())
            .unwrap_or(rocm_devices.len() + 1),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            rocm_downloading_semaphore,
            rocm_devices
                .into_iter()
                .map(|rocm_device| RocmRecordsEncoder::new(rocm_device, Arc::clone(&global_mutex)))
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    anyhow::anyhow!("Failed to create ROCm records encoder: {error}")
                })?,
            global_mutex,
            kzg,
            erasure_coding,
            Some(registry),
        )
        .map_err(|error| anyhow::anyhow!("Failed to initialize ROCm plotter: {error}"))?,
    ))
}
