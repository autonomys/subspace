use crate::commands::shared::metrics::{FarmerMetrics, SectorState};
use crate::commands::shared::network::{configure_network, NetworkArgs};
use crate::commands::shared::{derive_libp2p_keypair, DiskFarm, PlottingThreadPriority};
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use backoff::ExponentialBackoff;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PublicKey, Record};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::farm::{
    Farm, FarmingNotification, SectorExpirationDetails, SectorPlottingDetails, SectorUpdate,
};
use subspace_farmer::farmer_cache::FarmerCache;
use subspace_farmer::node_client::node_rpc_client::NodeRpcClient;
use subspace_farmer::node_client::NodeClient;
use subspace_farmer::plotter::cpu::CpuPlotter;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::farmer_piece_getter::{DsnCacheRetryPolicy, FarmerPieceGetter};
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::plotted_pieces::PlottedPieces;
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    create_plotting_thread_pool_manager, parse_cpu_cores_sets,
    recommended_number_of_farming_threads, run_future_in_dedicated_thread,
    thread_pool_core_indices, AsyncJoinOnDrop,
};
use subspace_farmer::Identity;
use subspace_farmer_components::plotting::PlottedSector;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tokio::sync::{Barrier, Semaphore};
use tracing::{debug, error, info, info_span, warn, Instrument};

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
    /// `size` is max allocated size in human-readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure to not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime). Optionally, `record-chunks-mode` can be
    /// set to `ConcurrentChunks` or `WholeSector` in order to avoid internal benchmarking during
    /// startup.
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
    /// Sets some flags that are convenient during development, currently `--allow-private-ips`
    #[arg(long)]
    dev: bool,
    /// Run temporary farmer with specified plot size in human-readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory that will be deleted at the
    /// end of the process.
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
    /// Network parameters
    #[clap(flatten)]
    network_args: NetworkArgs,
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
    /// Defines how many records farmer will encode in a single sector concurrently, defaults to one
    /// record per 2 cores, but not more than 8 in total. Higher concurrency means higher memory
    /// usage and typically more efficient CPU utilization.
    #[arg(long)]
    record_encoding_concurrency: Option<NonZeroUsize>,
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
    /// farming is successful and computer can be used comfortably for other things.  Can be set to
    /// "min", "max" or "default".
    #[arg(long, default_value_t = PlottingThreadPriority::Min)]
    plotting_thread_priority: PlottingThreadPriority,
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
    let signal = shutdown_signal();

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
        sector_downloading_concurrency,
        sector_encoding_concurrency,
        record_encoding_concurrency,
        farming_thread_pool_size,
        plotting_thread_pool_size,
        plotting_cpu_cores,
        replotting_thread_pool_size,
        replotting_cpu_cores,
        plotting_thread_priority,
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

    let _tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = tempfile::Builder::new()
            .prefix("subspace-farmer-")
            .tempdir()?;

        disk_farms = vec![DiskFarm {
            directory: tmp_directory.as_ref().to_path_buf(),
            allocated_space: plot_size.as_u64(),
            read_sector_record_chunks_mode: None,
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

    let plotted_pieces = Arc::new(AsyncRwLock::new(PlottedPieces::default()));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

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

    let (farmer_cache, farmer_cache_worker) = FarmerCache::new(node_client.clone(), peer_id);

    // Metrics
    let mut prometheus_metrics_registry = Registry::default();
    let farmer_metrics = FarmerMetrics::new(&mut prometheus_metrics_registry);
    let should_start_prometheus_server = !prometheus_listen_on.is_empty();

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
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
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

    let plotting_thread_pool_core_indices;
    let replotting_thread_pool_core_indices;
    if let Some(plotting_cpu_cores) = plotting_cpu_cores {
        plotting_thread_pool_core_indices = parse_cpu_cores_sets(&plotting_cpu_cores)
            .map_err(|error| anyhow!("Failed to parse `--plotting-cpu-cores`: {error}"))?;
        replotting_thread_pool_core_indices = match replotting_cpu_cores {
            Some(replotting_cpu_cores) => parse_cpu_cores_sets(&replotting_cpu_cores)
                .map_err(|error| anyhow!("Failed to parse `--replotting-cpu-cores`: {error}"))?,
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
        plotting_thread_priority.into(),
    )?;
    let farming_thread_pool_size = farming_thread_pool_size
        .map(|farming_thread_pool_size| farming_thread_pool_size.get())
        .unwrap_or_else(recommended_number_of_farming_threads);
    let global_mutex = Arc::default();
    let plotter = Arc::new(CpuPlotter::<_, PosTable>::new(
        piece_getter,
        downloading_semaphore,
        plotting_thread_pool_manager,
        record_encoding_concurrency,
        Arc::clone(&global_mutex),
        kzg.clone(),
        erasure_coding.clone(),
    ));

    let (farms, plotting_delay_senders) = {
        let node_rpc_url = &node_rpc_url;
        let info_mutex = &AsyncMutex::new(());
        let faster_read_sector_record_chunks_mode_barrier =
            Arc::new(Barrier::new(disk_farms.len()));
        let faster_read_sector_record_chunks_mode_concurrency = Arc::new(Semaphore::new(1));
        let (plotting_delay_senders, plotting_delay_receivers) = (0..disk_farms.len())
            .map(|_| oneshot::channel())
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let mut farms = Vec::with_capacity(disk_farms.len());
        let mut farms_stream = disk_farms
            .into_iter()
            .zip(plotting_delay_receivers)
            .enumerate()
            .map(|(farm_index, (disk_farm, plotting_delay_receiver))| {
                let farmer_app_info = farmer_app_info.clone();
                let kzg = kzg.clone();
                let erasure_coding = erasure_coding.clone();
                let plotter = Arc::clone(&plotter);
                let global_mutex = Arc::clone(&global_mutex);
                let faster_read_sector_record_chunks_mode_barrier =
                    Arc::clone(&faster_read_sector_record_chunks_mode_barrier);
                let faster_read_sector_record_chunks_mode_concurrency =
                    Arc::clone(&faster_read_sector_record_chunks_mode_concurrency);

                async move {
                    debug!(url = %node_rpc_url, "Connecting to node RPC");
                    let node_client = match NodeRpcClient::new(node_rpc_url).await {
                        Ok(node_client) => node_client,
                        Err(error) => {
                            return (farm_index, Err(error.into()));
                        }
                    };

                    let farm_fut = SingleDiskFarm::new::<_, _, PosTable>(
                        SingleDiskFarmOptions {
                            directory: disk_farm.directory.clone(),
                            farmer_app_info,
                            allocated_space: disk_farm.allocated_space,
                            max_pieces_in_sector,
                            node_client,
                            reward_address,
                            kzg,
                            erasure_coding,
                            cache_percentage: cache_percentage.get(),
                            farming_thread_pool_size,
                            plotting_delay: Some(plotting_delay_receiver),
                            global_mutex,
                            disable_farm_locking,
                            read_sector_record_chunks_mode: disk_farm
                                .read_sector_record_chunks_mode,
                            faster_read_sector_record_chunks_mode_barrier,
                            faster_read_sector_record_chunks_mode_concurrency,
                            plotter,
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

                    (farm_index, Ok(Box::new(farm) as Box<dyn Farm>))
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
            farms.iter().map(|farm| farm.piece_cache()).collect(),
            if plot_cache {
                farms.iter().map(|farm| farm.plot_cache()).collect()
            } else {
                Vec::new()
            },
        )
        .await;
    drop(farmer_cache);

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    let mut total_and_plotted_sectors = Vec::with_capacity(farms.len());

    for (farm_index, farm) in farms.iter().enumerate() {
        let mut plotted_pieces = plotted_pieces.write().await;
        let farm_index = farm_index.try_into().map_err(|_error| {
            anyhow!(
                "More than 256 plots are not supported, consider running multiple farmer \
                    instances"
            )
        })?;

        plotted_pieces.add_farm(farm_index, farm.piece_reader());

        let total_sectors_count = farm.total_sectors_count();
        let mut plotted_sectors_count = 0;
        let plotted_sectors = farm.plotted_sectors();
        let mut plotted_sectors = plotted_sectors.get().await.map_err(|error| {
            anyhow!("Failed to get plotted sectors for farm {farm_index}: {error}")
        })?;

        while let Some(plotted_sector_result) = plotted_sectors.next().await {
            plotted_sectors_count += 1;
            plotted_pieces.add_sector(
                farm_index,
                &plotted_sector_result.map_err(|error| {
                    anyhow!(
                        "Failed reading plotted sector on startup for farm {farm_index}: {error}"
                    )
                })?,
            )
        }

        total_and_plotted_sectors.push((total_sectors_count, plotted_sectors_count));
    }

    info!("Finished collecting already plotted pieces successfully");

    let mut farms_stream = (0u8..)
        .zip(farms)
        .zip(total_and_plotted_sectors)
        .map(|((farm_index, farm), sector_counts)| {
            let plotted_pieces = Arc::clone(&plotted_pieces);
            let span = info_span!("", %farm_index);

            // Collect newly plotted pieces
            let on_plotted_sector_callback =
                move |plotted_sector: &PlottedSector,
                      maybe_old_plotted_sector: &Option<PlottedSector>| {
                    let _span_guard = span.enter();

                    {
                        let mut plotted_pieces = plotted_pieces.write_blocking();

                        if let Some(old_plotted_sector) = &maybe_old_plotted_sector {
                            plotted_pieces.delete_sector(farm_index, old_plotted_sector);
                        }
                        plotted_pieces.add_sector(farm_index, plotted_sector);
                    }
                };

            let (total_sector_count, plotted_sectors_count) = sector_counts;
            farmer_metrics.update_sectors_total(
                farm.id(),
                total_sector_count - plotted_sectors_count,
                SectorState::NotPlotted,
            );
            farmer_metrics.update_sectors_total(
                farm.id(),
                plotted_sectors_count,
                SectorState::Plotted,
            );
            farm.on_sector_update(Arc::new({
                let farm_id = *farm.id();
                let farmer_metrics = farmer_metrics.clone();

                move |(_sector_index, sector_state)| match sector_state {
                    SectorUpdate::Plotting(SectorPlottingDetails::Starting { .. }) => {
                        farmer_metrics.sector_plotting.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Downloading) => {
                        farmer_metrics.sector_downloading.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Downloaded(time)) => {
                        farmer_metrics.observe_sector_downloading_time(&farm_id, time);
                        farmer_metrics.sector_downloaded.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Encoding) => {
                        farmer_metrics.sector_encoding.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Encoded(time)) => {
                        farmer_metrics.observe_sector_encoding_time(&farm_id, time);
                        farmer_metrics.sector_encoded.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Writing) => {
                        farmer_metrics.sector_writing.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Written(time)) => {
                        farmer_metrics.observe_sector_writing_time(&farm_id, time);
                        farmer_metrics.sector_written.inc();
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Finished {
                        plotted_sector,
                        old_plotted_sector,
                        time,
                    }) => {
                        on_plotted_sector_callback(plotted_sector, old_plotted_sector);
                        farmer_metrics.observe_sector_plotting_time(&farm_id, time);
                        farmer_metrics.sector_plotted.inc();
                        farmer_metrics.update_sector_state(&farm_id, SectorState::Plotted);
                    }
                    SectorUpdate::Plotting(SectorPlottingDetails::Error(_)) => {
                        farmer_metrics.sector_plotting_error.inc();
                    }
                    SectorUpdate::Expiration(SectorExpirationDetails::AboutToExpire) => {
                        farmer_metrics.update_sector_state(&farm_id, SectorState::AboutToExpire);
                    }
                    SectorUpdate::Expiration(SectorExpirationDetails::Expired) => {
                        farmer_metrics.update_sector_state(&farm_id, SectorState::Expired);
                    }
                    SectorUpdate::Expiration(SectorExpirationDetails::Determined { .. }) => {
                        // Not interested in here
                    }
                }
            }))
            .detach();

            farm.on_farming_notification(Arc::new({
                let farm_id = *farm.id();
                let farmer_metrics = farmer_metrics.clone();

                move |farming_notification| match farming_notification {
                    FarmingNotification::Auditing(auditing_details) => {
                        farmer_metrics.observe_auditing_time(&farm_id, &auditing_details.time);
                    }
                    FarmingNotification::Proving(proving_details) => {
                        farmer_metrics.observe_proving_time(
                            &farm_id,
                            &proving_details.time,
                            proving_details.result,
                        );
                    }
                    FarmingNotification::NonFatalError(error) => {
                        farmer_metrics.note_farming_error(&farm_id, error);
                    }
                }
            }))
            .detach();

            farm.run().map(move |result| (farm_index, result))
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskFarm`
    // event handlers
    drop(plotted_pieces);

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

    // This defines order in which things are dropped
    let networking_fut = networking_fut;
    let farm_fut = farm_fut;
    let farmer_cache_worker_fut = farmer_cache_worker_fut;

    let networking_fut = pin!(networking_fut);
    let farm_fut = pin!(farm_fut);
    let farmer_cache_worker_fut = pin!(farmer_cache_worker_fut);

    select! {
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
    }

    anyhow::Ok(())
}
