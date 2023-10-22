mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::commands::shared::print_disk_farm_info;
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PublicKey, Record, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    run_future_in_dedicated_thread, tokio_rayon_spawn_handler, AsyncJoinOnDrop,
};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tempfile::TempDir;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, info_span, warn};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

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
        metrics_endpoints,
        sector_downloading_concurrency,
        sector_encoding_concurrency,
        farm_during_initial_plotting,
        farming_thread_pool_size,
        plotting_thread_pool_size,
        replotting_thread_pool_size,
    } = farming_args;

    // Override the `--enable_private_ips` flag with `--dev`
    dsn.enable_private_ips = dsn.enable_private_ips || dev;

    let _tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = TempDir::new()?;

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

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let first_farm_directory = disk_farms
        .first()
        .expect("Disk farm collection is not be empty as checked above; qed")
        .directory
        .clone();
    // TODO: Update `Identity` to use more specific error type and remove this `.unwrap()`
    let identity = Identity::open_or_create(&first_farm_directory).unwrap();
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();

    let (piece_cache, piece_cache_worker) = PieceCache::new(node_client.clone(), peer_id);

    let metrics_endpoints_are_specified = !metrics_endpoints.is_empty();

    let (node, mut node_runner, metrics_registry) = {
        if dsn.bootstrap_nodes.is_empty() {
            dsn.bootstrap_nodes = farmer_app_info.dsn_bootstrap_nodes.clone();
        }

        configure_dsn(
            hex::encode(farmer_app_info.genesis_hash),
            first_farm_directory,
            keypair,
            dsn,
            Arc::downgrade(&readers_and_pieces),
            node_client.clone(),
            piece_cache.clone(),
            metrics_endpoints_are_specified,
        )?
    };

    let _prometheus_worker = if metrics_endpoints_are_specified {
        let prometheus_task = start_prometheus_metrics_server(
            metrics_endpoints,
            RegistryAdapter::Libp2p(metrics_registry),
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
    // TODO: Consider introducing and using global in-memory segment header cache (this comment is
    //  in multiple files)
    let segment_commitments_cache = Mutex::new(LruCache::new(RECORDS_ROOTS_CACHE_SIZE));
    let piece_provider = PieceProvider::new(
        node.clone(),
        Some(SegmentCommitmentPieceValidator::new(
            node.clone(),
            node_client.clone(),
            kzg.clone(),
            segment_commitments_cache,
        )),
    );

    let piece_getter = Arc::new(FarmerPieceGetter::new(
        node.clone(),
        piece_provider,
        piece_cache.clone(),
        node_client.clone(),
        Arc::clone(&readers_and_pieces),
    ));

    let _piece_cache_worker = run_future_in_dedicated_thread(
        Box::pin(piece_cache_worker.run(piece_getter.clone())),
        "cache-worker".to_string(),
    );

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

    let plotting_thread_pool = Arc::new(
        ThreadPoolBuilder::new()
            .thread_name(move |thread_index| format!("plotting#{thread_index}"))
            .num_threads(plotting_thread_pool_size)
            .spawn_handler(tokio_rayon_spawn_handler())
            .build()?,
    );
    let replotting_thread_pool = Arc::new(
        ThreadPoolBuilder::new()
            .thread_name(move |thread_index| format!("replotting#{thread_index}"))
            .num_threads(replotting_thread_pool_size)
            .spawn_handler(tokio_rayon_spawn_handler())
            .build()?,
    );

    let downloading_semaphore = Arc::new(Semaphore::new(sector_downloading_concurrency.get()));
    let encoding_semaphore = Arc::new(Semaphore::new(sector_encoding_concurrency.get()));

    let mut plotting_delay_senders = Vec::with_capacity(disk_farms.len());

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        debug!(url = %node_rpc_url, %disk_farm_index, "Connecting to node RPC");
        let node_client = NodeRpcClient::new(&node_rpc_url).await?;
        let (plotting_delay_sender, plotting_delay_receiver) = oneshot::channel();
        plotting_delay_senders.push(plotting_delay_sender);

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
                encoding_semaphore: Arc::clone(&encoding_semaphore),
                farm_during_initial_plotting,
                farming_thread_pool_size,
                plotting_thread_pool: Arc::clone(&plotting_thread_pool),
                replotting_thread_pool: Arc::clone(&replotting_thread_pool),
                plotting_delay: Some(plotting_delay_receiver),
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
            print_disk_farm_info(disk_farm.directory, disk_farm_index);
        }

        single_disk_farms.push(single_disk_farm);
    }

    let cache_acknowledgement_receiver = piece_cache
        .replace_backing_caches(
            single_disk_farms
                .iter()
                .map(|single_disk_farm| single_disk_farm.piece_cache())
                .collect(),
        )
        .await;
    drop(piece_cache);

    // Wait for cache initialization before starting plotting
    tokio::spawn(async move {
        if cache_acknowledgement_receiver.await.is_ok() {
            for plotting_delay_sender in plotting_delay_senders {
                // Doesn't matter if receiver is gone
                let _ = plotting_delay_sender.send(());
            }
        }
    });

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_farms
        .iter()
        .map(|single_disk_farm| single_disk_farm.piece_reader())
        .collect::<Vec<_>>();

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    {
        let mut future_readers_and_pieces = ReadersAndPieces::new(piece_readers);

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
                            future_readers_and_pieces.add_sector(disk_farm_index, &plotted_sector);
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

        readers_and_pieces.lock().replace(future_readers_and_pieces);
    }

    info!("Finished collecting already plotted pieces successfully");

    let mut single_disk_farms_stream = single_disk_farms
        .into_iter()
        .enumerate()
        .map(|(disk_farm_index, single_disk_farm)| {
            let disk_farm_index = disk_farm_index.try_into().expect(
                "More than 256 plots are not supported, this is checked above already; qed",
            );
            let readers_and_pieces = Arc::clone(&readers_and_pieces);
            let span = info_span!("farm", %disk_farm_index);

            // Collect newly plotted pieces
            let on_plotted_sector_callback =
                move |(plotted_sector, maybe_old_plotted_sector): &(
                    PlottedSector,
                    Option<PlottedSector>,
                )| {
                    let _span_guard = span.enter();

                    {
                        let mut readers_and_pieces = readers_and_pieces.lock();
                        let readers_and_pieces = readers_and_pieces
                            .as_mut()
                            .expect("Initial value was populated above; qed");

                        if let Some(old_plotted_sector) = maybe_old_plotted_sector {
                            readers_and_pieces.delete_sector(disk_farm_index, old_plotted_sector);
                        }
                        readers_and_pieces.add_sector(disk_farm_index, plotted_sector);
                    }
                };

            single_disk_farm
                .on_sector_plotted(Arc::new(on_plotted_sector_callback))
                .detach();

            single_disk_farm.run()
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskFarm`
    // event handlers
    drop(readers_and_pieces);

    let farm_fut = run_future_in_dedicated_thread(
        Box::pin(async move {
            while let Some(result) = single_disk_farms_stream.next().await {
                let id = result?;

                info!(%id, "Farm exited successfully");
            }
            anyhow::Ok(())
        }),
        "farmer-farm".to_string(),
    )?;
    let mut farm_fut = Box::pin(farm_fut).fuse();

    let networking_fut = run_future_in_dedicated_thread(
        Box::pin(async move { node_runner.run().await }),
        "farmer-networking".to_string(),
    )?;
    let mut networking_fut = Box::pin(networking_fut).fuse();

    futures::select!(
        // Signal future
        _ = signal.fuse() => {},

        // Farm future
        result = farm_fut => {
            result??;
        },

        // Node runner future
        _ = networking_fut => {
            info!("Node runner exited.")
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
