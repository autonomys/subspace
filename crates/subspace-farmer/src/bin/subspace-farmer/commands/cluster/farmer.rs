//! Metrics specific for single disk farm

use crate::commands::shared::DiskFarm;
use anyhow::anyhow;
use async_lock::Mutex as AsyncMutex;
use backoff::ExponentialBackoff;
use bytesize::ByteSize;
use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt, select};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::fs;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::pieces::Record;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::cluster::controller::ClusterNodeClient;
use subspace_farmer::cluster::farmer::farmer_service;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::cluster::plotter::ClusterPlotter;
use subspace_farmer::farm::Farm;
use subspace_farmer::node_client::NodeClient;
use subspace_farmer::node_client::caching_proxy_node_client::CachingProxyNodeClient;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    AsyncJoinOnDrop, recommended_number_of_farming_threads, run_future_in_dedicated_thread,
};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_kzg::Kzg;
use subspace_proof_of_space::Table;
use tracing::{Instrument, error, info, info_span, warn};

const FARM_ERROR_PRINT_INTERVAL: Duration = Duration::from_secs(30);
/// Interval between farmer self-identification broadcast messages
pub(super) const FARMER_IDENTIFICATION_BROADCAST_INTERVAL: Duration = Duration::from_secs(30);

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(super) struct FarmerArgs {
    /// One or more farms located at specified paths, each with its own allocated space.
    ///
    /// In case of multiple disks, it is recommended to specify them individually rather than using
    /// RAID 0, that way farmer will be able to better take advantage of concurrency of individual
    /// drives.
    ///
    /// The format for each farm is a coma-separated list of strings like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human-readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure to not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime). Optionally, `record-chunks-mode` can be
    /// set to `ConcurrentChunks` (default) or `WholeSector`.
    disk_farms: Vec<DiskFarm>,
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: Option<PublicKey>,
    /// Sets some flags that are convenient during development, currently `--reward-address` (if
    /// not specified explicitly)
    #[arg(long)]
    dev: bool,
    /// Run a temporary farmer with a farm size in human-readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory that will be deleted at the
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
    /// Do not print info about configured farms on startup
    #[arg(long)]
    no_info: bool,
    /// The maximum number sectors a farmer will encode concurrently, defaults to 50. Might be
    /// limited by plotting capacity available in the cluster.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long, default_value = "50")]
    sector_encoding_concurrency: NonZeroUsize,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving). Defaults to the number of logical CPUs
    /// on UMA systems, or the number of logical CPUs in the first NUMA node on NUMA systems, but
    /// limited to 32 threads.
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
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
    /// Number of service instances.
    ///
    /// Increasing number of services allows to process more concurrent requests, but increasing
    /// beyond number of CPU cores doesn't make sense and will likely hurt performance instead.
    #[arg(long, default_value = "32")]
    service_instances: NonZeroUsize,
    /// Additional cluster components
    #[clap(raw = true)]
    pub(super) additional_components: Vec<String>,
}

pub(super) async fn farmer<PosTable>(
    nats_client: NatsClient,
    registry: &mut Registry,
    farmer_args: FarmerArgs,
) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>>
where
    PosTable: Table,
{
    let FarmerArgs {
        mut disk_farms,
        reward_address,
        dev,
        tmp,
        max_pieces_in_sector,
        no_info,
        sector_encoding_concurrency,
        farming_thread_pool_size,
        max_plotting_sectors_per_farm,
        disable_farm_locking,
        create,
        exit_on_farm_error,
        service_instances,
        additional_components: _,
    } = farmer_args;

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

    let tmp_directory = if let Some(plot_size) = tmp {
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

    let node_client = CachingProxyNodeClient::new(ClusterNodeClient::new(nats_client.clone()))
        .await
        .map_err(|error| anyhow!("Failed to create caching proxy node client: {error}"))?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow!("Failed to get farmer app info: {error}"))?;

    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;

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
    let plotter = Arc::new(ClusterPlotter::new(
        nats_client.clone(),
        sector_encoding_concurrency,
        ExponentialBackoff {
            max_elapsed_time: None,
            ..ExponentialBackoff::default()
        },
    ));

    let farms = {
        let node_client = node_client.clone();
        let info_mutex = &AsyncMutex::new(());
        let registry = &Mutex::new(registry);

        let mut farms = Vec::with_capacity(disk_farms.len());
        let mut farms_stream = disk_farms
            .into_iter()
            .enumerate()
            .map(|(farm_index, disk_farm)| {
                let farmer_app_info = farmer_app_info.clone();
                let node_client = node_client.clone();
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
                            // Cache is provided by dedicated caches in farming cluster
                            cache_percentage: 0,
                            farming_thread_pool_size,
                            plotting_delay: None,
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

        farms
            .into_iter()
            .map(|(_farm_index, farm)| farm)
            .collect::<Vec<_>>()
    };

    let mut farmer_services = (0..service_instances.get())
        .map(|index| {
            AsyncJoinOnDrop::new(
                tokio::spawn(farmer_service(
                    nats_client.clone(),
                    farms.as_slice(),
                    FARMER_IDENTIFICATION_BROADCAST_INTERVAL,
                    index == 0,
                )),
                true,
            )
        })
        .collect::<FuturesUnordered<_>>();

    let farmer_service_fut = async move {
        farmer_services
            .next()
            .await
            .expect("Not empty; qed")
            .map_err(|error| anyhow!("Farmer service failed: {error}"))?
            .map_err(|error| anyhow!("Farmer service failed: {error}"))
    };

    let mut farms_stream = (0u8..)
        .zip(farms)
        .map(|(farm_index, farm)| farm.run().map(move |result| (farm_index, result)))
        .collect::<FuturesUnordered<_>>();

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

    Ok(Box::pin(async move {
        let farm_fut = farm_fut;
        let farmer_service_fut = farmer_service_fut;

        let farm_fut = pin!(farm_fut);
        let farmer_service_fut = pin!(farmer_service_fut);

        select! {
            // Farm future
            result = farm_fut.fuse() => {
                result??;
            },

            // Piece cache worker future
            result = farmer_service_fut.fuse() => {
                result?;
            },
        }

        drop(tmp_directory);

        Ok(())
    }))
}
