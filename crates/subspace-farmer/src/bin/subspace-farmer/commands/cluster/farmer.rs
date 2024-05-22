use crate::commands::shared::metrics::{FarmerMetrics, SectorState};
use crate::commands::shared::DiskFarm;
use anyhow::anyhow;
use async_lock::Mutex as AsyncMutex;
use backoff::ExponentialBackoff;
use bytesize::ByteSize;
use clap::Parser;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{select, FutureExt, StreamExt, TryStreamExt};
use prometheus_client::registry::Registry;
use std::fs;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PublicKey, Record};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::cluster::controller::ClusterNodeClient;
use subspace_farmer::cluster::farmer::farmer_service;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::cluster::plotter::ClusterPlotter;
use subspace_farmer::farm::{
    Farm, FarmingNotification, SectorExpirationDetails, SectorPlottingDetails, SectorUpdate,
};
use subspace_farmer::node_client::NodeClient;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{
    recommended_number_of_farming_threads, run_future_in_dedicated_thread, AsyncJoinOnDrop,
};
use subspace_proof_of_space::Table;
use tokio::sync::{Barrier, Semaphore};
use tracing::{error, info, info_span, warn, Instrument};

const FARM_ERROR_PRINT_INTERVAL: Duration = Duration::from_secs(30);
/// Interval between farmer self-identification broadcast messages
pub(super) const FARMER_IDENTIFICATION_BROADCAST_INTERVAL: Duration = Duration::from_secs(5);

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(super) struct FarmerArgs {
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
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: PublicKey,
    /// Run temporary farmer with specified farm size in human-readable format (e.g. 10GB, 2TiB) or
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
    /// Do not print info about configured farms on startup
    #[arg(long)]
    no_info: bool,
    /// Defines max number sectors farmer will encode concurrently, defaults to 8. Might be limited
    /// by plotting capacity available in the cluster.
    ///
    /// Increase will result in higher memory usage.
    #[arg(long, default_value = "8")]
    sector_encoding_concurrency: NonZeroUsize,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of logical CPUs
    /// available on UMA system and number of logical CPUs in first NUMA node on NUMA system, but
    /// not more than 32 threads
    #[arg(long)]
    farming_thread_pool_size: Option<NonZeroUsize>,
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
        tmp,
        max_pieces_in_sector,
        no_info,
        sector_encoding_concurrency,
        farming_thread_pool_size,
        disable_farm_locking,
        create,
        exit_on_farm_error,
        additional_components: _,
    } = farmer_args;

    let tmp_directory = if let Some(plot_size) = tmp {
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

    let node_client = ClusterNodeClient::new(nats_client.clone());

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow!("Failed to get farmer app info: {error}"))?;

    let farmer_metrics = FarmerMetrics::new(registry);

    let kzg = Kzg::new(embedded_kzg_settings());
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
        let faster_read_sector_record_chunks_mode_barrier =
            Arc::new(Barrier::new(disk_farms.len()));
        let faster_read_sector_record_chunks_mode_concurrency = Arc::new(Semaphore::new(1));

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
                let faster_read_sector_record_chunks_mode_barrier =
                    Arc::clone(&faster_read_sector_record_chunks_mode_barrier);
                let faster_read_sector_record_chunks_mode_concurrency =
                    Arc::clone(&faster_read_sector_record_chunks_mode_concurrency);

                async move {
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
                            // Cache is provided by dedicated caches in farming cluster
                            cache_percentage: 0,
                            farming_thread_pool_size,
                            plotting_delay: None,
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

        farms
            .into_iter()
            .map(|(_farm_index, farm)| farm)
            .collect::<Vec<_>>()
    };

    let total_and_plotted_sectors = farms
        .iter()
        .enumerate()
        .map(|(farm_index, farm)| async move {
            let total_sector_count = farm.total_sectors_count();
            let mut plotted_sectors_count = 0;
            let plotted_sectors = farm.plotted_sectors();
            let mut plotted_sectors = plotted_sectors.get().await.map_err(|error| {
                anyhow!("Failed to get plotted sectors for farm {farm_index}: {error}")
            })?;
            while let Some(plotted_sector_result) = plotted_sectors.next().await {
                plotted_sectors_count += 1;
                plotted_sector_result.map_err(|error| {
                    anyhow!(
                        "Failed reading plotted sector on startup for farm {farm_index}: {error}"
                    )
                })?;
            }

            anyhow::Ok((total_sector_count, plotted_sectors_count))
        })
        .collect::<FuturesOrdered<_>>()
        .try_collect::<Vec<_>>()
        .await?;

    let farmer_service_fut = farmer_service(
        nats_client,
        farms.as_slice(),
        FARMER_IDENTIFICATION_BROADCAST_INTERVAL,
    );
    let farmer_service_fut = run_future_in_dedicated_thread(
        move || farmer_service_fut,
        "controller-service".to_string(),
    )?;

    let mut farms_stream = (0u8..)
        .zip(farms)
        .zip(total_and_plotted_sectors)
        .map(|((farm_index, farm), sector_counts)| {
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
                    SectorUpdate::Plotting(SectorPlottingDetails::Finished { time, .. }) => {
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
                result??;
            },
        }

        drop(tmp_directory);

        Ok(())
    }))
}
