mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::commands::shared::print_disk_farm_info;
use crate::utils::shutdown_signal;
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Record, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::single_disk_farm::{
    SingleDiskFarm, SingleDiskFarmError, SingleDiskFarmOptions,
};
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::utils::{run_future_in_dedicated_thread, tokio_rayon_spawn_handler};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tempfile::TempDir;
use tracing::{debug, error, info, info_span, warn};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm<PosTable>(farming_args: FarmingArgs) -> Result<(), anyhow::Error>
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

    if metrics_endpoints_are_specified {
        let prometheus_task = start_prometheus_metrics_server(
            metrics_endpoints,
            RegistryAdapter::Libp2p(metrics_registry),
        )?;

        let _prometheus_worker = tokio::spawn(prometheus_task);
    }

    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize).unwrap(),
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

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
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
                farming_thread_pool_size,
                plotting_thread_pool: Arc::clone(&plotting_thread_pool),
                replotting_thread_pool: Arc::clone(&replotting_thread_pool),
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

    piece_cache
        .replace_backing_caches(
            single_disk_farms
                .iter()
                .map(|single_disk_farm| single_disk_farm.piece_cache())
                .collect(),
        )
        .await;
    drop(piece_cache);

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_farms
        .iter()
        .map(|single_disk_farm| single_disk_farm.piece_reader())
        .collect::<Vec<_>>();

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    {
        let mut readers_and_pieces = readers_and_pieces.lock();
        let readers_and_pieces = readers_and_pieces.insert(ReadersAndPieces::new(piece_readers));

        single_disk_farms.iter().enumerate().try_for_each(
            |(disk_farm_index, single_disk_farm)| {
                let disk_farm_index = disk_farm_index.try_into().map_err(|_error| {
                    anyhow!(
                        "More than 256 plots are not supported, consider running multiple farmer \
                        instances"
                    )
                })?;

                (0 as SectorIndex..)
                    .zip(single_disk_farm.plotted_sectors())
                    .for_each(
                        |(sector_index, plotted_sector_result)| match plotted_sector_result {
                            Ok(plotted_sector) => {
                                readers_and_pieces.add_sector(disk_farm_index, &plotted_sector);
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

                Ok::<_, anyhow::Error>(())
            },
        )?;
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
                result?;

                info!("Farm exited successfully");
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
