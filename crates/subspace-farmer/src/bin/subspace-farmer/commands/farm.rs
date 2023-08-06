mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::commands::shared::print_disk_farm_info;
use crate::utils::{get_required_plot_space_with_overhead, shutdown_signal};
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{Piece, Record, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::single_disk_plot::{
    SingleDiskPlot, SingleDiskPlotError, SingleDiskPlotOptions,
};
use subspace_farmer::utils::archival_storage_info::ArchivalStorageInfo;
use subspace_farmer::utils::archival_storage_pieces::ArchivalStoragePieces;
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::utils::run_future_in_dedicated_thread;
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tracing::{debug, error, info, info_span, warn};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm_multi_disk<PosTable>(
    base_path: PathBuf,
    disk_farms: Vec<DiskFarm>,
    farming_args: FarmingArgs,
) -> Result<(), anyhow::Error>
where
    PosTable: Table,
{
    if disk_farms.is_empty() {
        return Err(anyhow!("There must be at least one disk farm provided"));
    }

    let signal = shutdown_signal();

    // TODO: Use variables and remove this suppression
    #[allow(unused_variables)]
    let FarmingArgs {
        node_rpc_url,
        reward_address,
        plot_size: _,
        max_pieces_in_sector,
        disk_concurrency,
        disable_farming,
        mut dsn,
        max_concurrent_plots,
        cache_percentage,
        no_info: _,
    } = farming_args;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let cuckoo_filter_capacity = disk_farms
        .iter()
        .map(|df| df.allocated_plotting_space as usize)
        .sum::<usize>()
        / Piece::SIZE
        + 1usize;
    let archival_storage_pieces = ArchivalStoragePieces::new(cuckoo_filter_capacity);
    let archival_storage_info = ArchivalStorageInfo::default();

    let directory = disk_farms
        .first()
        .expect("Disk farm collection is not be empty as checked above; qed")
        .directory
        .clone();
    // TODO: Update `Identity` to use more specific error type and remove this `.unwrap()`
    let identity = Identity::open_or_create(&directory).unwrap();
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();

    let (piece_cache, piece_cache_worker) = PieceCache::new(node_client.clone(), peer_id);

    let (node, mut node_runner) = {
        if dsn.bootstrap_nodes.is_empty() {
            dsn.bootstrap_nodes = farmer_app_info.dsn_bootstrap_nodes.clone();
        }

        configure_dsn(
            hex::encode(farmer_app_info.genesis_hash),
            base_path,
            keypair,
            dsn,
            &readers_and_pieces,
            node_client.clone(),
            archival_storage_pieces.clone(),
            archival_storage_info.clone(),
            piece_cache.clone(),
        )?
    };

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
        archival_storage_info,
    ));

    let _piece_cache_worker = run_future_in_dedicated_thread(
        Box::pin(piece_cache_worker.run(piece_getter.clone())),
        "cache-worker".to_string(),
    );

    let mut single_disk_plots = Vec::with_capacity(disk_farms.len());
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

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        debug!(url = %node_rpc_url, %disk_farm_index, "Connecting to node RPC");
        let node_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_plot_fut = SingleDiskPlot::new::<_, _, PosTable>(
            SingleDiskPlotOptions {
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
            },
            disk_farm_index,
        );

        let single_disk_plot = match single_disk_plot_fut.await {
            Ok(single_disk_plot) => single_disk_plot,
            Err(SingleDiskPlotError::InsufficientAllocatedSpace {
                min_size,
                allocated_space,
            }) => {
                let minimum_plot_size = get_required_plot_space_with_overhead(min_size as u64);
                let allocated_plotting_space_with_overhead =
                    get_required_plot_space_with_overhead(allocated_space);

                return Err(anyhow::anyhow!(
                    "Plot size is too low ({} bytes). Minimum is {}",
                    allocated_plotting_space_with_overhead,
                    minimum_plot_size
                ));
            }
            Err(error) => {
                return Err(error.into());
            }
        };

        if !farming_args.no_info {
            print_disk_farm_info(disk_farm.directory, disk_farm_index);
        }

        single_disk_plots.push(single_disk_plot);
    }

    piece_cache
        .replace_backing_caches(
            single_disk_plots
                .iter()
                .map(|single_disk_plot| single_disk_plot.piece_cache())
                .collect(),
        )
        .await;
    drop(piece_cache);

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_plots
        .iter()
        .map(|single_disk_plot| single_disk_plot.piece_reader())
        .collect::<Vec<_>>();

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    {
        let mut readers_and_pieces = readers_and_pieces.lock();
        let readers_and_pieces = readers_and_pieces.insert(ReadersAndPieces::new(
            piece_readers,
            archival_storage_pieces,
        ));

        single_disk_plots.iter().enumerate().try_for_each(
            |(disk_farm_index, single_disk_plot)| {
                let disk_farm_index = disk_farm_index.try_into().map_err(|_error| {
                    anyhow!(
                        "More than 256 plots are not supported, consider running multiple farmer \
                        instances"
                    )
                })?;

                (0 as SectorIndex..)
                    .zip(single_disk_plot.plotted_sectors())
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

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .enumerate()
        .map(|(disk_farm_index, single_disk_plot)| {
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

            single_disk_plot
                .on_sector_plotted(Arc::new(on_plotted_sector_callback))
                .detach();

            single_disk_plot.run()
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskPlot`
    // event handlers
    drop(readers_and_pieces);

    let farm_fut = run_future_in_dedicated_thread(
        Box::pin(async move {
            while let Some(result) = single_disk_plots_stream.next().await {
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
