mod dsn;

use crate::commands::farm::dsn::{configure_dsn, start_announcements_processor};
use crate::commands::shared::print_disk_farm_info;
use crate::utils::{get_required_plot_space_with_overhead, shutdown_signal};
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::channel::mpsc;
use futures::future::{select, Either};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PieceIndexHash, PieceOffset, Record};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_plot::{
    SingleDiskPlot, SingleDiskPlotError, SingleDiskPlotOptions,
};
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::node_piece_getter::NodePieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::readers_and_pieces::{PieceDetails, ReadersAndPieces};
use subspace_farmer::utils::run_future_in_dedicated_thread;
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::piece_caching::PieceMemoryCache;
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::utils::piece_announcement::announce_single_piece_index_hash_with_backoff;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tokio::sync::broadcast;
use tracing::{debug, error, info, info_span, warn, Instrument};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

const MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE: NonZeroUsize =
    NonZeroUsize::new(2000).expect("Not zero; qed");

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
        no_info: _,
    } = farming_args;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;
    let concurrent_plotting_semaphore = Arc::new(tokio::sync::Semaphore::new(
        farming_args.max_concurrent_plots.get(),
    ));

    let piece_memory_cache = PieceMemoryCache::default();

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let (provider_records_sender, provider_records_receiver) =
        mpsc::channel(MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE.get());

    let (node, mut node_runner, piece_cache) = {
        // TODO: Temporary networking identity derivation from the first disk farm identity.
        let directory = disk_farms
            .first()
            .expect("Disk farm collection should not be empty at this point.")
            .directory
            .clone();
        // TODO: Update `Identity` to use more specific error type and remove this `.unwrap()`
        let identity = Identity::open_or_create(&directory).unwrap();
        let keypair = derive_libp2p_keypair(identity.secret_key());

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
            piece_memory_cache.clone(),
            Mutex::new(provider_records_sender),
        )?
    };

    let piece_cache = Arc::new(tokio::sync::Mutex::new(piece_cache));

    start_announcements_processor(
        node.clone(),
        Arc::clone(&piece_cache),
        Arc::downgrade(&readers_and_pieces),
        provider_records_receiver,
    )?;

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
        NodePieceGetter::new(piece_provider),
        piece_cache,
        node.clone(),
    ));

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
                concurrent_plotting_semaphore: Arc::clone(&concurrent_plotting_semaphore),
                piece_memory_cache: piece_memory_cache.clone(),
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

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_plots
        .iter()
        .map(|single_disk_plot| single_disk_plot.piece_reader())
        .collect::<Vec<_>>();

    info!("Collecting already plotted pieces (this will take some time)...");

    // Collect already plotted pieces
    let plotted_pieces: HashMap<PieceIndexHash, PieceDetails> = single_disk_plots
        .iter()
        .enumerate()
        .flat_map(|(disk_farm_index, single_disk_plot)| {
            single_disk_plot
                .plotted_sectors()
                .enumerate()
                .filter_map(move |(sector_offset, plotted_sector_result)| {
                    match plotted_sector_result {
                        Ok(plotted_sector) => Some(plotted_sector),
                        Err(error) => {
                            error!(
                                %error,
                                %disk_farm_index,
                                %sector_offset,
                                "Failed reading plotted sector on startup, skipping"
                            );
                            None
                        }
                    }
                })
                .flat_map(move |plotted_sector| {
                    (PieceOffset::ZERO..).zip(plotted_sector.piece_indexes).map(
                        move |(piece_offset, piece_index)| {
                            (
                                piece_index.hash(),
                                PieceDetails {
                                    disk_farm_index,
                                    sector_index: plotted_sector.sector_index,
                                    piece_offset,
                                },
                            )
                        },
                    )
                })
        })
        // We implicitly ignore duplicates here, reading just from one of the plots
        .collect();

    info!("Finished collecting already plotted pieces successfully");

    readers_and_pieces
        .lock()
        .replace(ReadersAndPieces::new(piece_readers, plotted_pieces));

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .enumerate()
        .map(|(disk_farm_index, single_disk_plot)| {
            let readers_and_pieces = Arc::clone(&readers_and_pieces);
            let node = node.clone();
            let span = info_span!("farm", %disk_farm_index);

            // We are not going to send anything here, but dropping of sender on dropping of
            // corresponding `SingleDiskPlot` will allow us to stop background tasks.
            let (dropped_sender, _dropped_receiver) = broadcast::channel::<()>(1);

            // Collect newly plotted pieces
            // TODO: Once we have replotting, this will have to be updated
            single_disk_plot
                .on_sector_plotted(Arc::new(
                    move |(sector_offset, plotted_sector, plotting_permit)| {
                        let _span_guard = span.enter();
                        let plotting_permit = Arc::clone(plotting_permit);
                        let node = node.clone();
                        let sector_offset = *sector_offset;
                        let sector_index = plotted_sector.sector_index;

                        let mut dropped_receiver = dropped_sender.subscribe();

                        let new_pieces = {
                            let mut readers_and_pieces = readers_and_pieces.lock();
                            let readers_and_pieces = readers_and_pieces
                                .as_mut()
                                .expect("Initial value was populated above; qed");

                            let new_pieces = plotted_sector
                                .piece_indexes
                                .iter()
                                .filter(|&&piece_index| {
                                    // Skip pieces that are already plotted and thus were announced
                                    // before
                                    !readers_and_pieces.contains_piece(&piece_index.hash())
                                })
                                .copied()
                                .collect::<Vec<_>>();

                            readers_and_pieces.add_pieces(
                                (PieceOffset::ZERO..)
                                    .zip(plotted_sector.piece_indexes.iter().copied())
                                    .map(|(piece_offset, piece_index)| {
                                        (
                                            piece_index.hash(),
                                            PieceDetails {
                                                disk_farm_index,
                                                sector_index,
                                                piece_offset,
                                            },
                                        )
                                    }),
                            );

                            new_pieces
                        };

                        if new_pieces.is_empty() {
                            // None of the pieces are new, nothing left to do here
                            return;
                        }

                        // TODO: Skip those that were already announced (because they cached)
                        let publish_fut = async move {
                            let mut pieces_publishing_futures = new_pieces
                                .into_iter()
                                .map(|piece_index| {
                                    announce_single_piece_index_hash_with_backoff(
                                        piece_index.hash(),
                                        &node,
                                    )
                                })
                                .collect::<FuturesUnordered<_>>();

                            while pieces_publishing_futures.next().await.is_some() {
                                // Nothing is needed here, just driving all futures to completion
                            }

                            info!(
                                %sector_offset,
                                ?sector_index,
                                "Sector publishing was successful."
                            );

                            // Release only after publishing is finished
                            drop(plotting_permit);
                        }
                        .in_current_span();

                        tokio::spawn(async move {
                            let result =
                                select(Box::pin(publish_fut), Box::pin(dropped_receiver.recv()))
                                    .await;
                            if matches!(result, Either::Right(_)) {
                                debug!("Piece publishing was cancelled due to shutdown.");
                            }
                        });
                    },
                ))
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

    Keypair::Ed25519(
        ed25519::SecretKey::from_bytes(&mut secret_bytes.as_mut()[..32])
            .expect("Secret key is exactly 32 bytes in size; qed")
            .into(),
    )
}
