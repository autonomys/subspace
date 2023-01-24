mod dsn;

use crate::commands::farm::dsn::{configure_dsn, start_announcements_processor};
use crate::utils::{get_required_plot_space_with_overhead, shutdown_signal};
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::future::{select, Either};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{test_public_parameters, Kzg};
use subspace_core_primitives::{PieceIndexHash, PLOT_SECTOR_SIZE};
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotOptions};
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::node_piece_getter::NodePieceGetter;
use subspace_farmer::utils::piece_validator::RecordsRootPieceValidator;
use subspace_farmer::utils::readers_and_pieces::{PieceDetails, ReadersAndPieces};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_networking::utils::pieces::announce_single_piece_index_with_backoff;
use tokio::sync::broadcast;
use tracing::{debug, error, info};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm_multi_disk(
    base_path: PathBuf,
    disk_farms: Vec<DiskFarm>,
    farming_args: FarmingArgs,
) -> Result<(), anyhow::Error> {
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
        disk_concurrency,
        disable_farming,
        mut dsn,
        max_concurrent_plots,
    } = farming_args;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!("Connecting to node RPC at {}", node_rpc_url);
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;
    let concurrent_plotting_semaphore = Arc::new(tokio::sync::Semaphore::new(
        farming_args.max_concurrent_plots.get(),
    ));

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
            dsn.bootstrap_nodes = {
                node_client
                    .farmer_app_info()
                    .await
                    .map_err(|error| anyhow::anyhow!(error))?
                    .dsn_bootstrap_nodes
            };
        }
        configure_dsn(base_path, keypair, dsn, &readers_and_pieces).await?
    };

    let piece_cache = Arc::new(tokio::sync::Mutex::new(piece_cache));

    let _announcements_processing_handler = start_announcements_processor(
        node.clone(),
        Arc::clone(&piece_cache),
        Arc::downgrade(&readers_and_pieces),
    )?;

    let kzg = Kzg::new(test_public_parameters());
    let records_roots_cache = Mutex::new(LruCache::new(RECORDS_ROOTS_CACHE_SIZE));
    let piece_provider = PieceProvider::new(
        node.clone(),
        Some(RecordsRootPieceValidator::new(
            node.clone(),
            node_client.clone(),
            kzg.clone(),
            records_roots_cache,
        )),
    );
    let piece_getter = Arc::new(FarmerPieceGetter::new(
        NodePieceGetter::new(piece_provider),
        piece_cache,
        node.clone(),
    ));

    let mut single_disk_plots = Vec::with_capacity(disk_farms.len());

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
    for disk_farm in disk_farms {
        let minimum_plot_size = get_required_plot_space_with_overhead(PLOT_SECTOR_SIZE);

        if disk_farm.allocated_plotting_space < minimum_plot_size {
            return Err(anyhow::anyhow!(
                "Plot size is too low ({} bytes). Minimum is {}",
                disk_farm.allocated_plotting_space,
                minimum_plot_size
            ));
        }

        info!("Connecting to node RPC at {}", node_rpc_url);
        let node_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_plot_fut = SingleDiskPlot::new(SingleDiskPlotOptions {
            directory: disk_farm.directory,
            allocated_space: disk_farm.allocated_plotting_space,
            node_client,
            reward_address,
            kzg: kzg.clone(),
            piece_getter: piece_getter.clone(),
            concurrent_plotting_semaphore: Arc::clone(&concurrent_plotting_semaphore),
        });

        let single_disk_plot = single_disk_plot_fut.await?;

        single_disk_plots.push(single_disk_plot);
    }

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_plots
        .iter()
        .map(|single_disk_plot| single_disk_plot.piece_reader())
        .collect::<Vec<_>>();

    debug!("Collecting already plotted pieces");

    // Collect already plotted pieces
    let plotted_pieces: HashMap<PieceIndexHash, PieceDetails> = single_disk_plots
        .iter()
        .enumerate()
        .flat_map(|(plot_offset, single_disk_plot)| {
            single_disk_plot
                .plotted_sectors()
                .enumerate()
                .filter_map(move |(sector_offset, plotted_sector_result)| {
                    match plotted_sector_result {
                        Ok(plotted_sector) => Some(plotted_sector),
                        Err(error) => {
                            error!(
                                %error,
                                %plot_offset,
                                %sector_offset,
                                "Failed reading plotted sector on startup, skipping"
                            );
                            None
                        }
                    }
                })
                .flat_map(move |plotted_sector| {
                    plotted_sector.piece_indexes.into_iter().enumerate().map(
                        move |(piece_offset, piece_index)| {
                            (
                                PieceIndexHash::from_index(piece_index),
                                PieceDetails {
                                    plot_offset,
                                    sector_index: plotted_sector.sector_index,
                                    piece_offset: piece_offset as u64,
                                },
                            )
                        },
                    )
                })
        })
        // We implicitly ignore duplicates here, reading just from one of the plots
        .collect();

    debug!("Finished collecting already plotted pieces");

    readers_and_pieces
        .lock()
        .replace(ReadersAndPieces::new(piece_readers, plotted_pieces));

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .enumerate()
        .map(|(plot_offset, single_disk_plot)| {
            let readers_and_pieces = Arc::clone(&readers_and_pieces);
            let node = node.clone();

            // We are not going to send anything here, but dropping of sender on dropping of
            // corresponding `SingleDiskPlot` will allow us to stop background tasks.
            let (dropped_sender, _dropped_receiver) = broadcast::channel::<()>(1);

            // Collect newly plotted pieces
            // TODO: Once we have replotting, this will have to be updated
            single_disk_plot
                .on_sector_plotted(Arc::new(move |(plotted_sector, plotting_permit)| {
                    let plotting_permit = Arc::clone(plotting_permit);
                    let node = node.clone();
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
                                !readers_and_pieces
                                    .contains_piece(&PieceIndexHash::from_index(piece_index))
                            })
                            .copied()
                            .collect::<Vec<_>>();

                        readers_and_pieces.add_pieces(
                            plotted_sector
                                .piece_indexes
                                .iter()
                                .copied()
                                .enumerate()
                                .map(|(piece_offset, piece_index)| {
                                    (
                                        PieceIndexHash::from_index(piece_index),
                                        PieceDetails {
                                            plot_offset,
                                            sector_index,
                                            piece_offset: piece_offset as u64,
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

                    let publish_fut = async move {
                        let mut pieces_publishing_futures = new_pieces
                            .into_iter()
                            .map(|piece_index| {
                                announce_single_piece_index_with_backoff(piece_index, &node)
                            })
                            .collect::<FuturesUnordered<_>>();

                        while pieces_publishing_futures.next().await.is_some() {
                            // Nothing is needed here, just driving all futures to completion
                        }

                        info!("Piece publishing was successful.");

                        // Release only after publishing is finished
                        drop(plotting_permit);
                    };

                    tokio::spawn(async move {
                        let result =
                            select(Box::pin(publish_fut), Box::pin(dropped_receiver.recv())).await;
                        if !matches!(result, Either::Right(_)) {
                            debug!("Piece publishing was cancelled due to shutdown.");
                        }
                    });
                }))
                .detach();

            single_disk_plot.run()
        })
        .collect::<FuturesUnordered<_>>();

    // Drop original instance such that the only remaining instances are in `SingleDiskPlot`
    // event handlers
    drop(readers_and_pieces);

    futures::select!(
        // Signal future
        _ = signal.fuse() => {},

        // Plotting future
        result = Box::pin(async move {
            while let Some(result) = single_disk_plots_stream.next().await {
                result?;

                info!("Farm exited successfully");
            }
            anyhow::Ok(())
        }).fuse() => {
            result?;
        },

        // Node runner future
        _ = node_runner.run().fuse() => {
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
