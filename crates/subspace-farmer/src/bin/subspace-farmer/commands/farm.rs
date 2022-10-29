use crate::utils::shutdown_signal;
use crate::{DiskFarm, FarmingArgs, Multiaddr};
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndexHash, SectorIndex};
use subspace_farmer::single_disk_plot::piece_reader::PieceReader;
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotOptions};
use subspace_farmer::NodeRpcClient;
use subspace_networking::{
    create, BootstrappedNetworkingParameters, Config, Node, NodeRunner, PieceByHashRequestHandler,
    PieceByHashResponse, PieceKey,
};
use tokio::runtime::Handle;
use tracing::{debug, error, info};

#[derive(Debug, Copy, Clone)]
struct PieceDetails {
    plot_offset: usize,
    sector_index: SectorIndex,
    piece_offset: u64,
}

#[derive(Debug)]
struct ReadersAndPieces {
    readers: Vec<PieceReader>,
    pieces: HashMap<PieceIndexHash, PieceDetails>,
}

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm_multi_disk(
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
        bootstrap_nodes,
        listen_on,
        node_rpc_url,
        reward_address,
        plot_size: _,
        disk_concurrency,
        disable_farming,
        enable_dsn,
    } = farming_args;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    let (node, node_runner) =
        configure_dsn(enable_dsn, listen_on, bootstrap_nodes, &readers_and_pieces).await?;
    let mut single_disk_plots = Vec::with_capacity(disk_farms.len());

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
    for disk_farm in disk_farms {
        if disk_farm.allocated_plotting_space < 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "Plot size is too low ({0} bytes). Did you mean {0}G or {0}T?",
                disk_farm.allocated_plotting_space
            ));
        }

        info!("Connecting to node at {}", node_rpc_url);
        let rpc_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_plot = SingleDiskPlot::new(SingleDiskPlotOptions {
            directory: disk_farm.directory,
            allocated_space: disk_farm.allocated_plotting_space,
            rpc_client,
            reward_address,
            dsn_node: node.clone(),
        })?;

        single_disk_plots.push(single_disk_plot);
    }

    // Store piece readers so we can reference them later
    let piece_readers = single_disk_plots
        .iter()
        .map(|single_disk_plot| single_disk_plot.piece_reader())
        .collect::<Vec<_>>();

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

    readers_and_pieces.lock().replace(ReadersAndPieces {
        readers: piece_readers,
        pieces: plotted_pieces,
    });

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .enumerate()
        .map(|(plot_offset, single_disk_plot)| {
            let readers_and_pieces = Arc::clone(&readers_and_pieces);

            // Collect newly plotted pieces
            // TODO: Once we have replotting, this will have to be updated
            single_disk_plot
                .on_sector_plotted(Arc::new(move |plotted_sector| {
                    readers_and_pieces
                        .lock()
                        .as_mut()
                        .expect("Initial value was populated above; qed")
                        .pieces
                        .extend(
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
                                            sector_index: plotted_sector.sector_index,
                                            piece_offset: piece_offset as u64,
                                        },
                                    )
                                }),
                        );
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
        _ = Box::pin(async move {
            signal.await;
        }).fuse() => {},

        // Plotting future
        _ = Box::pin(async move {
            while let Some(result) = single_disk_plots_stream.next().await {
                result?;

                info!("Farm exited successfully");
            }
            anyhow::Ok(())
        }).fuse() => {},

        // Node runner future
        _ = Box::pin(async move {
            if let Some(mut node_runner) = node_runner{
                node_runner.run().await;

                info!("Node runner exited.")
            } else {
                futures::future::pending().await
            }
        }).fuse() => {},
    );

    anyhow::Ok(())
}

async fn configure_dsn(
    enable_dsn: bool,
    listen_on: Vec<Multiaddr>,
    bootstrap_nodes: Vec<Multiaddr>,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
) -> Result<(Option<Node>, Option<NodeRunner>), anyhow::Error> {
    if !enable_dsn {
        info!("No DSN configured.");
        return Ok((None, None));
    }

    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let handle = Handle::current();
    let config = Config {
        listen_on,
        allow_non_globals_in_dht: true,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::Sector(piece_index_hash) = req.key {
                let (mut reader, piece_details) = {
                    let readers_and_pieces = weak_readers_and_pieces.upgrade()?;
                    let readers_and_pieces = readers_and_pieces.lock();
                    let readers_and_pieces = readers_and_pieces.as_ref()?;
                    let piece_details =
                        readers_and_pieces.pieces.get(&piece_index_hash).copied()?;
                    let reader = readers_and_pieces
                        .readers
                        .get(piece_details.plot_offset)
                        .cloned()
                        .expect("Offsets strictly correspond to existing plots; qed");
                    (reader, piece_details)
                };

                let handle = handle.clone();
                tokio::task::block_in_place(move || {
                    handle.block_on(
                        reader.read_piece(piece_details.sector_index, piece_details.piece_offset),
                    )
                })
            } else {
                debug!(key=?req.key, "Incorrect piece request - unsupported key type.");

                None
            };

            Some(PieceByHashResponse { piece: result })
        })],
        ..Config::with_generated_keypair()
    };

    create(config)
        .await
        .map(|(node, node_runner)| (Some(node), Some(node_runner)))
        .map_err(Into::into)
}
