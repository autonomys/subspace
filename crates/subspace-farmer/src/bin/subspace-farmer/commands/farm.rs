use crate::utils::{get_required_plot_space_with_overhead, shutdown_signal};
use crate::{DiskFarm, DsnArgs, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndexHash, SectorIndex, PLOT_SECTOR_SIZE};
use subspace_farmer::single_disk_plot::piece_reader::PieceReader;
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotOptions};
use subspace_farmer::{Identity, NodeRpcClient, RpcClient};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, CustomRecordStore,
    LimitedSizeRecordStorageWrapper, MemoryProviderStorage, Node, NodeRunner,
    ParityDbRecordStorage, PieceByHashRequestHandler, PieceByHashResponse, PieceKey,
};
use tokio::runtime::Handle;
use tracing::{debug, error, info, trace};

const MAX_KADEMLIA_RECORDS_NUMBER: usize = 32768;

// Type alias for currently configured Kademlia's custom record store.
type ConfiguredRecordStore = CustomRecordStore<
    LimitedSizeRecordStorageWrapper<ParityDbRecordStorage>,
    MemoryProviderStorage,
>;

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
        piece_receiver_batch_size,
        piece_publisher_batch_size,
    } = farming_args;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    let (node, mut node_runner) = {
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
                info!("Connecting to node RPC at {}", node_rpc_url);
                let rpc_client = NodeRpcClient::new(&node_rpc_url).await?;

                rpc_client
                    .farmer_app_info()
                    .await
                    .map_err(|error| anyhow::anyhow!(error))?
                    .dsn_bootstrap_nodes
            };
        }
        configure_dsn(base_path, keypair, dsn, &readers_and_pieces).await?
    };
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
        let rpc_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_plot = SingleDiskPlot::new(SingleDiskPlotOptions {
            directory: disk_farm.directory,
            allocated_space: disk_farm.allocated_plotting_space,
            rpc_client,
            reward_address,
            dsn_node: node.clone(),
            piece_receiver_batch_size: farming_args.piece_receiver_batch_size,
            piece_publisher_batch_size: farming_args.piece_publisher_batch_size,
        })?;

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
        _ = Box::pin(async move {
            node_runner.run().await;

            info!("Node runner exited.")
        }).fuse() => {},
    );

    anyhow::Ok(())
}

async fn configure_dsn(
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        record_cache_size,
        disable_private_ips,
        reserved_peers,
    }: DsnArgs,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
) -> Result<(Node, NodeRunner<ConfiguredRecordStore>), anyhow::Error> {
    let record_cache_size = NonZeroUsize::new(record_cache_size).unwrap_or(
        NonZeroUsize::new(MAX_KADEMLIA_RECORDS_NUMBER)
            .expect("We don't expect an error on manually set value."),
    );
    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let record_cache_db_path = base_path.join("records_cache_db").into_boxed_path();

    info!(
        ?record_cache_db_path,
        ?record_cache_size,
        "Record cache DB configured."
    );

    let handle = Handle::current();
    let default_config = Config::with_generated_keypair();

    let config = Config::<ConfiguredRecordStore> {
        reserved_peers,
        keypair,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::Sector(piece_index_hash) = req.key {
                let (mut reader, piece_details) = {
                    let readers_and_pieces = match weak_readers_and_pieces.upgrade() {
                        Some(readers_and_pieces) => readers_and_pieces,
                        None => {
                            debug!("A readers and pieces are already dropped");
                            return None;
                        }
                    };
                    let readers_and_pieces = readers_and_pieces.lock();
                    let readers_and_pieces = match readers_and_pieces.as_ref() {
                        Some(readers_and_pieces) => readers_and_pieces,
                        None => {
                            debug!(
                                ?piece_index_hash,
                                "Readers and pieces are not initialized yet"
                            );
                            return None;
                        }
                    };
                    let piece_details =
                        match readers_and_pieces.pieces.get(&piece_index_hash).copied() {
                            Some(piece_details) => piece_details,
                            None => {
                                trace!(
                                    ?piece_index_hash,
                                    "Piece is not stored in any of the local plots"
                                );
                                return None;
                            }
                        };
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
        record_store: CustomRecordStore::new(
            LimitedSizeRecordStorageWrapper::new(
                ParityDbRecordStorage::new(&record_cache_db_path)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?,
                record_cache_size,
                peer_id(&default_config.keypair),
            ),
            MemoryProviderStorage::default(),
        ),
        ..default_config
    };

    create::<ConfiguredRecordStore>(config)
        .await
        .map_err(Into::into)
}

// TODO: implement proper conversion function with crypto entropy generator and zeroizing
fn derive_libp2p_keypair(schnorrkel_sk: &schnorrkel::SecretKey) -> Keypair {
    const SECRET_KEY_LENGTH: usize = 32;

    let schnorrkel_sk_bytes: [u8; SECRET_KEY_LENGTH] = schnorrkel_sk.to_bytes()
        [..SECRET_KEY_LENGTH]
        .try_into()
        .expect("Should be correct array length here.");

    let sk = ed25519::SecretKey::from_bytes(schnorrkel_sk_bytes)
        .expect("Bytes array length should be compatible");
    let ed25519_keypair: ed25519::Keypair = sk.into();

    Keypair::Ed25519(ed25519_keypair)
}
