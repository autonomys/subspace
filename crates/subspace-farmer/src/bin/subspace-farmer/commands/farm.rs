mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::commands::shared::print_disk_farm_info;
use crate::utils::{get_required_plot_space_with_overhead, shutdown_signal};
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Context, Result};
use futures::future::{select, Either};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{
    ArchivedHistorySegment, Piece, PieceIndex, Record, SectorIndex, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::single_disk_plot::{
    SingleDiskPlot, SingleDiskPlotError, SingleDiskPlotOptions,
};
use subspace_farmer::utils::archival_storage_pieces::ArchivalStoragePieces;
use subspace_farmer::utils::farmer_piece_cache::FarmerPieceCache;
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::node_piece_getter::NodePieceGetter;
use subspace_farmer::utils::piece_cache::PieceCache;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::utils::run_future_in_dedicated_thread;
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_announcement::announce_single_piece_index_hash_with_backoff;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");
const GET_PIECE_MAX_RETRIES_COUNT: u16 = 3;
const GET_PIECE_DELAY_IN_SECS: u64 = 3;

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
            archival_storage_pieces.clone(),
        )?
    };

    let piece_cache = Arc::new(tokio::sync::Mutex::new(piece_cache));

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
        piece_cache.clone(),
    ));

    let last_segment_index = farmer_app_info.protocol_info.history_size.segment_index();

    let _piece_cache_population = run_future_in_dedicated_thread(
        Box::pin({
            let piece_cache = piece_cache.clone();
            let piece_getter = piece_getter.clone();

            populate_pieces_cache(last_segment_index, piece_getter, piece_cache)
        }),
        "pieces-cache-population".to_string(),
    )?;

    let _piece_cache_maintainer = run_future_in_dedicated_thread(
        Box::pin({
            let piece_cache = piece_cache.clone();
            let node_client = node_client.clone();

            fill_piece_cache_from_archived_segments(node_client, piece_cache)
        }),
        "pieces-cache-maintainer".to_string(),
    )?;

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
    {
        let mut readers_and_pieces = readers_and_pieces.lock();
        let readers_and_pieces = readers_and_pieces.insert(ReadersAndPieces::new(piece_readers));

        single_disk_plots
            .iter()
            .enumerate()
            .for_each(|(disk_farm_index, single_disk_plot)| {
                let disk_farm_index = disk_farm_index
                    .try_into()
                    .expect("More than 256 plots are not supported, what are you even doing?!");

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
            });
    }

    info!("Finished collecting already plotted pieces successfully");

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .enumerate()
        .map(|(disk_farm_index, single_disk_plot)| {
            let disk_farm_index = disk_farm_index
                .try_into()
                .expect("More than 256 plots are not supported, what are you even doing?!");
            let readers_and_pieces = Arc::clone(&readers_and_pieces);
            let node = node.clone();
            let span = info_span!("farm", %disk_farm_index);
            let archival_storage_pieces = archival_storage_pieces.clone();

            // We are not going to send anything here, but dropping of sender on dropping of
            // corresponding `SingleDiskPlot` will allow us to stop background tasks.
            let (dropped_sender, _dropped_receiver) = broadcast::channel::<()>(1);

            // Collect newly plotted pieces
            // TODO: Once we have replotting, this will have to be updated
            single_disk_plot
                .on_sector_plotted(Arc::new(move |(plotted_sector, plotting_permit)| {
                    let _span_guard = span.enter();
                    let plotting_permit = Arc::clone(plotting_permit);
                    let node = node.clone();
                    let sector_index = plotted_sector.sector_index;

                    let mut dropped_receiver = dropped_sender.subscribe();

                    {
                        let mut readers_and_pieces = readers_and_pieces.lock();
                        let readers_and_pieces = readers_and_pieces
                            .as_mut()
                            .expect("Initial value was populated above; qed");
                        readers_and_pieces.add_sector(disk_farm_index, plotted_sector);
                    }

                    archival_storage_pieces.add_pieces(&plotted_sector.piece_indexes);

                    let piece_indexes = plotted_sector.piece_indexes.clone();
                    // TODO: Remove when we no longer need announcements
                    let publish_fut = async move {
                        let mut pieces_publishing_futures = piece_indexes
                            .iter()
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

                        info!(?sector_index, "Sector publishing was successful.");

                        // Release only after publishing is finished
                        drop(plotting_permit);
                    }
                    .in_current_span();

                    tokio::spawn(async move {
                        let result =
                            select(Box::pin(publish_fut), Box::pin(dropped_receiver.recv())).await;
                        if matches!(result, Either::Right(_)) {
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

/// Populates piece cache on startup. It waits for the new segment index and check all pieces from
/// previous segments to see if they are already in the cache. If they are not, they are added
/// from DSN.
async fn populate_pieces_cache<PG, PC>(
    segment_index: SegmentIndex,
    piece_getter: Arc<FarmerPieceGetter<PG, PC>>,
    piece_cache: Arc<tokio::sync::Mutex<FarmerPieceCache>>,
) where
    PG: PieceGetter + Send + Sync,
    PC: PieceCache + Send + 'static,
{
    debug!(%segment_index, "Started syncing piece cache...");
    let final_piece_index =
        u64::from(segment_index.first_piece_index()) + ArchivedHistorySegment::NUM_PIECES as u64;

    // TODO: consider optimizing starting point of this loop
    let mut piece_index = 0;
    'outer: while piece_index < final_piece_index {
        // Scroll to the next piece index to cache.
        {
            let piece_cache = piece_cache.lock().await;
            while !piece_cache
                .should_cache(&PieceIndex::from(piece_index).hash().to_multihash().into())
            {
                piece_index += 1;

                if piece_index >= final_piece_index {
                    break 'outer;
                }
            }
        }

        let key = PieceIndex::from(piece_index).hash().to_multihash().into();

        let result = piece_getter
            .get_piece(piece_index.into(), PieceGetterRetryPolicy::Limited(1))
            .await;

        match result {
            Ok(Some(piece)) => {
                debug!(%piece_index, "Added piece to cache.");
                piece_cache.lock().await.add_piece(key, piece);
            }
            Ok(None) => {
                debug!(%piece_index, "Couldn't find piece.");
            }
            Err(err) => {
                debug!(error=%err, %piece_index, "Failed to get piece for piece cache.");
            }
        }

        piece_index += 1;
    }

    debug!("Finished syncing piece cache.");
}

/// Subscribes to a new segment index and adds pieces from the segment to the cache if required.
async fn fill_piece_cache_from_archived_segments(
    node_client: NodeRpcClient,
    piece_cache: Arc<tokio::sync::Mutex<FarmerPieceCache>>,
) {
    let segment_headers_notifications = node_client
        .subscribe_archived_segment_headers()
        .await
        .map_err(|err| anyhow::anyhow!(err.to_string()))
        .context("Failed to subscribe to archived segments");

    match segment_headers_notifications {
        Ok(mut segment_headers_notifications) => {
            while let Some(segment_header) = segment_headers_notifications.next().await {
                let segment_index = segment_header.segment_index();

                debug!(%segment_index, "Starting to process archived segment....");

                for piece_index in segment_index.segment_piece_indexes() {
                    let key = piece_index.hash().to_multihash().into();
                    {
                        if !piece_cache.lock().await.should_cache(&key) {
                            trace!(%piece_index, ?key, "Piece key will not be included in the cache.");

                            continue;
                        }
                    }

                    trace!(%piece_index, ?key, "Piece key will be included in the cache.");

                    // Segment notification will come earlier than node's local cache finishes its
                    // initialization, so we need to wait for it.
                    let mut retries_count = 0u16;
                    'retry: loop {
                        if retries_count >= GET_PIECE_MAX_RETRIES_COUNT {
                            debug!(%piece_index, "Max retries number exceeded.");

                            break 'retry;
                        }

                        retries_count += 1;

                        let piece = node_client.piece(piece_index).await;

                        match piece {
                            Ok(Some(piece)) => {
                                {
                                    piece_cache.lock().await.add_piece(key, piece);
                                }

                                trace!(%piece_index, "Got piece for archived segment.");

                                break 'retry;
                            }
                            Ok(None) => {
                                debug!(%piece_index, "Can't get piece. Retrying...");

                                sleep(Duration::from_secs(GET_PIECE_DELAY_IN_SECS)).await;
                            }
                            Err(err) => {
                                warn!(
                                    piece_index = ?piece_index,
                                    err = ?err,
                                    "Failed to get piece"
                                );
                            }
                        }
                    }
                }

                match node_client
                    .acknowledge_archived_segment_header(segment_index)
                    .await
                {
                    Ok(()) => {
                        debug!(%segment_index, "Acknowledged archived segment.");
                    }
                    Err(err) => {
                        error!(%segment_index, ?err, "Failed to acknowledge archived segment.");
                    }
                };

                debug!(%segment_index, "Finished processing archived segment.");
            }
        }
        Err(err) => {
            error!(?err, "Failed to get archived segments notifications.")
        }
    }
}
