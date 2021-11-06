use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc::{FarmerMetadata, RpcClient};
use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use subspace_archiving::archiver::{ArchivedSegment, BlockArchiver, ObjectArchiver};
use subspace_archiving::pre_genesis_data;
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::{EncodedBlockWithObjectMapping, Sha256Hash};
use subspace_solving::SubspaceCodec;

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
pub async fn farm(base_directory: PathBuf, ws_server: &str) -> Result<()> {
    // TODO: revert this to pub(crate) again (temporarily modified)
    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = Plot::open_or_create(&base_directory.clone().into()).await?;

    info!("Opening commitments");
    let commitments = Commitments::new(base_directory.join("commitments").into()).await?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let path = base_directory.join("object-mappings");
        move || ObjectMappings::new(&path)
    })
    .await??;

    info!("Connecting to RPC server: {}", ws_server);
    let client = RpcClient::new(ws_server).await?;

    let identity = Identity::open_or_create(&base_directory)?;

    // start the farming task
    // right now the instance is unused, however, if we want to call stop the process
    // we can just drop the instance, and it will be stopped magically :)
    let _farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity.clone(),
    );

    // start the background plotting
    // NOTE: THIS WILL CHANGE IN THE UPCOMING PR
    let public_key = identity.public_key();
    let plotting_result =
        background_plotting(client, plot, commitments, object_mappings, &public_key).await;

    match plotting_result {
        Ok(()) => {
            info!("Background plotting shutdown gracefully");

            Ok(())
        }
        Err(error) => Err(anyhow!("Background plotting error: {}", error)),
    }
}

// TODO: Blocks that are coming form substrate node are fully trusted right now, which we probably
//  don't want eventually
/// Maintains plot in up to date state plotting new pieces as they are produced on the network.
async fn background_plotting<P: AsRef<[u8]>>(
    client: RpcClient,
    plot: Plot,
    commitments: Commitments,
    object_mappings: ObjectMappings,
    public_key: &P,
) -> Result<()> {
    let weak_plot = plot.downgrade();
    let FarmerMetadata {
        confirmation_depth_k,
        record_size,
        recorded_history_segment_size,
        pre_genesis_object_size,
        pre_genesis_object_count,
        pre_genesis_object_seed,
    } = client.farmer_metadata().await?;

    // TODO: This assumes fixed size segments, which might not be the case
    let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

    let subspace_solving = SubspaceCodec::new(public_key);

    let mut archiver = if let Some(last_root_block) = plot.get_last_root_block().await? {
        // Continuing from existing initial state
        if plot.is_empty() {
            return Err(anyhow!("Plot is empty on restart, can't continue",));
        }

        drop(plot);

        let last_archived_block_number = last_root_block.last_archived_block().number;
        info!("Last archived block {}", last_archived_block_number);

        let maybe_last_archived_block = client.block_by_number(last_archived_block_number).await?;

        match maybe_last_archived_block {
            Some(EncodedBlockWithObjectMapping {
                block,
                object_mapping,
            }) => BlockArchiver::with_initial_state(
                record_size as usize,
                recorded_history_segment_size as usize,
                last_root_block,
                &block,
                object_mapping,
            )?,
            None => {
                return Err(anyhow!(
                    "Failed to get block {} from the chain, probably need to erase existing plot",
                    last_archived_block_number
                ));
            }
        }
    } else {
        // Starting from genesis
        if !plot.is_empty() {
            // Restart before first block was archived, erase the plot
            // TODO: Erase plot
        }

        drop(plot);

        let mut object_archiver =
            ObjectArchiver::new(record_size as usize, recorded_history_segment_size as usize)?;

        // Erasure coding in archiver and piece encoding are a CPU-intensive operations
        let maybe_block_archiver_handle = tokio::task::spawn_blocking({
            let weak_plot = weak_plot.clone();
            let commitments = commitments.clone();
            let object_mappings = object_mappings.clone();
            let subspace_solving = subspace_solving.clone();

            move || -> Result<Option<BlockArchiver>, anyhow::Error> {
                let runtime_handle = tokio::runtime::Handle::current();
                info!("Plotting pre-genesis objects");

                // These archived segments are a part of the public parameters of network setup
                for index in 0..pre_genesis_object_count {
                    let archived_segments =
                        object_archiver.add_object(pre_genesis_data::from_seed(
                            &pre_genesis_object_seed,
                            index,
                            pre_genesis_object_size,
                        ));

                    for archived_segment in archived_segments {
                        let ArchivedSegment {
                            root_block,
                            mut pieces,
                            object_mapping,
                        } = archived_segment;
                        let piece_index_offset = merkle_num_leaves * root_block.segment_index();

                        let object_mapping =
                            create_global_object_mapping(piece_index_offset, object_mapping);

                        // TODO: Batch encoding
                        for (position, piece) in pieces.iter_mut().enumerate() {
                            if let Err(error) =
                                subspace_solving.encode(piece_index_offset + position as u64, piece)
                            {
                                error!("Failed to encode a piece: error: {}", error);
                                continue;
                            }
                        }

                        if let Some(plot) = weak_plot.upgrade() {
                            let pieces = Arc::new(pieces);
                            // TODO: There is no internal mapping between pieces and their indexes yet
                            // TODO: Then we might want to send indexes as a separate vector
                            runtime_handle.block_on(
                                plot.write_many(Arc::clone(&pieces), piece_index_offset),
                            )?;
                            runtime_handle.block_on(
                                commitments.create_for_pieces(&pieces, piece_index_offset),
                            )?;
                            object_mappings.store(&object_mapping)?;
                            info!(
                                "Archived segment {} at object {}",
                                root_block.segment_index(),
                                index
                            );
                        } else {
                            return Ok(None);
                        }
                    }
                }

                info!("Finished plotting pre-genesis objects");

                Ok(Some(object_archiver.into_block_archiver()))
            }
        });

        match maybe_block_archiver_handle.await?? {
            Some(block_archiver) => block_archiver,
            None => {
                // Plot was dropped, time to exit already
                return Ok(());
            }
        }
    };

    let (new_block_to_archive_sender, new_block_to_archive_receiver) =
        std::sync::mpsc::sync_channel::<Arc<AtomicU32>>(0);
    // Process blocks since last fully archived block (or genesis) up to the current head minus K
    let mut blocks_to_archive_from = archiver
        .last_archived_block_number()
        .map(|n| n + 1)
        .unwrap_or_default();

    // Erasure coding in archiver and piece encoding are CPU-intensive operations.
    tokio::task::spawn_blocking({
        let client = client.clone();
        let weak_plot = weak_plot.clone();

        #[allow(clippy::mut_range_bound)]
        move || {
            let runtime_handle = tokio::runtime::Handle::current();
            info!("Plotting new blocks in the background");

            'outer: while let Ok(blocks_to_archive_to) = new_block_to_archive_receiver.recv() {
                let blocks_to_archive_to = blocks_to_archive_to.load(Ordering::Relaxed);
                if blocks_to_archive_to >= blocks_to_archive_from {
                    debug!(
                        "Archiving blocks {}..={}",
                        blocks_to_archive_from, blocks_to_archive_to,
                    );
                }

                for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                    let EncodedBlockWithObjectMapping {
                        block,
                        object_mapping,
                    } = match runtime_handle.block_on(client.block_by_number(block_to_archive)) {
                        Ok(Some(block)) => block,
                        Ok(None) => {
                            error!(
                                "Failed to get block #{} from RPC: Block not found",
                                block_to_archive,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                        Err(error) => {
                            error!(
                                "Failed to get block #{} from RPC: {}",
                                block_to_archive, error,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                    };

                    let mut last_root_block = None;
                    for archived_segment in archiver.add_block(block, object_mapping) {
                        let ArchivedSegment {
                            root_block,
                            mut pieces,
                            object_mapping,
                        } = archived_segment;
                        let piece_index_offset = merkle_num_leaves * root_block.segment_index();

                        let object_mapping =
                            create_global_object_mapping(piece_index_offset, object_mapping);

                        // TODO: Batch encoding
                        for (position, piece) in pieces.iter_mut().enumerate() {
                            if let Err(error) =
                                subspace_solving.encode(piece_index_offset + position as u64, piece)
                            {
                                error!("Failed to encode a piece: error: {}", error);
                                continue;
                            }
                        }

                        if let Some(plot) = weak_plot.upgrade() {
                            let pieces = Arc::new(pieces);
                            // TODO: There is no internal mapping between pieces and their indexes yet
                            // TODO: Then we might want to send indexes as a separate vector
                            if let Err(error) = runtime_handle
                                .block_on(plot.write_many(Arc::clone(&pieces), piece_index_offset))
                            {
                                error!("Failed to write encoded pieces: {}", error);
                            }
                            if let Err(error) = runtime_handle.block_on(
                                commitments.create_for_pieces(&pieces, piece_index_offset),
                            ) {
                                error!("Failed to create commitments for pieces: {}", error);
                            }
                            if let Err(error) = object_mappings.store(&object_mapping) {
                                error!("Failed to store object mappings for pieces: {}", error);
                            }

                            let segment_index = root_block.segment_index();
                            last_root_block.replace(root_block);

                            info!(
                                "Archived segment {} at block {}",
                                segment_index, block_to_archive
                            );
                        }
                    }

                    if let Some(last_root_block) = last_root_block {
                        if let Some(plot) = weak_plot.upgrade() {
                            if let Err(error) =
                                runtime_handle.block_on(plot.set_last_root_block(&last_root_block))
                            {
                                error!("Failed to store last root block: {:?}", error);
                            }
                        }
                    }
                }

                blocks_to_archive_from = blocks_to_archive_to + 1;
            }
        }
    });

    info!("Subscribing to new heads");
    let mut new_head = client.subscribe_new_head().await?;

    let block_to_archive = Arc::new(AtomicU32::default());

    // Listen for new blocks produced on the network
    while let Some(head) = new_head.next().await? {
        // Numbers are in the format `0xabcd`, so strip `0x` prefix and interpret the rest as an
        // integer in hex
        let block_number = u32::from_str_radix(&head.number[2..], 16).unwrap();
        debug!("Last block number: {:#?}", block_number);

        if let Some(block) = block_number.checked_sub(confirmation_depth_k) {
            // We send block that should be archived over channel that doesn't have a buffer, atomic
            // integer is used to make sure archiving process always read up to date value
            block_to_archive.store(block, Ordering::Relaxed);
            let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
        }
    }

    Ok(())
}

fn create_global_object_mapping(
    piece_index_offset: u64,
    object_mapping: Vec<PieceObjectMapping>,
) -> Vec<(Sha256Hash, GlobalObject)> {
    object_mapping
        .iter()
        .enumerate()
        .flat_map(move |(position, object_mapping)| {
            object_mapping.objects.iter().map(move |piece_object| {
                let PieceObject::V0 { hash, offset } = piece_object;
                (
                    *hash,
                    GlobalObject::V0 {
                        piece_index: piece_index_offset + position as u64,
                        offset: *offset,
                    },
                )
            })
        })
        .collect()
}
