//! Assumes that the following structs (Identity, Plot, Commitments, ObjectMappings, RpcClient)
//! are initialized, and going to be used in here for the plotting operation.
//! This file is an abstraction of plotting process, which provides:
//! start (for starting the plotting), Drop (stopping the plotting), and on_new_piece
//! (for updating the plotting when a new piece arrives)

use crate::commitments::Commitments;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc::{EncodedBlockWithObjectMapping, FarmerMetadata, RpcClient};
use crate::Identity;
use futures::lock::Mutex;
use log::{error, info};
use proc_macro::error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use subspace_archiving::archiver::{ArchivedSegment, BlockArchiver, ObjectArchiver};
use subspace_archiving::pre_genesis_data;
use subspace_solving::SubspaceCodec;

pub struct Plotting<'a, P: AsRef<[u8]>> {
    plot: Plot,
    commitments: Commitments,
    object_mappings: ObjectMappings,
    client: RpcClient,
    public_key: &'a P,
}

impl Plotting<P> {
    /// assumes front-end will open the plot, commitments, etc...
    /// then call this function to start plotting with the already initialized structs
    pub async fn start(
        plot: Plot,
        commitments: Commitments,
        object_mappings: ObjectMappings,
        client: RpcClient,
        identity: Identity,
    ) -> Result<Self, ()> {
        plotting = Plotting {
            plot: plot.clone(),
            commitments: commitments.clone(),
            object_mappings,
            client: client.clone(),
            public_key: &identity.public_key(),
        };

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

        let public_key = &identity.public_key();

        let subspace_solving = SubspaceCodec::new(public_key);

        let mut archiver = if let Some(last_root_block) = plot.get_last_root_block().await? {
            // Continuing from existing initial state
            if plot.is_empty() {
                return Err(anyhow!("Plot is empty on restart, can't continue",));
            }

            //drop(plot);

            let last_archived_block_number = last_root_block.last_archived_block().number;
            info!("Last archived block {}", last_archived_block_number);

            let maybe_last_archived_block =
                client.block_by_number(last_archived_block_number).await?;

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
                                if let Err(error) = subspace_solving
                                    .encode(piece_index_offset + position as u64, piece)
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
                    return Ok(Plotting);
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

                    let mut last_root_block = None;
                    for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                        let EncodedBlockWithObjectMapping {
                            block,
                            object_mapping,
                        } = match runtime_handle.block_on(client.block_by_number(block_to_archive))
                        {
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
                                if let Err(error) = subspace_solving
                                    .encode(piece_index_offset + position as u64, piece)
                                {
                                    error!("Failed to encode a piece: error: {}", error);
                                    continue;
                                }
                            }

                            if let Some(plot) = weak_plot.upgrade() {
                                let pieces = Arc::new(pieces);
                                // TODO: There is no internal mapping between pieces and their indexes yet
                                // TODO: Then we might want to send indexes as a separate vector
                                if let Err(error) = runtime_handle.block_on(
                                    plot.write_many(Arc::clone(&pieces), piece_index_offset),
                                ) {
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

                    blocks_to_archive_from = blocks_to_archive_to + 1;
                }
            }
        });

        plotting
    }

    pub async fn on_new_piece<C: Fn(u64) + Sync + Send + 'static>(&self, callback: C) {
        // TODO later
    }
}

impl Drop for Plotting<P> {
    fn drop(&mut self) {
        info!("Plotting stopped!");
    }
}
