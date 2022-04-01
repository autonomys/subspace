#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc::RpcClient;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::{ArchivedSegment, Archiver};
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::{PieceIndex, Sha256Hash};
use subspace_rpc_primitives::{EncodedBlockWithObjectMapping, FarmerMetadata};
use subspace_solving::SubspaceCodec;
use thiserror::Error;
use tokio::sync::oneshot::Receiver;
use tokio::{sync::oneshot, task::JoinHandle};

const BEST_BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum PlottingError {
    #[error("Plot is empty on restart, can't continue")]
    ContinueError,
    #[error("Failed to get block {0} from the chain, probably need to erase existing plot")]
    GetBlockError(u32),
    #[error("jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Last block retrieval from plot, rocksdb error: {0}")]
    LastBlock(rocksdb::Error),
    #[error("Error joining task: {0}")]
    JoinTask(tokio::task::JoinError),
    #[error("Archiver instantiation error: {0}")]
    Archiver(subspace_archiving::archiver::ArchiverInstantiationError),
}
/// `Plotting` struct is the abstraction of the plotting process
///
/// Plotting Instance that stores a channel to stop/pause the background farming task
/// and a handle to make it possible to wait on this background task
pub struct Plotting {
    stop_sender: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Result<(), PlottingError>>>,
}

pub struct FarmerData {
    plot: Plot,
    commitments: Commitments,
    object_mappings: ObjectMappings,
    metadata: FarmerMetadata,
}

impl FarmerData {
    pub fn new(
        plot: Plot,
        commitments: Commitments,
        object_mappings: ObjectMappings,
        metadata: FarmerMetadata,
    ) -> Self {
        Self {
            plot,
            commitments,
            object_mappings,
            metadata,
        }
    }
}

/// Assumes `plot`, `commitment`, `object_mappings`, `client` and `identity` are already initialized
impl Plotting {
    /// Returns an instance of plotting, and also starts a concurrent background plotting task
    pub fn start<T: RpcClient + Clone + Send + Sync + 'static>(
        farmer_data: FarmerData,
        client: T,
        subspace_codec: SubspaceCodec,
        best_block_number_check_interval: Duration,
    ) -> Self {
        // Oneshot channels, that will be used for interrupt/stop the process
        let (stop_sender, stop_receiver) = oneshot::channel();

        // Get a handle for the background task, so that we can wait on it later if we want to
        let plotting_handle = tokio::spawn(background_plotting(
            farmer_data,
            client,
            subspace_codec,
            best_block_number_check_interval,
            stop_receiver,
        ));

        Plotting {
            stop_sender: Some(stop_sender),
            handle: Some(plotting_handle),
        }
    }

    /// Waits for the background plotting to finish
    pub async fn wait(mut self) -> Result<(), PlottingError> {
        self.handle
            .take()
            .unwrap()
            .await
            .map_err(PlottingError::JoinTask)?
    }
}

impl Drop for Plotting {
    fn drop(&mut self) {
        let _ = self.stop_sender.take().unwrap().send(());
    }
}

// TODO: Blocks that are coming form substrate node are fully trusted right now, which we probably
//  don't want eventually
/// Maintains plot in up to date state plotting new pieces as they are produced on the network.
async fn background_plotting<T: RpcClient + Clone + Send + 'static>(
    farmer_data: FarmerData,
    client: T,
    mut subspace_codec: SubspaceCodec,
    best_block_number_check_interval: Duration,
    mut stop_receiver: Receiver<()>,
) -> Result<(), PlottingError> {
    let weak_plot = farmer_data.plot.downgrade();
    let FarmerMetadata {
        confirmation_depth_k,
        record_size,
        recorded_history_segment_size,
        ..
    } = farmer_data.metadata;

    // TODO: This assumes fixed size segments, which might not be the case
    let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

    let maybe_last_root_block = tokio::task::spawn_blocking({
        let plot = farmer_data.plot.clone();

        move || plot.get_last_root_block().map_err(PlottingError::LastBlock)
    })
    .await
    .unwrap()?;

    let mut archiver = if let Some(last_root_block) = maybe_last_root_block {
        // Continuing from existing initial state
        if farmer_data.plot.is_empty() {
            return Err(PlottingError::ContinueError);
        }

        let last_archived_block_number = last_root_block.last_archived_block().number;
        info!("Last archived block {}", last_archived_block_number);

        let maybe_last_archived_block = client
            .block_by_number(last_archived_block_number)
            .await
            .map_err(PlottingError::RpcError)?;

        match maybe_last_archived_block {
            Some(EncodedBlockWithObjectMapping {
                block,
                object_mapping,
            }) => Archiver::with_initial_state(
                record_size as usize,
                recorded_history_segment_size as usize,
                last_root_block,
                &block,
                object_mapping,
            )
            .map_err(PlottingError::Archiver)?,
            None => {
                return Err(PlottingError::GetBlockError(last_archived_block_number));
            }
        }
    } else {
        // Starting from genesis
        if !farmer_data.plot.is_empty() {
            // Restart before first block was archived, erase the plot
            // TODO: Erase plot
        }

        drop(farmer_data.plot);

        Archiver::new(record_size as usize, recorded_history_segment_size as usize)
            .map_err(PlottingError::Archiver)?
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

            'outer: for blocks_to_archive_to in new_block_to_archive_receiver.into_iter() {
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

                        // TODO: Batch encoding with more than 1 archived segment worth of data
                        if let Some(plot) = weak_plot.upgrade() {
                            let piece_indexes = (piece_index_offset..)
                                .take(pieces.count())
                                .collect::<Vec<PieceIndex>>();

                            if let Err(error) =
                                subspace_codec.batch_encode(&mut pieces, &piece_indexes)
                            {
                                error!("Failed to encode a piece: error: {}", error);
                                continue;
                            }
                            let pieces = Arc::new(pieces);

                            match plot.write_many(Arc::clone(&pieces), piece_indexes) {
                                Ok(write_result) => {
                                    if let Err(error) = farmer_data
                                        .commitments
                                        .remove_pieces(write_result.evicted_pieces())
                                    {
                                        error!(
                                            "Failed to remove old commitments for pieces: {}",
                                            error
                                        );
                                    }

                                    // TODO: This will not create commitments properly if pieces are
                                    //  evicted during plotting
                                    if let Err(error) =
                                        farmer_data.commitments.create_for_pieces(|| {
                                            write_result.to_recommitment_iterator()
                                        })
                                    {
                                        error!(
                                            "Failed to create commitments for pieces: {}",
                                            error
                                        );
                                    }
                                }
                                Err(error) => error!("Failed to write encoded pieces: {}", error),
                            }
                            if let Err(error) = farmer_data.object_mappings.store(&object_mapping) {
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
                            if let Err(error) = plot.set_last_root_block(&last_root_block) {
                                error!("Failed to store last root block: {}", error);
                            }
                        }
                    }
                }

                blocks_to_archive_from = blocks_to_archive_to + 1;
            }
        }
    });

    info!("Subscribing to new heads");
    let mut new_head = client
        .subscribe_new_head()
        .await
        .map_err(PlottingError::RpcError)?;

    let block_to_archive = Arc::new(AtomicU32::default());

    if maybe_last_root_block.is_none() {
        // If not continuation, archive genesis block
        new_block_to_archive_sender
            .send(Arc::clone(&block_to_archive))
            .expect("Failed to send genesis block archiving message");
    }

    let (mut best_block_number_sender, mut best_block_number_receiver) = mpsc::channel(1);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(best_block_number_check_interval).await;

            // In case connection dies, we need to disconnect from the node
            let best_block_number_result =
                tokio::time::timeout(BEST_BLOCK_REQUEST_TIMEOUT, client.best_block_number()).await;

            let is_error = !matches!(best_block_number_result, Ok(Ok(_)));
            // Result doesn't matter here
            let _ = best_block_number_sender
                .send(best_block_number_result)
                .await;

            if is_error {
                break;
            }
        }
    });

    let mut last_best_block_number_error = false;

    // Listen for new blocks produced on the network
    loop {
        tokio::select! {
            _ = &mut stop_receiver => {
                info!("Plotting stopped!");
                break;
            }
            result = new_head.recv() => {
                match result {
                    Some(head) => {
                        let block_number = u32::from_str_radix(&head.number[2..], 16).unwrap();
                        debug!("Last block number: {:#?}", block_number);

                        if let Some(block_number) = block_number.checked_sub(confirmation_depth_k) {
                            // We send block that should be archived over channel that doesn't have
                            // a buffer, atomic integer is used to make sure archiving process
                            // always read up to date value
                            block_to_archive.store(block_number, Ordering::Relaxed);
                            let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
                        }
                    },
                    None => {
                        debug!("Subscription has forcefully closed from node side!");
                        break;
                    }
                }
            }
            maybe_result = best_block_number_receiver.next() => {
                match maybe_result {
                    Some(Ok(Ok(best_block_number))) => {
                        debug!("Best block number: {:#?}", best_block_number);
                        last_best_block_number_error = false;

                        if let Some(block_number) = best_block_number.checked_sub(confirmation_depth_k) {
                            // We send block that should be archived over channel that doesn't have
                            // a buffer, atomic integer is used to make sure archiving process
                            // always read up to date value
                            block_to_archive.fetch_max(block_number, Ordering::Relaxed);
                            let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
                        }
                    }
                    Some(Ok(Err(error))) => {
                        if last_best_block_number_error {
                            error!("Request to get new best block failed second time: {error}");
                            break;
                        } else {
                            warn!("Request to get new best block failed: {error}");
                            last_best_block_number_error = true;
                        }
                    }
                    Some(Err(_error)) => {
                        if last_best_block_number_error {
                            error!("Request to get new best block timed out second time");
                            break;
                        } else {
                            warn!("Request to get new best block timed out");
                            last_best_block_number_error = true;
                        }
                    }
                    None => {
                        debug!("Best block number channel closed!");
                        break;
                    }
                }
            }
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
