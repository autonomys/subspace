#[cfg(test)]
mod tests;

use crate::archiving::{self, ArchivedBlock};
use crate::commitments::Commitments;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use log::{debug, error, info};
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::{PieceIndex, Sha256Hash};
use subspace_rpc_primitives::FarmerMetadata;
use subspace_solving::SubspaceCodec;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

#[derive(Debug, Error)]
pub enum PlottingError {
    #[error("Last block retrieval from plot, rocksdb error: {0}")]
    LastBlock(rocksdb::Error),
    #[error("Error joining task: {0}")]
    JoinTask(tokio::task::JoinError),
    #[error("Error during archiving start")]
    ArchivingStart(
        #[from]
        #[source]
        archiving::Error,
    ),
}

/// `Plotting` struct is the abstraction of the plotting process
pub struct Plotting {
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
    pub fn start(
        farmer_data: FarmerData,
        subspace_codec: SubspaceCodec,
        archived_blocks_receiver: broadcast::Receiver<ArchivedBlock>,
    ) -> Self {
        // Get a handle for the background task, so that we can wait on it later if we want to
        let plotting_handle = tokio::spawn(background_plotting(
            farmer_data,
            subspace_codec,
            archived_blocks_receiver,
        ));

        Self {
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

// TODO: Blocks that are coming form substrate node are fully trusted right now, which we probably
//  don't want eventually
/// Maintains plot in up to date state plotting new pieces as they are produced on the network.
async fn background_plotting(
    farmer_data: FarmerData,
    mut subspace_codec: SubspaceCodec,
    mut archived_blocks_receiver: broadcast::Receiver<ArchivedBlock>,
) -> Result<(), PlottingError> {
    let weak_plot = farmer_data.plot.downgrade();
    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        ..
    } = farmer_data.metadata;

    // TODO: This assumes fixed size segments, which might not be the case
    let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

    // Erasure coding in archiver and piece encoding are CPU-intensive operations.
    tokio::task::spawn_blocking({
        let weak_plot = weak_plot.clone();

        move || {
            info!("Plotting new blocks in the background");
            let handle = tokio::runtime::Handle::current();

            loop {
                let ArchivedBlock { number, segments } =
                    match handle.block_on(archived_blocks_receiver.recv()) {
                        Ok(block) => block,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            debug!("Skipped {n} blocks");
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    };
                let mut last_root_block = None;

                for segment in segments {
                    let ArchivedSegment {
                        root_block,
                        mut pieces,
                        object_mapping,
                    } = segment;
                    let piece_index_offset = merkle_num_leaves * root_block.segment_index();

                    let object_mapping =
                        create_global_object_mapping(piece_index_offset, object_mapping);

                    // TODO: Batch encoding with more than 1 archived segment worth of data
                    if let Some(plot) = weak_plot.upgrade() {
                        let piece_indexes = (piece_index_offset..)
                            .take(pieces.count())
                            .collect::<Vec<PieceIndex>>();

                        if let Err(error) = subspace_codec.batch_encode(&mut pieces, &piece_indexes)
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
                                if let Err(error) = farmer_data
                                    .commitments
                                    .create_for_pieces(|| write_result.to_recommitment_iterator())
                                {
                                    error!("Failed to create commitments for pieces: {}", error);
                                }
                            }
                            Err(error) => error!("Failed to write encoded pieces: {}", error),
                        }
                        if let Err(error) = farmer_data.object_mappings.store(&object_mapping) {
                            error!("Failed to store object mappings for pieces: {}", error);
                        }
                        let segment_index = root_block.segment_index();
                        last_root_block.replace(root_block);

                        info!("Archived segment {} at block {}", segment_index, number);
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
        }
    });

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
