#[cfg(test)]
mod tests;

use crate::archiving::PiecesToPlot;
use crate::commitments::Commitments;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc::RpcClient;
use log::error;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{FlatPieces, PieceIndex};
use subspace_rpc_primitives::FarmerMetadata;
use subspace_solving::{BatchEncodeError, SubspaceCodec};
use thiserror::Error;
use tokio::{sync::oneshot, task::JoinHandle};

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
    archiving_handle: Option<JoinHandle<Result<(), PlottingError>>>,
    plotting_handle: Option<JoinHandle<()>>,
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
        mut subspace_codec: SubspaceCodec,
        best_block_number_check_interval: Duration,
    ) -> Self {
        // Oneshot channels, that will be used for interrupt/stop the process
        let (stop_sender, stop_receiver) = oneshot::channel();

        let FarmerData {
            plot,
            commitments,
            object_mappings,
            metadata,
        } = farmer_data;
        let weak_plot = plot.downgrade();

        let (pieces_to_plot_sender, pieces_to_plot_receiver) =
            std::sync::mpsc::sync_channel::<PiecesToPlot>(0);

        // Get a handle for the background task, so that we can wait on it later if we want to
        let archiving_handle = tokio::spawn(crate::archiving::background_archiving(
            pieces_to_plot_sender,
            plot,
            metadata,
            object_mappings,
            client,
            best_block_number_check_interval,
            stop_receiver,
        ));

        // Get a handle for the background task, so that we can wait on it later if we want to
        let plotting_handle = tokio::task::spawn_blocking(move || {
            // TODO: Batch encoding with more than 1 archived segment worth of data
            while let Ok(pieces_to_plot) = pieces_to_plot_receiver.recv() {
                if let Some(plot) = weak_plot.upgrade() {
                    if let Err(error) = plot_pieces(
                        &mut subspace_codec,
                        &plot,
                        &commitments,
                        pieces_to_plot.piece_index_offset,
                        pieces_to_plot.pieces,
                    ) {
                        error!("Failed to encode a piece: error: {}", error);
                        break;
                    }
                }
            }
        });

        Plotting {
            stop_sender: Some(stop_sender),
            archiving_handle: Some(archiving_handle),
            plotting_handle: Some(plotting_handle),
        }
    }

    /// Waits for the background plotting to finish
    pub async fn wait(mut self) -> Result<(), PlottingError> {
        self.archiving_handle
            .take()
            .unwrap()
            .await
            .map_err(PlottingError::JoinTask)??;
        self.plotting_handle
            .take()
            .unwrap()
            .await
            .map_err(PlottingError::JoinTask)
    }
}

impl Drop for Plotting {
    fn drop(&mut self) {
        let _ = self.stop_sender.take().unwrap().send(());
    }
}

/// Plot a set of pieces into a particular plot and commitment database.
fn plot_pieces(
    subspace_codec: &mut SubspaceCodec,
    plot: &Plot,
    commitments: &Commitments,
    piece_index_offset: u64,
    mut pieces: FlatPieces,
) -> Result<(), BatchEncodeError> {
    let piece_indexes = (piece_index_offset..)
        .take(pieces.count())
        .collect::<Vec<PieceIndex>>();

    subspace_codec.batch_encode(&mut pieces, &piece_indexes)?;

    let pieces = Arc::new(pieces);

    match plot.write_many(Arc::clone(&pieces), piece_indexes) {
        Ok(write_result) => {
            if let Err(error) = commitments.remove_pieces(write_result.evicted_pieces()) {
                error!("Failed to remove old commitments for pieces: {}", error);
            }

            if let Err(error) =
                commitments.create_for_pieces(|| write_result.to_recommitment_iterator())
            {
                error!("Failed to create commitments for pieces: {}", error);
            }
        }
        Err(error) => error!("Failed to write encoded pieces: {}", error),
    }

    Ok(())
}
