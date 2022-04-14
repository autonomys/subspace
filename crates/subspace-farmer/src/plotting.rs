//! `Plotting` structure is the abstraction on top of the plotting process on the
//! single replica.
//!
//! Plotting Instance stores a channel to stop/pause the background plotting
//! task and a handle to make it possible to wait on this background task.
//!
//! It does several things.
//!
//! ### Listen for new blocks produced by network
//!
//! In order to plot whole blockchain history we need to receive network updates,
//! for that we regularly ask node for its best block number and after that plot
//! block which is under some confirmation depth constant.
//!
//! TODO: make plotting account for forks
//!
//! ### Archiving blocks
//!
//! After listening for new blocks, we request blocks under some
//! confirmation depth from the best block.
//!
//! This is currently necessary due to implementation challenge where archiving
//! that happens on the node is not waiting for farmer. Also farmer can
//! connect/disconnect from node at any time, thus resulting in farmer potentially
//! missing some of the archived pieces altogether. As such, farmer temporarily has
//! its own archiving process as well. It will eventually be replaced with DNS-based
//! subscriptions where pieces are disseminated by executors.
//!
//! Each of blocks gets passed through the `Archiver::add_block`. It segments
//! block into several segments (each having pieces, objects, and root block).
//!
//! ## Global object mapping
//!
//! After receiving new block we also need to add newly added objects in a block.
//! So we store objects' location by their hash in `ObjectMappings` db.
//!
//! ## Encoding pieces and writing to plot
//!
//! After receiving block, archiving each segment has several raw pieces. Each of
//! those needs to be encoded using time asymmetric permutation
//! `subspace_solving::SubspaceCodec` (wrapper around `sloth256_189`).
//!
//! Then, pieces are written to the `Plot` by their indexes.
//!
//! ## Updating commitments
//!
//! When writing to plot is done, `Plot` returns `WriteResult` which is needed to
//! update the `Commitments` for the consensus puzzle solving. We will just iterate
//! over evicted pieces and remove them. After that we just add new pieces written to
//! the plot.

#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::plot::Plot;
use crate::PiecesToPlot;
use log::error;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, PieceIndex};
use subspace_solving::{BatchEncodeError, SubspaceCodec};

/// Generates a function that will plot pieces.
pub fn plot_pieces(
    mut subspace_codec: SubspaceCodec,
    plot: &Plot,
    commitments: Commitments,
) -> impl FnMut(PiecesToPlot) -> bool + Send + 'static {
    let weak_plot = plot.downgrade();

    move |pieces_to_plot| {
        if let Some(plot) = weak_plot.upgrade() {
            if let Err(error) = plot_pieces_internal(
                &mut subspace_codec,
                &plot,
                &commitments,
                pieces_to_plot.piece_index_offset,
                pieces_to_plot.pieces,
            ) {
                error!("Failed to encode a piece: error: {}", error);
                return false;
            }
        } else {
            return false;
        }

        true
    }
}

/// Plot a set of pieces into a particular plot and commitment database.
fn plot_pieces_internal(
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
