//! Module with callbacks related to plotting pieces. It will:
//! * encode pieces
//! * write them to the plot
//! * update commitments accordingly to change in piece set

#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::plot::Plot;
use crate::rpc_client::{SegmentPipelineEvent, SegmentPipelineEventSender};
use crate::PiecesToPlot;
use log::error;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, PieceIndex, PIECE_SIZE};
use subspace_solving::{BatchEncodeError, SubspaceCodec};

/// Generates a function that will plot pieces.
pub fn plot_pieces(
    mut subspace_codec: SubspaceCodec,
    plot: &Plot,
    commitments: Commitments,
) -> impl FnMut(PiecesToPlot, &'_ SegmentPipelineEventSender) -> bool + Send + 'static {
    let weak_plot = plot.downgrade();

    move |pieces_to_plot, segment_pipeline_event_sender| {
        if let Some(plot) = weak_plot.upgrade() {
            if let Err(error) = plot_pieces_internal(
                &mut subspace_codec,
                &plot,
                &commitments,
                pieces_to_plot.piece_index_offset,
                pieces_to_plot.pieces,
                segment_pipeline_event_sender,
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
    segment_pipeline_event_sender: &'_ SegmentPipelineEventSender,
) -> Result<(), BatchEncodeError> {
    let piece_indexes = (piece_index_offset..)
        .take(pieces.count())
        .collect::<Vec<PieceIndex>>();
    let pieces_amount = pieces.len() as u64 / PIECE_SIZE as u64;

    subspace_codec.batch_encode(&mut pieces, &piece_indexes)?;
    segment_pipeline_event_sender.send(SegmentPipelineEvent::encoded(
        piece_index_offset,
        pieces_amount,
    ));

    let pieces = Arc::new(pieces);

    match plot.write_many(Arc::clone(&pieces), piece_indexes) {
        Ok(write_result) => {
            segment_pipeline_event_sender.send(SegmentPipelineEvent::writen_to_plot(
                piece_index_offset,
                pieces_amount,
            ));
            if let Err(error) = commitments.remove_pieces(write_result.evicted_pieces()) {
                error!("Failed to remove old commitments for pieces: {}", error);
            }
            segment_pipeline_event_sender.send(SegmentPipelineEvent::evicted_pieces(
                piece_index_offset,
                pieces_amount,
            ));

            if let Err(error) =
                commitments.create_for_pieces(|| write_result.to_recommitment_iterator())
            {
                error!("Failed to create commitments for pieces: {}", error);
            }
            segment_pipeline_event_sender.send(SegmentPipelineEvent::created_commitments(
                piece_index_offset,
                pieces_amount,
            ));
        }
        Err(error) => error!("Failed to write encoded pieces: {}", error),
    }

    Ok(())
}
