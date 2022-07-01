//! Module with callbacks related to plotting pieces. It will:
//! * encode pieces
//! * write them to the plot
//! * update commitments accordingly to change in piece set

use crate::commitments::Commitments;
use crate::plot::Plot;
use std::sync::Arc;
use subspace_networking::PiecesToPlot;
use subspace_solving::{BatchEncodeError, SubspaceCodec};
use tracing::error;

/// Generates a function that will plot pieces.
pub fn plot_pieces(
    subspace_codec: SubspaceCodec,
    plot: &Plot,
    commitments: Commitments,
) -> impl FnMut(PiecesToPlot) -> bool + Send + 'static {
    let weak_plot = plot.downgrade();

    move |pieces_to_plot| {
        if let Some(plot) = weak_plot.upgrade() {
            if let Err(error) =
                plot_pieces_internal(&subspace_codec, &plot, &commitments, pieces_to_plot)
            {
                error!(%error, "Failed to encode a piece");
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
    subspace_codec: &SubspaceCodec,
    plot: &Plot,
    commitments: &Commitments,
    PiecesToPlot {
        piece_indexes,
        mut pieces,
    }: PiecesToPlot,
) -> Result<(), BatchEncodeError> {
    subspace_codec.batch_encode(&mut pieces, &piece_indexes)?;

    let pieces = Arc::new(pieces);

    match plot.write_many(Arc::clone(&pieces), piece_indexes) {
        Ok(write_result) => {
            if let Err(error) = commitments.remove_pieces(write_result.evicted_pieces()) {
                error!(%error, "Failed to remove old commitments for pieces");
            }

            if let Err(error) =
                commitments.create_for_pieces(|| write_result.to_recommitment_iterator())
            {
                error!(%error, "Failed to create commitments for pieces");
            }
        }
        Err(error) => error!(%error, "Failed to write encoded pieces"),
    }

    Ok(())
}
