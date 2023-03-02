use futures::stream::FuturesOrdered;
use futures::StreamExt;
use std::iter;
use subspace_archiving::piece_reconstructor::{PieceReconstructorError, PiecesReconstructor};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, SegmentIndex, PIECES_IN_SEGMENT, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_farmer_components::plotting::PieceGetter;
use thiserror::Error;
use tracing::error;

pub struct SegmentReconstruction<PG> {
    piece_getter: PG,
    kzg: Kzg,
}

#[derive(Debug, Error)]
pub enum SegmentReconstructionError {
    /// Not enough pieces to reconstruct a segment
    #[error("Not enough pieces to reconstruct a segment")]
    NotEnoughPiecesAcquired,

    /// Internal piece retrieval process failed
    #[error("Pieces retrieval failed")]
    PieceRetrievalFailed(#[from] PieceReconstructorError),
}

impl<PG: PieceGetter> SegmentReconstruction<PG> {
    pub fn new(piece_getter: PG, kzg: Kzg) -> Self {
        Self { piece_getter, kzg }
    }

    pub async fn get_missing_piece(
        &self,
        missing_piece_index: PieceIndex,
    ) -> Result<Piece, SegmentReconstructionError> {
        let segment_index: SegmentIndex =
            missing_piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);

        // TODO: Consider taking more pieces here.
        // We take minimum pieces to reconstruct the segment plus one to mitigate the missing piece.
        let pieces_to_retrieve = (PIECES_IN_SEGMENT / 2 + 1) as usize;

        let starting_piece_index = segment_index * SegmentIndex::from(PIECES_IN_SEGMENT);

        let piece_indexes = (starting_piece_index..)
            .take(pieces_to_retrieve)
            .collect::<Vec<_>>();

        let mut piece_requests = piece_indexes
            .iter()
            .map(|piece_index| self.piece_getter.get_piece(*piece_index))
            .collect::<FuturesOrdered<_>>();

        let mut pieces = iter::repeat(None)
            .take(PIECES_IN_SEGMENT as usize)
            .collect::<Vec<Option<Piece>>>();
        let mut piece_index: usize = 0;
        while let Some(piece_response) = piece_requests.next().await {
            match piece_response {
                Ok(piece) => {
                    pieces[piece_index] = piece;
                    piece_index += 1;
                }
                Err(err) => {
                    error!(?err, "Piece getter failed.");

                    // TODO: Consider taking extra pieces to not fail on the first error.
                    return Err(SegmentReconstructionError::NotEnoughPiecesAcquired);
                }
            }
        }

        let archiver =
            PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, self.kzg.clone())
                .expect("Internal constructor call must succeed.");

        let result = archiver.retrieve_pieces(&pieces)?;

        let piece_offset = (missing_piece_index - starting_piece_index) as usize;

        let piece = result[piece_offset].clone();

        Ok(piece)
    }
}
