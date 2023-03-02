use std::iter;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::StreamExt;
use subspace_core_primitives::{Piece, PieceIndex, SegmentIndex, PIECES_IN_SEGMENT, RECORD_SIZE};
use subspace_farmer_components::plotting::PieceGetter;
use tracing::{error, info};
use subspace_archiving::reconstructor::Reconstructor;

const SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

pub struct SegmentReconstruction<PG> {
    piece_getter: PG,
}

impl<PG: PieceGetter> SegmentReconstruction<PG> {
    pub fn new(piece_getter: PG) -> Self {
        Self { piece_getter }
    }

    pub async fn get_missing_piece(&self, missing_piece_index: PieceIndex) -> Option<Piece> {
        let segment_index: SegmentIndex =
            missing_piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);

        // TODO: Consider taking more pieces here.
        // We take minimum pieces to reconstruct the segment plus one to mitigate the missing piece.
        let pieces_to_retrieve = (PIECES_IN_SEGMENT / 2 + 1) as usize;

        let starting_piece_index = segment_index * SegmentIndex::from(PIECES_IN_SEGMENT);

        let piece_offset = (missing_piece_index - starting_piece_index) as usize; // TODO:
        info!(%missing_piece_index, %starting_piece_index, %pieces_to_retrieve, %piece_offset);

        let piece_indexes = (starting_piece_index..)
            .take(pieces_to_retrieve)
            .collect::<Vec<_>>();

        let mut piece_requests = piece_indexes
            .iter()
            .map(|piece_index| self.piece_getter.get_piece(*piece_index))
            .collect::<FuturesOrdered<_>>();

        let mut pieces = iter::repeat(None).take(PIECES_IN_SEGMENT as usize).collect::<Vec<Option<Piece>>>();
        let mut piece_index: usize = 0;
        while let Some(piece_response) = piece_requests.next().await {
            match piece_response {
                Ok(piece) => {
                    pieces[piece_index] = piece;
                    piece_index += 1;
                } ,
                Err(err) => {
                    error!(?err, "Piece getter failed.");

                    // TODO: Consider taking extra pieces to not fail on the first error.
                    return None;
                }
            }
        }

        info!(some_piece_number=%pieces.iter().fold(0, |acc, item| {
            acc + item.clone().map(|_| 1).unwrap_or_default()
        }));

        //TODO:
        let mut archiver = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

        //TODO:
        let result = archiver.retrieve_pieces(&pieces).unwrap();

        let piece_offset = (missing_piece_index - starting_piece_index) as usize;

        Is it existing piece from the collection or reconstructed piece?

            Double check by removing the piece from the collection.
        let piece = result[piece_offset].clone();


        piece
    }
}
