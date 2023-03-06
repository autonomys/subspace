use crate::plotting::{PieceGetter, PieceGetterRetryPolicy};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::iter;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use subspace_archiving::piece_reconstructor::{PiecesReconstructor, ReconstructorError};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, SegmentIndex, PIECES_IN_SEGMENT, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, trace, warn};

const PARALLELISM_LEVEL: usize = 20;

#[derive(Debug, Error)]
pub enum SegmentReconstructionError {
    /// Not enough pieces to reconstruct a segment
    #[error("Not enough pieces to reconstruct a segment")]
    NotEnoughPiecesAcquired,

    /// Internal piece retrieval process failed
    #[error("Pieces retrieval failed")]
    PieceRetrievalFailed(#[from] ReconstructorError),
}

pub async fn recover_missing_piece<PG: PieceGetter>(
    piece_getter: &PG,
    kzg: &Kzg,
    missing_piece_index: PieceIndex,
) -> Result<Piece, SegmentReconstructionError> {
    info!(%missing_piece_index, "Recovering missing piece...");
    let segment_index: SegmentIndex = missing_piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);

    let starting_piece_index = segment_index * SegmentIndex::from(PIECES_IN_SEGMENT);

    let piece_indexes = (starting_piece_index..)
        .take(PIECES_IN_SEGMENT as usize)
        .collect::<Vec<_>>();

    let semaphore = Arc::new(Semaphore::new(PARALLELISM_LEVEL));
    let acquired_pieces_counter = AtomicUsize::default();
    let required_pieces_number = PIECES_IN_SEGMENT / 2;

    let mut piece_requests = piece_indexes
        .iter()
        .map(|piece_index| async {
            let _permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    warn!(
                        piece_index=*piece_index,
                        %error,
                        "Semaphore was closed, interrupting piece recover..."
                    );
                    return (*piece_index, Ok(None));
                }
            };

            if acquired_pieces_counter.load(Ordering::Relaxed) >= required_pieces_number as usize {
                trace!(piece_index = *piece_index, "Skipped piece acquiring.");

                return (*piece_index, Ok(None));
            }

            let piece = piece_getter
                .get_piece(*piece_index, PieceGetterRetryPolicy::NoRetry)
                .await;

            if let Ok(piece) = &piece {
                if piece.is_some() {
                    acquired_pieces_counter.fetch_add(1, Ordering::Relaxed);
                }
            }

            (*piece_index, piece)
        })
        .collect::<FuturesUnordered<_>>();

    let mut pieces = iter::repeat(None)
        .take(PIECES_IN_SEGMENT as usize)
        .collect::<Vec<Option<Piece>>>();

    while let Some(piece_response) = piece_requests.next().await {
        match piece_response.1 {
            Ok(piece) => {
                let piece_index = piece_response.0;
                let position = (piece_index - starting_piece_index) as usize;
                pieces[position] = piece;
            }
            Err(err) => {
                debug!(?err, "Piece getter failed.");
            }
        }
    }

    let collected_piece_count = pieces.iter().filter(|piece| piece.is_some()).count();
    if collected_piece_count < required_pieces_number as usize {
        error!(%missing_piece_index, "Recovering missing piece failed.");

        return Err(SegmentReconstructionError::NotEnoughPiecesAcquired);
    }

    let archiver =
        PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone())
            .expect("Internal constructor call must succeed.");

    let position = (missing_piece_index - starting_piece_index) as usize;

    let result = archiver.reconstruct_piece(&pieces, position)?;

    info!(%missing_piece_index, "Recovering missing piece succeeded.");

    Ok(result)
}
