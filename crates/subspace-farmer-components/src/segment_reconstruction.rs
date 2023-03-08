use crate::plotting::{PieceGetter, PieceGetterRetryPolicy};
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    kzg: Kzg,
    missing_piece_index: PieceIndex,
) -> Result<Piece, SegmentReconstructionError> {
    info!(%missing_piece_index, "Recovering missing piece...");
    let segment_index: SegmentIndex = missing_piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);

    let starting_piece_index: PieceIndex = segment_index * SegmentIndex::from(PIECES_IN_SEGMENT);

    let semaphore = Semaphore::new(PARALLELISM_LEVEL);
    let acquired_pieces_counter = AtomicUsize::default();
    let required_pieces_number = PIECES_IN_SEGMENT / 2;

    // This is so we can move references into the future below
    let semaphore = &semaphore;
    let acquired_pieces_counter = &acquired_pieces_counter;

    let pieces = (starting_piece_index..)
        .take(PIECES_IN_SEGMENT as usize)
        .map(|piece_index| async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(error) => {
                    warn!(
                        piece_index,
                        %error,
                        "Semaphore was closed, interrupting piece recover..."
                    );
                    return None;
                }
            };

            if acquired_pieces_counter.load(Ordering::SeqCst) >= required_pieces_number as usize {
                trace!(piece_index, "Skipped piece acquiring.");

                return None;
            }

            let piece = piece_getter
                .get_piece(piece_index, PieceGetterRetryPolicy::Limited(0))
                .await;

            match piece {
                Ok(piece) => {
                    if piece.is_some() {
                        acquired_pieces_counter.fetch_add(1, Ordering::SeqCst);
                    }

                    piece
                }
                Err(error) => {
                    debug!(?error, piece_index, "Failed to get piece");
                    None
                }
            }
        })
        .collect::<FuturesOrdered<_>>()
        .collect::<Vec<Option<Piece>>>()
        .await;

    if acquired_pieces_counter.load(Ordering::SeqCst) < required_pieces_number as usize {
        error!(%missing_piece_index, "Recovering missing piece failed.");

        return Err(SegmentReconstructionError::NotEnoughPiecesAcquired);
    }

    let archiver = PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg)
        .expect("Internal constructor call must succeed.");

    let position = (missing_piece_index - starting_piece_index) as usize;

    let result = archiver.reconstruct_piece(&pieces, position)?;

    info!(%missing_piece_index, "Recovering missing piece succeeded.");

    Ok(result)
}
