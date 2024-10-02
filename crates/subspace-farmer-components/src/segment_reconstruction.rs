use crate::PieceGetter;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use subspace_archiving::piece_reconstructor::{PiecesReconstructor, ReconstructorError};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{ArchivedHistorySegment, RecordedHistorySegment};
use subspace_erasure_coding::ErasureCoding;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinError;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Error)]
pub(crate) enum SegmentReconstructionError {
    /// Not enough pieces to reconstruct a segment
    #[error("Not enough pieces to reconstruct a segment")]
    NotEnoughPiecesAcquired,

    /// Internal piece retrieval process failed
    #[error("Pieces retrieval failed")]
    PieceRetrievalFailed(#[from] ReconstructorError),

    /// Join error
    #[error("Join error: {0}")]
    JoinError(#[from] JoinError),
}

pub(crate) async fn recover_missing_piece<PG: PieceGetter>(
    piece_getter: &PG,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    missing_piece_index: PieceIndex,
) -> Result<Piece, SegmentReconstructionError> {
    info!(%missing_piece_index, "Recovering missing piece...");
    let segment_index = missing_piece_index.segment_index();
    let position = missing_piece_index.position();

    let semaphore = &Semaphore::new(RecordedHistorySegment::NUM_RAW_RECORDS);
    let acquired_pieces_counter = &AtomicUsize::default();
    let required_pieces_number = RecordedHistorySegment::NUM_RAW_RECORDS;

    let mut received_segment_pieces = segment_index
        .segment_piece_indexes()
        .map(|piece_index| async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(error) => {
                    warn!(
                        %piece_index,
                        %error,
                        "Semaphore was closed, interrupting piece recover..."
                    );
                    return None;
                }
            };

            if acquired_pieces_counter.load(Ordering::SeqCst) >= required_pieces_number {
                trace!(%piece_index, "Skipped piece acquiring.");

                return None;
            }

            let piece = piece_getter.get_piece(piece_index).await;

            match piece {
                Ok(piece) => {
                    if let Some(piece) = piece {
                        acquired_pieces_counter.fetch_add(1, Ordering::SeqCst);

                        Some((piece_index, piece))
                    } else {
                        None
                    }
                }
                Err(error) => {
                    debug!(?error, %piece_index, "Failed to get piece");
                    None
                }
            }
        })
        .into_iter()
        .collect::<FuturesOrdered<_>>();

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];
    while let Some(maybe_received_piece) = received_segment_pieces.next().await {
        if let Some((piece_index, received_piece)) = maybe_received_piece {
            segment_pieces
                .get_mut(piece_index.position() as usize)
                .expect("Piece position is by definition within segment; qed")
                .replace(received_piece);
        }
    }

    let received_pieces = acquired_pieces_counter.load(Ordering::SeqCst);
    if received_pieces < required_pieces_number {
        error!(
            %missing_piece_index,
            %received_pieces,
            %required_pieces_number,
            "Recovering missing piece failed."
        );

        return Err(SegmentReconstructionError::NotEnoughPiecesAcquired);
    }

    let result = tokio::task::spawn_blocking(move || {
        let reconstructor = PiecesReconstructor::new(kzg, erasure_coding);

        reconstructor.reconstruct_piece(&segment_pieces, position as usize)
    })
    .await??;

    info!(%missing_piece_index, "Recovering missing piece succeeded.");

    Ok(result)
}
