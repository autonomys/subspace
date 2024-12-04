use crate::PieceGetter;
use futures::StreamExt;
use subspace_archiving::piece_reconstructor::{PiecesReconstructor, ReconstructorError};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{
    ArchivedHistorySegment, RecordedHistorySegment, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, error, info};

#[derive(Debug, Error)]
pub(crate) enum SegmentReconstructionError {
    /// Not enough pieces to reconstruct a segment
    #[error("Not enough pieces to reconstruct a segment")]
    NotEnoughPiecesAcquired,

    /// Internal piece retrieval process failed
    #[error("Piece reconstruction failed: {0}")]
    ReconstructionFailed(#[from] ReconstructorError),

    /// Internal piece retrieval process failed
    #[error("Pieces retrieval failed: {0}")]
    PieceRetrievalFailed(#[from] anyhow::Error),

    /// Join error
    #[error("Join error: {0}")]
    JoinError(#[from] JoinError),
}

/// Downloads pieces of the segment such that segment can be reconstructed afterward, prefers source
/// pieces
pub(super) async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Result<Vec<Option<Piece>>, SegmentReconstructionError>
where
    PG: PieceGetter + Send + Sync,
{
    let required_pieces_number = RecordedHistorySegment::NUM_RAW_RECORDS;
    let mut received_pieces = 0_usize;

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];

    let mut pieces_iter = segment_index
        .segment_piece_indexes_source_first()
        .into_iter();

    // Download in batches until we get enough or exhaust available pieces
    while !pieces_iter.is_empty() && received_pieces != required_pieces_number {
        let piece_indices = pieces_iter
            .by_ref()
            .take(required_pieces_number - received_pieces);

        let mut received_segment_pieces = piece_getter.get_pieces(piece_indices).await?;

        while let Some((piece_index, result)) = received_segment_pieces.next().await {
            match result {
                Ok(Some(piece)) => {
                    received_pieces += 1;
                    segment_pieces
                        .get_mut(piece_index.position() as usize)
                        .expect("Piece position is by definition within segment; qed")
                        .replace(piece);
                }
                Ok(None) => {
                    debug!(%piece_index, "Piece was not found");
                }
                Err(error) => {
                    debug!(%error, %piece_index, "Failed to get piece");
                }
            }
        }
    }

    if received_pieces < required_pieces_number {
        error!(
            %segment_index,
            %received_pieces,
            %required_pieces_number,
            "Failed to retrieve pieces for segment"
        );

        return Err(SegmentReconstructionError::NotEnoughPiecesAcquired);
    }

    Ok(segment_pieces)
}

pub(crate) async fn recover_missing_piece<PG>(
    piece_getter: &PG,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    missing_piece_index: PieceIndex,
) -> Result<Piece, SegmentReconstructionError>
where
    PG: PieceGetter + Send + Sync,
{
    info!(%missing_piece_index, "Recovering missing piece...");
    let segment_index = missing_piece_index.segment_index();
    let position = missing_piece_index.position();

    let segment_pieces = download_segment_pieces(segment_index, piece_getter).await?;

    let result = tokio::task::spawn_blocking(move || {
        let reconstructor = PiecesReconstructor::new(kzg, erasure_coding);

        reconstructor.reconstruct_piece(&segment_pieces, position as usize)
    })
    .await??;

    info!(%missing_piece_index, "Recovering missing piece succeeded.");

    Ok(result)
}
