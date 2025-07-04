use subspace_archiving::piece_reconstructor::{PiecesReconstructor, ReconstructorError};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_data_retrieval::segment_downloading::{
    SEGMENT_DOWNLOAD_RETRIES, SEGMENT_DOWNLOAD_RETRY_DELAY, SegmentDownloadingError,
    download_segment_pieces,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{error, info};

#[derive(Debug, Error)]
pub(crate) enum SegmentReconstructionError {
    /// Segment downloading failed
    #[error("Segment downloading failed: {0}")]
    SegmentDownloadingFailed(#[from] SegmentDownloadingError),

    /// Internal piece retrieval process failed
    #[error("Piece reconstruction failed: {0}")]
    ReconstructionFailed(#[from] ReconstructorError),

    /// Join error
    #[error("Join error: {0}")]
    JoinError(#[from] JoinError),
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

    let segment_pieces = download_segment_pieces(
        segment_index,
        piece_getter,
        SEGMENT_DOWNLOAD_RETRIES,
        Some(SEGMENT_DOWNLOAD_RETRY_DELAY),
    )
    .await?;

    let result = tokio::task::spawn_blocking(move || {
        let reconstructor = PiecesReconstructor::new(kzg, erasure_coding);

        reconstructor.reconstruct_piece(&segment_pieces, position as usize)
    })
    .await??;

    info!(%missing_piece_index, "Recovering missing piece succeeded.");

    Ok(result)
}
