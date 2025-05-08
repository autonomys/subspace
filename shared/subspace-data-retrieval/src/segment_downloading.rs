//! Fetching segments of the archived history of Subspace Network.

use crate::piece_getter::PieceGetter;
use futures::StreamExt;
use subspace_archiving::archiver::Segment;
use subspace_archiving::reconstructor::{Reconstructor, ReconstructorError};
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::segments::{
    ArchivedHistorySegment, RecordedHistorySegment, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use tokio::task::spawn_blocking;
use tracing::debug;

/// Segment getter errors.
#[derive(Debug, thiserror::Error)]
pub enum SegmentDownloadingError {
    /// Not enough pieces
    #[error(
        "Not enough ({downloaded_pieces}/{}) pieces for segment {segment_index}",
        RecordedHistorySegment::NUM_RAW_RECORDS
    )]
    NotEnoughPieces {
        /// The segment we were trying to download
        segment_index: SegmentIndex,
        /// Number of pieces that were downloaded
        downloaded_pieces: usize,
    },

    /// Piece getter error
    #[error("Piece getter error: {source}")]
    PieceGetterError {
        #[from]
        source: anyhow::Error,
    },

    /// Segment reconstruction error
    #[error("Segment reconstruction error: {source}")]
    SegmentReconstruction {
        #[from]
        source: ReconstructorError,
    },

    /// Segment decoding error
    #[error("Segment data decoding error: {source}")]
    SegmentDecoding {
        #[from]
        source: parity_scale_codec::Error,
    },
}

/// Concurrently downloads the pieces for `segment_index`, and reconstructs the segment.
pub async fn download_segment<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
    erasure_coding: ErasureCoding,
) -> Result<Segment, SegmentDownloadingError>
where
    PG: PieceGetter,
{
    let reconstructor = Reconstructor::new(erasure_coding);

    let segment_pieces = download_segment_pieces(segment_index, piece_getter).await?;

    let segment = spawn_blocking(move || reconstructor.reconstruct_segment(&segment_pieces))
        .await
        .expect("Panic if blocking task panicked")?;

    Ok(segment)
}

/// Downloads pieces of the segment such that segment can be reconstructed afterward.
///
/// Prefers source pieces if available, on error returns number of downloaded pieces.
pub async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Result<Vec<Option<Piece>>, SegmentDownloadingError>
where
    PG: PieceGetter,
{
    let required_pieces_number = RecordedHistorySegment::NUM_RAW_RECORDS;
    let mut downloaded_pieces = 0_usize;

    // Debugging failure patterns in piece downloads
    let mut first_success = None;
    let mut last_success = None;
    let mut first_failure = None;
    let mut last_failure = None;

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];

    let mut pieces_iter = segment_index
        .segment_piece_indexes_source_first()
        .into_iter()
        .peekable();

    // Download in batches until we get enough or exhaust available pieces
    while !pieces_iter.is_empty() && downloaded_pieces != required_pieces_number {
        let piece_indices = pieces_iter
            .by_ref()
            .take(required_pieces_number - downloaded_pieces)
            .collect();

        let mut received_segment_pieces = piece_getter.get_pieces(piece_indices).await?;

        while let Some((piece_index, result)) = received_segment_pieces.next().await {
            match result {
                Ok(Some(piece)) => {
                    downloaded_pieces += 1;
                    segment_pieces
                        .get_mut(piece_index.position() as usize)
                        .expect("Piece position is by definition within segment; qed")
                        .replace(piece);

                    if first_success.is_none() {
                        first_success = Some(piece_index.position());
                    }
                    last_success = Some(piece_index.position());
                }
                // We often see an error where 127 pieces are downloaded successfully, but the
                // other 129 fail. It seems like 1 request in a 128 piece batch fails, then 128
                // single piece requests are made, and also fail.
                // Delaying requests after a failure gives the node a chance to find other peers.
                Ok(None) => {
                    debug!(%piece_index, "Piece was not found");
                    if first_failure.is_none() {
                        first_failure = Some(piece_index.position());
                    }
                    last_failure = Some(piece_index.position());
                }
                Err(error) => {
                    debug!(%error, %piece_index, "Failed to get piece");
                    if first_failure.is_none() {
                        first_failure = Some(piece_index.position());
                    }
                    last_failure = Some(piece_index.position());
                }
            }
        }
    }

    if downloaded_pieces < required_pieces_number {
        debug!(
            %segment_index,
            %downloaded_pieces,
            %required_pieces_number,
            // Piece positions that succeeded/failed
            ?first_success,
            ?last_success,
            ?first_failure,
            ?last_failure,
            "Failed to retrieve pieces for segment"
        );

        return Err(SegmentDownloadingError::NotEnoughPieces {
            segment_index,
            downloaded_pieces,
        });
    }

    Ok(segment_pieces)
}
