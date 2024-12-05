// Copyright (C) 2024 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
    #[error("Not enough ({downloaded_pieces}) pieces")]
    NotEnoughPieces {
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
/// Prefers source pieces if available, on error returns number of downloaded pieces
pub async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Result<Vec<Option<Piece>>, SegmentDownloadingError>
where
    PG: PieceGetter,
{
    let required_pieces_number = RecordedHistorySegment::NUM_RAW_RECORDS;
    let mut downloaded_pieces = 0_usize;

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];

    let mut pieces_iter = segment_index
        .segment_piece_indexes_source_first()
        .into_iter();

    // Download in batches until we get enough or exhaust available pieces
    while !pieces_iter.is_empty() && downloaded_pieces != required_pieces_number {
        let piece_indices = pieces_iter
            .by_ref()
            .take(required_pieces_number - downloaded_pieces);

        let mut received_segment_pieces = piece_getter.get_pieces(piece_indices).await?;

        while let Some((piece_index, result)) = received_segment_pieces.next().await {
            match result {
                Ok(Some(piece)) => {
                    downloaded_pieces += 1;
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

    if downloaded_pieces < required_pieces_number {
        debug!(
            %segment_index,
            %downloaded_pieces,
            %required_pieces_number,
            "Failed to retrieve pieces for segment"
        );

        return Err(SegmentDownloadingError::NotEnoughPieces { downloaded_pieces });
    }

    Ok(segment_pieces)
}
