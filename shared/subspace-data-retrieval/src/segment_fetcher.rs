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

use crate::piece_getter::ObjectPieceGetter;
use futures::{stream, StreamExt};
use subspace_archiving::archiver::Segment;
use subspace_archiving::reconstructor::{Reconstructor, ReconstructorError};
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::segments::{
    ArchivedHistorySegment, RecordedHistorySegment, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use tokio::task::spawn_blocking;
use tracing::{debug, trace};

/// Segment getter errors.
#[derive(Debug, thiserror::Error)]
pub enum SegmentGetterError {
    /// Piece getter error
    #[error("Failed to get enough segment pieces")]
    PieceGetter { segment_index: SegmentIndex },

    /// Segment reconstruction error
    #[error("Segment reconstruction error: {source:?}")]
    SegmentReconstruction {
        #[from]
        source: ReconstructorError,
    },

    /// Segment decoding error
    #[error("Segment data decoding error: {source:?}")]
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
) -> Result<Segment, SegmentGetterError>
where
    PG: ObjectPieceGetter,
{
    let reconstructor = Reconstructor::new(erasure_coding);

    let segment_pieces = download_segment_pieces(segment_index, piece_getter).await?;

    let segment = spawn_blocking(move || reconstructor.reconstruct_segment(&segment_pieces))
        .await
        .expect("Panic if blocking task panicked")?;

    Ok(segment)
}

/// Concurrently downloads the pieces for `segment_index`.
// TODO: pass a lower concurrency limit into this function, to avoid overwhelming residential routers or slow connections
pub async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Result<Vec<Option<Piece>>, SegmentGetterError>
where
    PG: ObjectPieceGetter,
{
    debug!(%segment_index, "Retrieving pieces of the segment");

    // We want NUM_RAW_RECORDS pieces to reconstruct the segment, but it doesn't matter exactly which ones.
    let piece_indexes = segment_index.segment_piece_indexes_source_first();
    let mut piece_indexes = piece_indexes.as_slice();
    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];

    let mut pieces_pending = 0;
    let mut pieces_received = 0;
    let mut piece_streams = Vec::new();

    // Loop Invariant:
    // - the number of remaining piece indexes gets smaller, eventually finishing the fetcher, or
    // - the number of pending pieces gets smaller, eventually triggering another batch.
    // We also exit early if we have enough pieces to reconstruct a segment.
    'fetcher: while !piece_indexes.is_empty()
        && pieces_received < RecordedHistorySegment::NUM_RAW_RECORDS
    {
        // Request the number of pieces needed to reconstruct the segment, assuming all pending
        // pieces are successful.
        let batch_size = RecordedHistorySegment::NUM_RAW_RECORDS - pieces_received - pieces_pending;
        if batch_size > 0 {
            let (batch_indexes, remaining_piece_indexes) = piece_indexes
                .split_at_checked(batch_size)
                .unwrap_or((piece_indexes, &[]));
            // Invariant: the number of remaining piece indexes gets smaller.
            piece_indexes = remaining_piece_indexes;

            let stream = piece_getter.get_pieces(batch_indexes.iter().cloned()).await;
            match stream {
                Ok(stream) => {
                    piece_streams.push(stream);
                    pieces_pending += batch_size;
                }
                Err(error) => {
                    // A single batch failure isn't fatal.
                    debug!(
                        ?error,
                        %segment_index,
                        batch_size,
                        pieces_pending,
                        pieces_received,
                        pieces_needed = RecordedHistorySegment::NUM_RAW_RECORDS,
                        "Segment piece getter batch failed"
                    );
                }
            }
        }

        // Poll all the batches concurrently, getting all finished pieces.
        let piece_responses = stream::iter(&mut piece_streams)
            .flatten_unordered(None)
            .ready_chunks(RecordedHistorySegment::NUM_RAW_RECORDS)
            .next()
            .await;

        let Some(piece_responses) = piece_responses else {
            // All streams have finished, perhaps abnormally, so reset the number of pending pieces.
            // Invariant: the number of pending pieces gets smaller.
            pieces_pending = 0;
            continue 'fetcher;
        };

        // Process the piece responses.
        'processor: for maybe_piece in piece_responses {
            // Invariant: the number of pending pieces gets smaller.
            pieces_pending -= 1;

            let (piece_index, Ok(Some(piece))) = maybe_piece else {
                continue 'processor;
            };

            segment_pieces
                .get_mut(piece_index.position() as usize)
                .expect("Piece position is by definition within segment; qed")
                .replace(piece);

            pieces_received += 1;

            if pieces_received >= RecordedHistorySegment::NUM_RAW_RECORDS {
                trace!(%segment_index, "Received half of the segment.");
                break 'fetcher;
            }
        }
    }

    if pieces_received < RecordedHistorySegment::NUM_RAW_RECORDS {
        debug!(
            %segment_index,
            pieces_received,
            pieces_needed = RecordedHistorySegment::NUM_RAW_RECORDS,
            "Failed to get half of the pieces in the segment"
        );

        Err(SegmentGetterError::PieceGetter { segment_index })
    } else {
        trace!(
            %segment_index,
            pieces_received,
            pieces_needed = RecordedHistorySegment::NUM_RAW_RECORDS,
            "Successfully retrieved enough pieces of the segment"
        );

        Ok(segment_pieces)
    }
}
