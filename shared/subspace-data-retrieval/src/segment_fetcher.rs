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
use async_lock::Semaphore;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
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
// This code was copied and modified from subspace_service::sync_from_dsn::download_and_reconstruct_blocks():
// <https://github.com/autonomys/subspace/blob/d71ca47e45e1b53cd2e472413caa23472a91cd74/crates/subspace-service/src/sync_from_dsn/import_blocks.rs#L236-L322>
//
// TODO: pass a lower concurrency limit into this function, to avoid overwhelming residential routers or slow connections
pub async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Result<Vec<Option<Piece>>, SegmentGetterError>
where
    PG: ObjectPieceGetter,
{
    debug!(%segment_index, "Retrieving pieces of the segment");

    let semaphore = &Semaphore::new(RecordedHistorySegment::NUM_RAW_RECORDS);

    let mut received_segment_pieces = segment_index
        .segment_piece_indexes_source_first()
        .into_iter()
        .map(|piece_index| {
            // Source pieces will acquire permit here right away
            let maybe_permit = semaphore.try_acquire();

            async move {
                let permit = match maybe_permit {
                    Some(permit) => permit,
                    None => {
                        // Other pieces will acquire permit here instead
                        semaphore.acquire().await
                    }
                };
                let piece = match piece_getter.get_piece(piece_index).await {
                    Ok(Some(piece)) => piece,
                    Ok(None) => {
                        trace!(?piece_index, "Piece not found");
                        return None;
                    }
                    Err(error) => {
                        trace!(
                            %error,
                            ?piece_index,
                            "Piece request failed",
                        );
                        return None;
                    }
                };

                trace!(?piece_index, "Piece request succeeded");

                // Piece was received successfully, "remove" this slot from semaphore
                permit.forget();
                Some((piece_index, piece))
            }
        })
        .collect::<FuturesUnordered<_>>();

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];
    let mut pieces_received = 0;

    while let Some(maybe_piece) = received_segment_pieces.next().await {
        let Some((piece_index, piece)) = maybe_piece else {
            continue;
        };

        segment_pieces
            .get_mut(piece_index.position() as usize)
            .expect("Piece position is by definition within segment; qed")
            .replace(piece);

        pieces_received += 1;

        if pieces_received >= RecordedHistorySegment::NUM_RAW_RECORDS {
            trace!(%segment_index, "Received half of the segment.");
            break;
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
