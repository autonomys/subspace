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
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use subspace_core_primitives::{
    ArchivedHistorySegment, Piece, RecordedHistorySegment, SegmentIndex,
};
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

/// Concurrently downloads the pieces for `segment_index`.
// This code was copied and modified from subspace_service::sync_from_dsn::download_and_reconstruct_blocks():
// <https://github.com/autonomys/subspace/blob/d71ca47e45e1b53cd2e472413caa23472a91cd74/crates/subspace-service/src/sync_from_dsn/import_blocks.rs#L236-L322>
//
// TODO: pass a lower concurrency limit into this function, to avoid overwhelming residential routers or slow connections
pub async fn download_segment_pieces<PG>(
    segment_index: SegmentIndex,
    piece_getter: &PG,
) -> Vec<Option<Piece>>
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
            let maybe_permit = semaphore.try_acquire().ok();

            async move {
                let permit = match maybe_permit {
                    Some(permit) => permit,
                    None => {
                        // Other pieces will acquire permit here instead
                        match semaphore.acquire().await {
                            Ok(permit) => permit,
                            Err(error) => {
                                warn!(
                                    %piece_index,
                                    %error,
                                    "Semaphore was closed, interrupting piece retrieval"
                                );
                                return None;
                            }
                        }
                    }
                };
                let maybe_piece = match piece_getter.get_piece(piece_index).await {
                    Ok(maybe_piece) => maybe_piece,
                    Err(error) => {
                        trace!(
                            %error,
                            ?piece_index,
                            "Piece request failed",
                        );
                        return None;
                    }
                };

                trace!(
                    ?piece_index,
                    piece_found = maybe_piece.is_some(),
                    "Piece request succeeded",
                );

                maybe_piece.map(|received_piece| {
                    // Piece was received successfully, "remove" this slot from semaphore
                    permit.forget();
                    (piece_index, received_piece)
                })
            }
        })
        .collect::<FuturesUnordered<_>>();

    let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];
    let mut pieces_received = 0;

    while let Some(maybe_result) = received_segment_pieces.next().await {
        let Some((piece_index, piece)) = maybe_result else {
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

    segment_pieces
}
