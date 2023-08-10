// Copyright (C) 2023 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod piece_validator;
mod segment_headers;

use crate::dsn::import_blocks::piece_validator::SegmentCommitmentPieceValidator;
use crate::dsn::import_blocks::segment_headers::SegmentHeaderHandler;
use parity_scale_codec::Encode;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::IncomingBlock;
use sc_tracing::tracing::{debug, trace};
use sp_consensus::BlockOrigin;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use static_assertions::const_assert;
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{
    ArchivedHistorySegment, BlockNumber, Piece, RecordedHistorySegment, SegmentHeader, SegmentIndex,
};
use subspace_networking::utils::piece_provider::{PieceProvider, RetryPolicy};
use subspace_networking::Node;

// Refuse to compile on non-64-bit platforms, otherwise segment indices will not fit in memory
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// How many blocks to queue before pausing and waiting for blocks to be imported
const QUEUED_BLOCKS_LIMIT: BlockNumber = 2048;
/// Time to wait for blocks to import if import is too slow
const WAIT_FOR_BLOCKS_TO_IMPORT: Duration = Duration::from_secs(1);

// TODO: Only download segment headers starting with the first segment that node doesn't have rather
//  than from genesis
/// Starts the process of importing blocks.
///
/// Returns number of downloaded blocks.
pub async fn import_blocks_from_dsn<Block, IQS, Client>(
    node: &Node,
    client: &Client,
    import_queue_service: &mut IQS,
    block_origin: BlockOrigin,
    force: bool,
) -> Result<u64, sc_service::Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
    IQS: ImportQueueService<Block> + ?Sized,
{
    let segment_headers = SegmentHeaderHandler::new(node.clone())
        .get_segment_headers()
        .await
        .map_err(|error| error.to_string())?;

    debug!("Found {} segment headers", segment_headers.len());

    if segment_headers.is_empty() {
        return Ok(0);
    }

    // TODO: Consider introducing and using global in-memory segment header cache (this comment is
    //  in multiple files)
    let segment_commitments = segment_headers
        .iter()
        .map(SegmentHeader::segment_commitment)
        .collect::<Vec<_>>();

    let segments_found = segment_commitments.len();
    let piece_provider = PieceProvider::<SegmentCommitmentPieceValidator>::new(
        node.clone(),
        Some(SegmentCommitmentPieceValidator::new(
            node.clone(),
            Kzg::new(embedded_kzg_settings()),
            segment_commitments,
        )),
    );

    let mut downloaded_blocks = 0;
    let mut reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;

    // Skip the first segment, everyone has it locally
    for segment_index in (SegmentIndex::ZERO..).take(segments_found).skip(1) {
        debug!(%segment_index, "Downloading segment");
        let pieces_indices = segment_index.segment_piece_indexes_source_first();

        if let Some(segment_header) = segment_headers.get(u64::from(segment_index) as usize) {
            trace!(
                %segment_index,
                last_archived_block_number = %segment_header.last_archived_block().number,
                last_archived_block_progress = ?segment_header.last_archived_block().archived_progress,
                "Downloaded segment header"
            );

            let last_archived_block =
                NumberFor::<Block>::from(segment_header.last_archived_block().number);
            if last_archived_block <= client.info().best_number {
                // Reset reconstructor instance
                reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;
                continue;
            }
        }

        let mut segment_pieces = vec![None::<Piece>; ArchivedHistorySegment::NUM_PIECES];
        let mut pieces_received = 0;

        for piece_index in pieces_indices {
            let maybe_piece = piece_provider
                .get_piece(piece_index, RetryPolicy::Limited(0))
                .await?;

            trace!(
                ?piece_index,
                success = maybe_piece.is_some(),
                "Piece request completed.",
            );

            if let Some(received_piece) = maybe_piece {
                segment_pieces
                    .get_mut(piece_index.position() as usize)
                    .expect("Piece position is by definition within segment; qed")
                    .replace(received_piece);

                pieces_received += 1;
            }

            if pieces_received >= RecordedHistorySegment::NUM_RAW_RECORDS {
                trace!(%segment_index, "Received half of the segment.");
                break;
            }
        }

        let reconstructed_contents = reconstructor
            .add_segment(segment_pieces.as_ref())
            .map_err(|error| error.to_string())?;
        drop(segment_pieces);

        trace!(%segment_index, "Segment reconstructed successfully");

        let mut blocks_to_import = Vec::with_capacity(QUEUED_BLOCKS_LIMIT as usize);

        let mut best_block_number = client.info().best_number;
        for (block_number, block_bytes) in reconstructed_contents.blocks {
            {
                let block_number = block_number.into();
                if block_number <= best_block_number {
                    if block_number == 0u32.into() {
                        let block = client
                            .block(client.hash(block_number)?.expect(
                                "Block before best block number must always be found; qed",
                            ))?
                            .expect("Block before best block number must always be found; qed");

                        if block.encode() != block_bytes {
                            return Err(sc_service::Error::Other(
                                "Wrong genesis block, block import failed".to_string(),
                            ));
                        }
                    }

                    continue;
                }

                // Limit number of queued blocks for import
                while block_number - best_block_number >= QUEUED_BLOCKS_LIMIT.into() {
                    if !blocks_to_import.is_empty() {
                        // Import queue handles verification and importing it into the client
                        import_queue_service.import_blocks(block_origin, blocks_to_import.clone());
                        blocks_to_import.clear();
                    }
                    trace!(
                        %block_number,
                        %best_block_number,
                        "Number of importing blocks reached queue limit, waiting before retrying"
                    );
                    tokio::time::sleep(WAIT_FOR_BLOCKS_TO_IMPORT).await;
                    best_block_number = client.info().best_number;
                }
            }

            let block =
                Block::decode(&mut block_bytes.as_slice()).map_err(|error| error.to_string())?;

            let (header, extrinsics) = block.deconstruct();
            let hash = header.hash();

            blocks_to_import.push(IncomingBlock {
                hash,
                header: Some(header),
                body: Some(extrinsics),
                indexed_body: None,
                justifications: None,
                origin: None,
                allow_missing_state: false,
                import_existing: force,
                state: None,
                skip_execution: false,
            });

            downloaded_blocks += 1;

            if downloaded_blocks % 1000 == 0 {
                debug!("Adding block {} from DSN to the import queue", block_number);
            }
        }

        if blocks_to_import.is_empty() {
            break;
        }

        // Import queue handles verification and importing it into the client
        import_queue_service.import_blocks(block_origin, blocks_to_import);
    }

    Ok(downloaded_blocks)
}
