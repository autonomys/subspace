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
use futures::FutureExt;
use parity_scale_codec::Encode;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::{BlockImportError, BlockImportStatus, IncomingBlock, Link};
use sc_service::ImportQueue;
use sc_tracing::tracing::{debug, info, trace};
use sp_consensus::BlockOrigin;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{
    ArchivedHistorySegment, Piece, RecordedHistorySegment, SegmentHeader, SegmentIndex,
};
use subspace_networking::utils::piece_provider::{PieceProvider, RetryPolicy};
use subspace_networking::Node;

/// How long to wait for peers before giving up
const WAIT_FOR_PEERS_TIMEOUT: Duration = Duration::from_secs(10);

struct WaitLinkError<B: BlockT> {
    error: BlockImportError,
    hash: B::Hash,
}

struct WaitLink<B: BlockT> {
    imported_blocks: u64,
    error: Option<WaitLinkError<B>>,
}

impl<B: BlockT> WaitLink<B> {
    fn new() -> Self {
        Self {
            imported_blocks: 0,
            error: None,
        }
    }
}

impl<B: BlockT> Link<B> for WaitLink<B> {
    fn blocks_processed(
        &mut self,
        imported: usize,
        _num_expected_blocks: usize,
        results: Vec<(
            Result<BlockImportStatus<NumberFor<B>>, BlockImportError>,
            B::Hash,
        )>,
    ) {
        debug!("Imported {imported} blocks");
        self.imported_blocks += imported as u64;

        for result in results {
            if let (Err(error), hash) = result {
                self.error.replace(WaitLinkError { error, hash });
                break;
            }
        }
    }
}

/// Starts the process of importing blocks, used for for initial sync on node startup because it
/// requires [`ImportQueue`] as a dependency.
///
/// Returns number of imported blocks.
pub async fn initial_block_import_from_dsn<Block, IQ, Client>(
    node: &Node,
    client: Arc<Client>,
    import_queue: &mut IQ,
    force: bool,
) -> Result<u64, sc_service::Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
    IQ: ImportQueue<Block> + 'static,
{
    let mut link = WaitLink::new();
    let mut import_queue_service = import_queue.service();

    let import_blocks_fut = import_blocks_from_dsn(
        node,
        client.as_ref(),
        import_queue_service.as_mut(),
        BlockOrigin::NetworkInitialSync,
        force,
    );
    let drive_import_queue_fut = async {
        let mut last_imported_blocks = link.imported_blocks;
        loop {
            futures::future::poll_fn(|ctx| {
                import_queue.poll_actions(ctx, &mut link);

                if last_imported_blocks == link.imported_blocks && link.error.is_none() {
                    // Nothing changed yet, wait for waker to be called
                    Poll::Pending
                } else {
                    last_imported_blocks = link.imported_blocks;
                    Poll::Ready(())
                }
            })
            .await;

            if let Some(WaitLinkError { error, hash }) = &link.error {
                return Err::<(), sc_service::Error>(sc_service::Error::Other(format!(
                    "Stopping block import after #{} blocks on {} because of an error: {}",
                    link.imported_blocks, hash, error
                )));
            }
        }
    };

    let downloaded_blocks = futures::select! {
        maybe_downloaded_blocks = import_blocks_fut.fuse() => {
            maybe_downloaded_blocks?
        }
        result = drive_import_queue_fut.fuse() => {
            if let Err(error) = result {
                return Err(error);
            } else {
                unreachable!();
            }
        }
    };

    while link.imported_blocks < downloaded_blocks {
        futures::future::poll_fn(|ctx| {
            import_queue.poll_actions(ctx, &mut link);

            Poll::Ready(())
        })
        .await;

        if let Some(WaitLinkError { error, hash }) = &link.error {
            return Err(sc_service::Error::Other(format!(
                "Stopping block import after #{} blocks on {} because of an error: {}",
                link.imported_blocks, hash, error
            )));
        }
    }

    Ok(downloaded_blocks)
}

// TODO: Handle situation where block we are about to import is already included in chain and
//  further sync from DSN is not necessary
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
    debug!("Waiting for connected peers...");
    if node
        .wait_for_connected_peers(WAIT_FOR_PEERS_TIMEOUT)
        .await
        .is_err()
    {
        info!("Was not able to find any DSN peers, cancelling sync from DSN");
        return Ok(0);
    }
    debug!("Connected to peers.");

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

    let best_block_number = client.info().best_number;
    let mut downloaded_blocks = 0;
    let mut reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;

    // Skip the first segment, everyone has it locally
    for segment_index in (SegmentIndex::ZERO..).take(segments_found).skip(1) {
        let pieces_indices = segment_index.segment_piece_indexes_source_first();

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
            }

            let block =
                Block::decode(&mut block_bytes.as_slice()).map_err(|error| error.to_string())?;

            let (header, extrinsics) = block.deconstruct();
            let hash = header.hash();

            // import queue handles verification and importing it into the client.
            import_queue_service.import_blocks(
                block_origin,
                vec![IncomingBlock::<Block> {
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
                }],
            );

            downloaded_blocks += 1;

            if downloaded_blocks % 1000 == 0 {
                info!("Imported block {}", block_number);
            }
        }
    }

    Ok(downloaded_blocks)
}
