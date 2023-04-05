// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

use crate::{
    get_chain_constants, ArchivedSegmentNotification, BlockImportingNotification, SubspaceLink,
    SubspaceNotificationSender,
};
use codec::Encode;
use futures::StreamExt;
use log::{debug, error, info, warn};
use sc_client_api::{AuxStore, Backend as BackendT, BlockBackend, Finalizer, LockImportRun};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_INFO};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor, One, Zero};
use std::future::Future;
use std::sync::Arc;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{BlockNumber, SegmentHeader};

fn find_last_archived_block<Block, Client>(
    client: &Client,
    best_block_hash: Block::Hash,
) -> Option<(SegmentHeader, SignedBlock<Block>, BlockObjectMapping)>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
{
    let mut block_to_check = best_block_hash;
    let last_segment_header = 'outer: loop {
        let block = client
            .block(block_to_check)
            .expect("Older blocks should always exist")
            .expect("Older blocks should always exist");

        for extrinsic in block.block.extrinsics() {
            match client
                .runtime_api()
                .extract_segment_headers(block_to_check, extrinsic)
            {
                Ok(Some(segment_headers)) => {
                    break 'outer segment_headers.into_iter().last()?;
                }
                Ok(None) => {
                    // Some other extrinsic, ignore
                }
                Err(error) => {
                    // TODO: Probably light client, can this even happen?
                    panic!(
                        "Failed to make runtime API call during last archived block search: \
                        {error:?}"
                    );
                }
            }
        }

        let parent_block_hash = *block.block.header().parent_hash();

        if parent_block_hash == Block::Hash::default() {
            // Genesis block, nothing else to check
            return None;
        }

        block_to_check = parent_block_hash;
    };

    let last_archived_block_number = last_segment_header.last_archived_block().number;

    let last_archived_block = loop {
        let block = client
            .block(block_to_check)
            .expect("Older blocks must always exist")
            .expect("Older blocks must always exist");

        if *block.block.header().number() == last_archived_block_number.into() {
            break block;
        }

        block_to_check = *block.block.header().parent_hash();
    };

    let last_archived_block_hash = block_to_check;

    let block_object_mappings = client
        .runtime_api()
        .validated_object_call_hashes(last_archived_block_hash)
        .and_then(|calls| {
            client.runtime_api().extract_block_object_mapping(
                *last_archived_block.block.header().parent_hash(),
                last_archived_block.block.clone(),
                calls,
            )
        })
        .unwrap_or_default();

    Some((
        last_segment_header,
        last_archived_block,
        block_object_mappings,
    ))
}

struct BlockHashesToArchive<Block>
where
    Block: BlockT,
{
    block_hashes: Vec<Block::Hash>,
    best_archived: Option<(Block::Hash, NumberFor<Block>)>,
}

fn block_hashes_to_archive<Block, Client>(
    client: &Client,
    best_block_hash: Block::Hash,
    blocks_to_archive_from: NumberFor<Block>,
    blocks_to_archive_to: NumberFor<Block>,
) -> BlockHashesToArchive<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    let block_range = blocks_to_archive_from..=blocks_to_archive_to;
    let mut block_hashes = Vec::new();
    let mut block_hash_to_check = best_block_hash;
    let mut best_archived = None;

    loop {
        // TODO: `Error` here must be handled instead
        let header = client
            .header(block_hash_to_check)
            .expect("Parent block must exist; qed")
            .expect("Parent block must exist; qed");

        if block_range.contains(header.number()) {
            block_hashes.push(block_hash_to_check);

            if best_archived.is_none() {
                best_archived.replace((block_hash_to_check, *header.number()));
            }
        }

        if *header.number() == blocks_to_archive_from {
            break;
        }

        block_hash_to_check = *header.parent_hash();
    }

    BlockHashesToArchive {
        block_hashes,
        best_archived,
    }
}

struct InitializedArchiver<Block>
where
    Block: BlockT,
{
    confirmation_depth_k: BlockNumber,
    archiver: Archiver,
    older_archived_segments: Vec<NewArchivedSegment>,
    best_archived_block: (Block::Hash, NumberFor<Block>),
}

fn initialize_archiver<Block, Client>(
    best_block_hash: Block::Hash,
    best_block_number: NumberFor<Block>,
    subspace_link: &SubspaceLink<Block>,
    client: &Client,
    kzg: Kzg,
) -> InitializedArchiver<Block>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
{
    let confirmation_depth_k = get_chain_constants(client)
        .expect("Must always be able to get chain constants")
        .confirmation_depth_k();

    let maybe_last_archived_block = find_last_archived_block(client, best_block_hash);
    let have_last_segment_header = maybe_last_archived_block.is_some();
    let mut best_archived_block = None;

    let mut archiver =
        if let Some((last_segment_header, last_archived_block, block_object_mappings)) =
            maybe_last_archived_block
        {
            // Continuing from existing initial state
            let last_archived_block_number = last_segment_header.last_archived_block().number;
            info!(
                target: "subspace",
                "Last archived block {}",
                last_archived_block_number,
            );

            // Set initial value, this is needed in case only genesis block was archived and there
            // is nothing else available
            best_archived_block.replace((
                last_archived_block.block.hash(),
                *last_archived_block.block.header().number(),
            ));

            Archiver::with_initial_state(
                kzg,
                last_segment_header,
                &last_archived_block.encode(),
                block_object_mappings,
            )
            .expect("Incorrect parameters for archiver")
        } else {
            info!(target: "subspace", "Starting archiving from genesis");

            Archiver::new(kzg).expect("Incorrect parameters for archiver")
        };

    let mut older_archived_segments = Vec::new();

    // Process blocks since last fully archived block (or genesis) up to the current head minus K
    {
        let blocks_to_archive_from = archiver
            .last_archived_block_number()
            .map(|n| n + 1)
            .unwrap_or_default();
        let blocks_to_archive_to =
            TryInto::<BlockNumber>::try_into(best_block_number)
                .unwrap_or_else(|_| {
                    panic!(
                        "Best block number {best_block_number} can't be converted into BlockNumber",
                    );
                })
                .checked_sub(confirmation_depth_k)
                .or({
                    if have_last_segment_header {
                        None
                    } else {
                        // If not continuation, archive genesis block
                        Some(0)
                    }
                });

        if let Some(blocks_to_archive_to) = blocks_to_archive_to {
            info!(
                target: "subspace",
                "Archiving already produced blocks {}..={}",
                blocks_to_archive_from,
                blocks_to_archive_to,
            );

            let block_hashes_to_archive = block_hashes_to_archive(
                client,
                best_block_hash,
                blocks_to_archive_from.into(),
                blocks_to_archive_to.into(),
            );
            best_archived_block = block_hashes_to_archive.best_archived;
            let block_hashes_to_archive = block_hashes_to_archive.block_hashes;

            for block_hash_to_archive in block_hashes_to_archive.into_iter().rev() {
                let block = client
                    .block(block_hash_to_archive)
                    .expect("Older block by number must always exist")
                    .expect("Older block by number must always exist");
                let block_number_to_archive = *block.block.header().number();

                let block_object_mappings = client
                    .runtime_api()
                    .validated_object_call_hashes(block_hash_to_archive)
                    .and_then(|calls| {
                        client.runtime_api().extract_block_object_mapping(
                            *block.block.header().parent_hash(),
                            block.block.clone(),
                            calls,
                        )
                    })
                    .unwrap_or_default();

                let encoded_block = block.encode();
                debug!(
                    target: "subspace",
                    "Encoded block {} has size of {:.2} kiB",
                    block_number_to_archive,
                    encoded_block.len() as f32 / 1024.0
                );

                let archived_segments = archiver.add_block(encoded_block, block_object_mappings);
                let new_segment_headers: Vec<SegmentHeader> = archived_segments
                    .iter()
                    .map(|archived_segment| archived_segment.segment_header)
                    .collect();

                older_archived_segments.extend(archived_segments);

                if !new_segment_headers.is_empty() {
                    // Set list of expected segment headers for the block where we expect segment
                    // header extrinsic to be included
                    subspace_link.segment_headers.lock().put(
                        if block_number_to_archive.is_zero() {
                            // Special case for genesis block whose segment header should be included in
                            // the first block in order for further validation to work properly.
                            One::one()
                        } else {
                            block_number_to_archive + confirmation_depth_k.into() + One::one()
                        },
                        new_segment_headers,
                    );
                }
            }
        }
    }

    InitializedArchiver {
        confirmation_depth_k,
        archiver,
        older_archived_segments,
        best_archived_block: best_archived_block
            .expect("Must always set if there is no logical error; qed"),
    }
}

fn finalize_block<Block, Backend, Client>(
    client: &Client,
    telemetry: Option<TelemetryHandle>,
    hash: Block::Hash,
    number: NumberFor<Block>,
) where
    Block: BlockT,
    Backend: BackendT<Block>,
    Client: LockImportRun<Block, Backend> + Finalizer<Block, Backend>,
{
    // We don't have anything useful to do with this result yet, the only source of errors was
    // logged already inside
    let _result: Result<_, sp_blockchain::Error> = client.lock_import_and_run(|import_op| {
        // Ideally some handle to a synchronization oracle would be used to avoid unconditionally
        // notifying.
        client
            .apply_finality(import_op, hash, None, true)
            .map_err(|error| {
                warn!(target: "subspace", "Error applying finality to block {:?}: {}", (hash, number), error);
                error
            })?;

        debug!(target: "subspace", "Finalizing blocks up to ({:?}, {})", number, hash);

        telemetry!(
            telemetry;
            CONSENSUS_INFO;
            "subspace.finalized_blocks_up_to";
            "number" => ?number, "hash" => ?hash,
        );

        Ok(())
    });
}

/// Crate an archiver task that will listen for importing blocks and archive blocks at `K` depth,
/// producing pieces and segment headers (segment headers are then added back to the blockchain as
/// `store_segment_header` extrinsic).
///
/// NOTE: Archiver is doing blocking operations and must run in a dedicated task.
pub fn create_subspace_archiver<Block, Backend, Client>(
    subspace_link: &SubspaceLink<Block>,
    client: Arc<Client>,
    telemetry: Option<TelemetryHandle>,
) -> impl Future<Output = ()> + Send + 'static
where
    Block: BlockT,
    Backend: BackendT<Block>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + LockImportRun<Block, Backend>
        + Finalizer<Block, Backend>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
{
    let client_info = client.info();
    let best_block_hash = client_info.best_hash;
    let best_block_number = client_info.best_number;

    let InitializedArchiver {
        confirmation_depth_k,
        mut archiver,
        older_archived_segments,
        best_archived_block: (mut best_archived_block_hash, mut best_archived_block_number),
    } = initialize_archiver(
        best_block_hash,
        best_block_number,
        subspace_link,
        client.as_ref(),
        subspace_link.kzg.clone(),
    );

    let mut block_importing_notification_stream = subspace_link
        .block_importing_notification_stream
        .subscribe();
    let archived_segment_notification_sender =
        subspace_link.archived_segment_notification_sender.clone();
    let segment_headers = Arc::clone(&subspace_link.segment_headers);

    async move {
        // Farmers may have not received all previous segments, send them now.
        for archived_segment in older_archived_segments {
            send_archived_segment_notification(
                &archived_segment_notification_sender,
                archived_segment,
            )
            .await;
        }

        while let Some(BlockImportingNotification {
            block_number,
            // Just to be very explicit that block import shouldn't continue until archiving
            // is over
            acknowledgement_sender: _acknowledgement_sender,
            ..
        }) = block_importing_notification_stream.next().await
        {
            let block_number_to_archive =
                match block_number.checked_sub(&confirmation_depth_k.into()) {
                    Some(block_number_to_archive) => block_number_to_archive,
                    None => {
                        continue;
                    }
                };

            if best_archived_block_number >= block_number_to_archive {
                // This block was already archived, skip
                continue;
            }

            best_archived_block_number = block_number_to_archive;

            let block = client
                .block(
                    client
                        .hash(block_number_to_archive)
                        .expect("Older block by number must always exist")
                        .expect("Older block by number must always exist"),
                )
                .expect("Older block by number must always exist")
                .expect("Older block by number must always exist");

            let parent_block_hash = *block.block.header().parent_hash();
            let block_hash_to_archive = block.block.hash();

            debug!(
                target: "subspace",
                "Archiving block {:?} ({})",
                block_number_to_archive,
                block_hash_to_archive
            );

            if parent_block_hash != best_archived_block_hash {
                error!(
                    target: "subspace",
                    "Attempt to switch to a different fork beyond archiving depth, \
                    can't do it: parent block hash {}, best archived block hash {}",
                    parent_block_hash,
                    best_archived_block_hash
                );
                return;
            }

            best_archived_block_hash = block_hash_to_archive;

            let block_object_mappings = match client
                .runtime_api()
                .validated_object_call_hashes(block_hash_to_archive)
                .and_then(|calls| {
                    client.runtime_api().extract_block_object_mapping(
                        parent_block_hash,
                        block.block.clone(),
                        calls,
                    )
                }) {
                Ok(block_object_mappings) => block_object_mappings,
                Err(error) => {
                    error!(
                        target: "subspace",
                        "Failed to retrieve block object mappings: {error}"
                    );
                    return;
                }
            };

            let encoded_block = block.encode();
            debug!(
                target: "subspace",
                "Encoded block {} has size of {:.2} kiB",
                block_number_to_archive,
                encoded_block.len() as f32 / 1024.0
            );

            let mut new_segment_headers = Vec::new();
            for archived_segment in archiver.add_block(encoded_block, block_object_mappings) {
                let segment_header = archived_segment.segment_header;

                send_archived_segment_notification(
                    &archived_segment_notification_sender,
                    archived_segment,
                )
                .await;

                new_segment_headers.push(segment_header);
            }

            if !new_segment_headers.is_empty() {
                segment_headers
                    .lock()
                    .put(block_number + One::one(), new_segment_headers);
            }

            finalize_block(
                client.as_ref(),
                telemetry.clone(),
                block_hash_to_archive,
                block_number_to_archive,
            );
        }
    }
}

async fn send_archived_segment_notification(
    archived_segment_notification_sender: &SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment: NewArchivedSegment,
) {
    let (acknowledgement_sender, mut acknowledgement_receiver) =
        tracing_unbounded::<()>("subspace_acknowledgement", 100);
    let archived_segment_notification = ArchivedSegmentNotification {
        archived_segment: Arc::new(archived_segment),
        acknowledgement_sender,
    };

    archived_segment_notification_sender.notify(move || archived_segment_notification);

    while acknowledgement_receiver.next().await.is_some() {
        // Wait until all acknowledgements are received
    }
}
