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

use super::*;

fn find_last_root_block<Block: BlockT, Client>(client: &Client) -> Option<RootBlock>
where
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceApi<Block>,
{
    let mut block_to_check = BlockId::Hash(client.info().best_hash);
    loop {
        let block = client
            .block(&block_to_check)
            .expect("Older blocks should always exist")
            .expect("Older blocks should always exist");
        let mut latest_root_block: Option<RootBlock> = None;

        for extrinsic in block.block.extrinsics() {
            match client
                .runtime_api()
                .extract_root_block(&block_to_check, extrinsic.encode())
            {
                Ok(Some(root_block)) => match &mut latest_root_block {
                    Some(latest_root_block) => {
                        if latest_root_block.segment_index() < root_block.segment_index() {
                            *latest_root_block = root_block;
                        }
                    }
                    None => {
                        latest_root_block.replace(root_block);
                    }
                },
                Ok(None) => {
                    // Some other extrinsic, ignore
                }
                Err(error) => {
                    // TODO: Probably light client, can this even happen?
                    error!(target: "subspace", "Failed to make runtime API call: {:?}", error);
                }
            }
        }

        if latest_root_block.is_some() {
            break latest_root_block;
        }

        let parent_block_hash = *block.block.header().parent_hash();

        if parent_block_hash == Block::Hash::default() {
            // Genesis block, nothing else to check
            break None;
        }

        block_to_check = BlockId::Hash(parent_block_hash);
    }
}

/// Start an archiver that will listen for imported blocks and archive blocks at `K` depth,
/// producing pieces and root blocks (root blocks are then added back to the blockchain as
/// `store_root_block` extrinsic).
pub fn start_subspace_archiver<Block: BlockT, Client>(
    subspace_link: &SubspaceLink<Block>,
    client: Arc<Client>,
    spawner: &impl sp_core::traits::SpawnNamed,
) where
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block>,
{
    let genesis_block_id = BlockId::Number(Zero::zero());

    let confirmation_depth_k = client
        .runtime_api()
        .confirmation_depth_k(&genesis_block_id)
        .expect("Failed to get `confirmation_depth_k` from runtime API");
    let record_size = client
        .runtime_api()
        .record_size(&genesis_block_id)
        .expect("Failed to get `record_size` from runtime API");
    let recorded_history_segment_size = client
        .runtime_api()
        .recorded_history_segment_size(&genesis_block_id)
        .expect("Failed to get `recorded_history_segment_size` from runtime API");

    let mut archiver = if let Some(last_root_block) = find_last_root_block(client.as_ref()) {
        // Continuing from existing initial state
        let last_archived_block_number = last_root_block.last_archived_block().number;
        info!(
            target: "subspace",
            "Last archived block {}",
            last_archived_block_number,
        );
        let last_archived_block = client
            .block(&BlockId::Number(last_archived_block_number.into()))
            .expect("Older blocks should always exist")
            .expect("Older blocks should always exist");

        let block_object_mapping = client
            .runtime_api()
            .extract_block_object_mapping(
                &BlockId::Number(last_archived_block_number.saturating_sub(1).into()),
                last_archived_block.block.clone(),
            )
            .expect("Must be able to make runtime call");

        BlockArchiver::with_initial_state(
            record_size as usize,
            recorded_history_segment_size as usize,
            last_root_block,
            &last_archived_block.encode(),
            block_object_mapping,
        )
        .expect("Incorrect parameters for archiver")
    } else {
        // Starting from genesis
        let runtime_api = client.runtime_api();

        let mut object_archiver =
            ObjectArchiver::new(record_size as usize, recorded_history_segment_size as usize)
                .expect("Incorrect parameters for archiver");

        let pre_genesis_object_size = runtime_api
            .pre_genesis_object_size(&genesis_block_id)
            .expect("Failed to get `pre_genesis_object_size` from runtime API");
        let pre_genesis_object_count = runtime_api
            .pre_genesis_object_count(&genesis_block_id)
            .expect("Failed to get `pre_genesis_object_count` from runtime API");
        let pre_genesis_object_seed = runtime_api
            .pre_genesis_object_seed(&genesis_block_id)
            .expect("Failed to get `pre_genesis_object_seed` from runtime API");

        // These archived segments are a part of the public parameters of network setup, thus do not
        // need to be sent to farmers
        info!(target: "subspace", "Processing pre-genesis objects");
        let new_root_blocks: Vec<RootBlock> = (0..pre_genesis_object_count)
            .map(|index| {
                object_archiver
                    .add_object(pre_genesis_data::from_seed(
                        &pre_genesis_object_seed,
                        index,
                        pre_genesis_object_size,
                    ))
                    .into_iter()
            })
            .flatten()
            .map(|archived_segment| archived_segment.root_block)
            .collect();

        if subspace_link.authoring_enabled {
            // TODO: Block size will not be enough in case number of root blocks it too large; not a
            //  problem for now though. Also RAM usage will be very significant with current approach.
            // Submit store root block extrinsic at genesis block.
            for root_block in new_root_blocks.iter().copied() {
                client
                    .runtime_api()
                    .submit_store_root_block_extrinsic(&genesis_block_id, root_block)
                    .expect("Failed to submit `store_root_block` extrinsic at genesis block");
            }
        }

        // Set list of expected root blocks for the next block after genesis (we can't have
        // extrinsics in genesis block, at least not right now)
        subspace_link
            .root_blocks
            .lock()
            .put(One::one(), new_root_blocks);

        info!(target: "subspace", "Finished processing pre-genesis objects");

        object_archiver.into_block_archiver()
    };

    // Process blocks since last fully archived block (or genesis) up to the current head minus K
    {
        let blocks_to_archive_from = archiver
            .last_archived_block_number()
            .map(|n| n + 1)
            .unwrap_or_default();
        let best_number = client.info().best_number;
        let blocks_to_archive_to = TryInto::<u32>::try_into(best_number)
            .unwrap_or_else(|_| {
                panic!(
                    "Best block number {} can't be converted into u32",
                    best_number,
                );
            })
            .checked_sub(confirmation_depth_k);

        if let Some(blocks_to_archive_to) = blocks_to_archive_to {
            info!(
                target: "subspace",
                "Archiving already produced blocks {}..={}",
                blocks_to_archive_from,
                blocks_to_archive_to,
            );
            for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                let block = client
                    .block(&BlockId::Number(block_to_archive.into()))
                    .expect("Older block by number must always exist")
                    .expect("Older block by number must always exist");

                let block_object_mapping = client
                    .runtime_api()
                    .extract_block_object_mapping(
                        &BlockId::Number(block_to_archive.saturating_sub(1).into()),
                        block.block.clone(),
                    )
                    .expect("Must be able to make runtime call");

                // These archived segments were processed before, thus do not need to be sent to
                // farmers
                let new_root_blocks = archiver
                    .add_block(block.encode(), block_object_mapping)
                    .into_iter()
                    .map(|archived_segment| archived_segment.root_block)
                    .collect();

                // Set list of expected root blocks for the block where we expect root block
                // extrinsic to be included
                subspace_link.root_blocks.lock().put(
                    (block_to_archive + confirmation_depth_k + 1).into(),
                    new_root_blocks,
                );
            }
        }
    }

    spawner.spawn_blocking(
        "subspace-archiver",
        Box::pin({
            let mut imported_block_notification_stream =
                subspace_link.imported_block_notification_stream.subscribe();
            let archived_segment_notification_sender =
                subspace_link.archived_segment_notification_sender.clone();

            async move {
                let mut last_archived_block_number =
                    archiver.last_archived_block_number().map(Into::into);

                while let Some((block_number, mut root_block_sender)) =
                    imported_block_notification_stream.next().await
                {
                    let block_to_archive =
                        match block_number.checked_sub(&confirmation_depth_k.into()) {
                            Some(block_to_archive) => block_to_archive,
                            None => {
                                continue;
                            }
                        };

                    if let Some(last_archived_block) = &mut last_archived_block_number {
                        if *last_archived_block >= block_to_archive {
                            // This block was already archived, skip
                            continue;
                        }

                        *last_archived_block = block_to_archive;
                    } else {
                        last_archived_block_number.replace(block_to_archive);
                    }

                    debug!(target: "subspace", "Archiving block {:?}", block_to_archive);

                    let block = client
                        .block(&BlockId::Number(block_to_archive))
                        .expect("Older block by number must always exist")
                        .expect("Older block by number must always exist");

                    let block_object_mapping = client
                        .runtime_api()
                        .extract_block_object_mapping(
                            &BlockId::Number(block_to_archive.saturating_sub(One::one())),
                            block.block.clone(),
                        )
                        .expect("Must be able to make runtime call");

                    for archived_segment in archiver.add_block(block.encode(), block_object_mapping)
                    {
                        let ArchivedSegment {
                            root_block,
                            pieces,
                            object_mapping,
                        } = archived_segment;

                        archived_segment_notification_sender.notify(move || {
                            ArchivedSegmentNotification {
                                root_block,
                                pieces,
                                object_mapping,
                            }
                        });

                        let _ = root_block_sender.send(root_block).await;
                    }
                }
            }
        }),
    );
}
