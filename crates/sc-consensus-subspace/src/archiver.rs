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

//! Consensus archiver responsible for archival of blockchain history, it is driven by block import
//! pipeline.
//!
//! Implements archiving process in Subspace blockchain that converts blockchain history (blocks)
//! into archived history (pieces).
//!
//! The main entry point here is [`create_subspace_archiver`] that will create a task, which while
//! driven will perform the archiving itself.
//!
//! Archiving is triggered by block importing notification ([`SubspaceLink::block_importing_notification_stream`])
//! and tries to archive the block at [`ChainConstants::confirmation_depth_k`](sp_consensus_subspace::ChainConstants::confirmation_depth_k)
//! depth from the block being imported. Block import will then wait for archiver to acknowledge
//! processing, which is necessary for ensuring that when the next block is imported, inherents will
//! contain segment header of newly archived block (must happen exactly in the next block).
//!
//! Archiving itself will also wait for acknowledgement by various subscribers before proceeding,
//! which includes farmer subscription, in case of reference implementation via RPC
//! (`sc-consensus-subspace-rpc`), but could also be in other ways.
//!
//! [`SegmentHeadersStore`] is maintained as a data structure containing all known (including future
//! in case of syncing) segment headers. This data structure contents is then made available to
//! other parts of the protocol that need to know what correct archival history of the blockchain
//! looks like. For example, it is used during node sync and farmer plotting in order to verify
//! pieces of archival history received from other network participants.
//!
//! [`recreate_genesis_segment`] is a bit of a hack and is useful for deriving of the genesis
//! segment that is special case since we don't have enough data in the blockchain history itself
//! during genesis in order to do the archiving.
//!
//! [`encode_block`] and [`decode_block`] are symmetric encoding/decoding functions turning
//! [`SignedBlock`]s into bytes and back.

#[cfg(test)]
mod tests;

use crate::block_import::BlockImportingNotification;
use crate::slot_worker::SubspaceSyncOracle;
use crate::{SubspaceLink, SubspaceNotificationSender};
use codec::{Decode, Encode};
use futures::StreamExt;
use parking_lot::Mutex;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use sc_client_api::{AuxStore, Backend as BackendT, BlockBackend, Finalizer, LockImportRun};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_INFO};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi, SubspaceJustification};
use sp_objects::ObjectsApi;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor, Zero};
use sp_runtime::{Justifications, Saturating};
use std::error::Error;
use std::future::Future;
use std::slice;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{BlockNumber, RecordedHistorySegment, SegmentHeader, SegmentIndex};
use tracing::{debug, info, warn};

/// This corresponds to default value of `--max-runtime-instances` in Substrate
const BLOCKS_TO_ARCHIVE_CONCURRENCY: usize = 8;

/// How deep (in segments) should block be in order to be finalized.
///
/// This is required for full nodes to not prune recent history such that keep-up sync in Substrate
/// works even without archival nodes (initial sync will be done from DSN).
///
/// Ideally, we'd decouple pruning from finalization, but it may require invasive changes in
/// Substrate and is not worth it right now.
/// https://github.com/paritytech/substrate/discussions/14359
pub(crate) const FINALIZATION_DEPTH_IN_SEGMENTS: SegmentIndex = SegmentIndex::new(5);

#[derive(Debug)]
struct SegmentHeadersStoreInner<AS> {
    aux_store: Arc<AS>,
    next_key_index: AtomicU16,
    /// In-memory cache of segment headers
    cache: Mutex<Vec<SegmentHeader>>,
}

/// Persistent storage of segment headers.
///
/// It maintains all known segment headers. During sync from DSN it is possible that this data structure contains
/// segment headers that from the point of view of the tip of the current chain are "in the future". This is expected
/// and must be accounted for in the archiver and other places.
///
/// Segment headers are stored in batches (which is more efficient to store and retrieve). Each next batch contains
/// distinct segment headers with monotonically increasing segment indices. During instantiation all previously stored
/// batches will be read and in-memory representation of the whole contents will be created such that queries to this
/// data structure are quick and not involving any disk I/O.
#[derive(Debug)]
pub struct SegmentHeadersStore<AS> {
    inner: Arc<SegmentHeadersStoreInner<AS>>,
    confirmation_depth_k: BlockNumber,
}

impl<AS> Clone for SegmentHeadersStore<AS> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            confirmation_depth_k: self.confirmation_depth_k,
        }
    }
}

impl<AS> SegmentHeadersStore<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &'static [u8] = b"segment-headers";
    const INITIAL_CACHE_CAPACITY: usize = 1_000;

    /// Create new instance
    pub fn new(
        aux_store: Arc<AS>,
        confirmation_depth_k: BlockNumber,
    ) -> sp_blockchain::Result<Self> {
        let mut cache = Vec::with_capacity(Self::INITIAL_CACHE_CAPACITY);

        debug!("Started loading segment headers into cache");
        // Segment headers are stored in batches (which is more efficient to store and retrieve), this is why code deals
        // with key indices here rather that segment indices. Essentially this iterates over keys from 0 until missing
        // entry is hit, which becomes the next key index where additional segment headers will be stored.
        let mut next_key_index = 0;
        while let Some(segment_headers) =
            aux_store
                .get_aux(&Self::key(next_key_index))?
                .map(|segment_header| {
                    Vec::<SegmentHeader>::decode(&mut segment_header.as_slice())
                        .expect("Always correct segment header unless DB is corrupted; qed")
                })
        {
            cache.extend(segment_headers);
            next_key_index += 1;
        }
        debug!("Finished loading segment headers into cache");

        Ok(Self {
            inner: Arc::new(SegmentHeadersStoreInner {
                aux_store,
                next_key_index: AtomicU16::new(next_key_index),
                cache: Mutex::new(cache),
            }),
            confirmation_depth_k,
        })
    }

    /// Returns last observed segment index
    pub fn max_segment_index(&self) -> Option<SegmentIndex> {
        let segment_index = self.inner.cache.lock().len().checked_sub(1)? as u64;
        Some(SegmentIndex::from(segment_index))
    }

    /// Add segment headers.
    ///
    /// Multiple can be inserted for efficiency purposes.
    pub fn add_segment_headers(
        &self,
        segment_headers: &[SegmentHeader],
    ) -> sp_blockchain::Result<()> {
        let mut maybe_last_segment_index = self.max_segment_index();
        let mut segment_headers_to_store = Vec::with_capacity(segment_headers.len());
        // Check all input segment headers to see which ones are not stored yet and verifying that segment indices are
        // monotonically increasing
        for segment_header in segment_headers {
            let segment_index = segment_header.segment_index();
            match maybe_last_segment_index {
                Some(last_segment_index) => {
                    if segment_index <= last_segment_index {
                        // Skip already stored segment headers
                        continue;
                    }

                    if segment_index != last_segment_index + SegmentIndex::ONE {
                        let error = format!(
                            "Segment index {} must strictly follow {}, can't store segment header",
                            segment_index, last_segment_index
                        );
                        return Err(sp_blockchain::Error::Application(error.into()));
                    }

                    segment_headers_to_store.push(segment_header);
                    maybe_last_segment_index.replace(segment_index);
                }
                None => {
                    if segment_index != SegmentIndex::ZERO {
                        let error = format!(
                            "First segment header index must be zero, found index {segment_index}"
                        );
                        return Err(sp_blockchain::Error::Application(error.into()));
                    }

                    segment_headers_to_store.push(segment_header);
                    maybe_last_segment_index.replace(segment_index);
                }
            }
        }

        if segment_headers_to_store.is_empty() {
            return Ok(());
        }

        // Insert all new segment headers into vacant key index for efficiency purposes
        // TODO: Do compaction when we have too many keys: combine multiple segment headers into a
        //  single entry for faster retrievals and more compact storage
        {
            let key_index = self.inner.next_key_index.fetch_add(1, Ordering::SeqCst);
            let key = Self::key(key_index);
            let value = segment_headers_to_store.encode();
            let insert_data = vec![(key.as_slice(), value.as_slice())];

            self.inner.aux_store.insert_aux(&insert_data, &[])?;
        }
        self.inner.cache.lock().extend(segment_headers_to_store);

        Ok(())
    }

    /// Get a single segment header
    pub fn get_segment_header(&self, segment_index: SegmentIndex) -> Option<SegmentHeader> {
        self.inner
            .cache
            .lock()
            .get(u64::from(segment_index) as usize)
            .copied()
    }

    fn key(key_index: u16) -> Vec<u8> {
        (Self::KEY_PREFIX, key_index.to_le_bytes()).encode()
    }

    /// Get segment headers that are expected to be included at specified block number.
    pub fn segment_headers_for_block(&self, block_number: BlockNumber) -> Vec<SegmentHeader> {
        let Some(last_segment_index) = self.max_segment_index() else {
            // Not initialized
            return Vec::new();
        };

        // Special case for the initial segment (for genesis block).
        if block_number == 1 {
            // If there is a segment index present, and we store monotonically increasing segment
            // headers, then the first header exists.
            return vec![self
                .get_segment_header(SegmentIndex::ZERO)
                .expect("Segment headers are stored in monotonically increasing order; qed")];
        }

        if last_segment_index == SegmentIndex::ZERO {
            // Genesis segment already included in block #1
            return Vec::new();
        }

        let mut current_segment_index = last_segment_index;
        loop {
            // If the current segment index present, and we store monotonically increasing segment
            // headers, then the current segment header exists as well.
            let current_segment_header = self
                .get_segment_header(current_segment_index)
                .expect("Segment headers are stored in monotonically increasing order; qed");

            // The block immediately after the archived segment adding the confirmation depth
            let target_block_number =
                current_segment_header.last_archived_block().number + 1 + self.confirmation_depth_k;
            if target_block_number == block_number {
                let mut headers_for_block = vec![current_segment_header];

                // Check block spanning multiple segments
                let last_archived_block_number =
                    current_segment_header.last_archived_block().number;
                let mut segment_index = current_segment_index - SegmentIndex::ONE;

                while let Some(segment_header) = self.get_segment_header(segment_index) {
                    if segment_header.last_archived_block().number == last_archived_block_number {
                        headers_for_block.insert(0, segment_header);
                        segment_index -= SegmentIndex::ONE;
                    } else {
                        break;
                    }
                }

                return headers_for_block;
            }

            // iterate segments further
            if target_block_number > block_number {
                // no need to check the initial segment
                if current_segment_index > SegmentIndex::ONE {
                    current_segment_index -= SegmentIndex::ONE
                } else {
                    break;
                }
            } else {
                return Vec::new(); // no segment headers required
            }
        }

        Vec::new() // no segment headers required
    }
}

/// Notification with block header hash that needs to be signed and sender for signature.
#[derive(Debug, Clone)]
pub struct ArchivedSegmentNotification {
    /// Archived segment.
    pub archived_segment: Arc<NewArchivedSegment>,
    /// Sender that signified the fact of receiving archived segment by farmer.
    ///
    /// This must be used to send a message or else block import pipeline will get stuck.
    pub acknowledgement_sender: TracingUnboundedSender<()>,
}

fn find_last_archived_block<Block, Client, AS>(
    client: &Client,
    segment_headers_store: &SegmentHeadersStore<AS>,
    best_block_to_archive: NumberFor<Block>,
) -> sp_blockchain::Result<Option<(SegmentHeader, SignedBlock<Block>, BlockObjectMapping)>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    AS: AuxStore,
{
    let Some(max_segment_index) = segment_headers_store.max_segment_index() else {
        return Ok(None);
    };

    if max_segment_index == SegmentIndex::ZERO {
        // Just genesis, nothing else to check
        return Ok(None);
    }

    for segment_header in (SegmentIndex::ZERO..=max_segment_index)
        .rev()
        .filter_map(|segment_index| segment_headers_store.get_segment_header(segment_index))
    {
        let last_archived_block_number = segment_header.last_archived_block().number;
        if NumberFor::<Block>::from(last_archived_block_number) > best_block_to_archive {
            // Last archived block in segment header is too high for current state of the chain
            // (segment headers store may know about more blocks in existence than is currently
            // imported)
            continue;
        }
        let Some(last_archived_block_hash) = client.hash(last_archived_block_number.into())? else {
            // This block number is not in our chain yet (segment headers store may know about more
            // blocks in existence than is currently imported)
            continue;
        };

        let last_segment_header = segment_header;

        let last_archived_block = client
            .block(last_archived_block_hash)?
            .expect("Last archived block must always be retrievable; qed");

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

        return Ok(Some((
            last_segment_header,
            last_archived_block,
            block_object_mappings,
        )));
    }

    Ok(None)
}

/// Derive genesis segment on demand, returns `Ok(None)` in case genesis block was already pruned
pub fn recreate_genesis_segment<Block, Client>(
    client: &Client,
    kzg: Kzg,
) -> Result<Option<NewArchivedSegment>, Box<dyn Error>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block>,
    Client::Api: ObjectsApi<Block>,
{
    let genesis_hash = client.info().genesis_hash;
    let Some(signed_block) = client.block(genesis_hash)? else {
        return Ok(None);
    };

    let block_object_mappings = client
        .runtime_api()
        .validated_object_call_hashes(genesis_hash)
        .and_then(|calls| {
            client.runtime_api().extract_block_object_mapping(
                *signed_block.block.header().parent_hash(),
                signed_block.block.clone(),
                calls,
            )
        })
        .unwrap_or_default();

    let encoded_block = encode_block(signed_block);

    let new_archived_segment = Archiver::new(kzg)?
        .add_block(encoded_block, block_object_mappings, false)
        .into_iter()
        .next()
        .expect("Genesis block always results in exactly one archived segment; qed");

    Ok(Some(new_archived_segment))
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

/// Encode block for archiving purposes.
///
/// Only specific Subspace justifications are included in the encoding, determined by result of
/// [`SubspaceJustification::must_be_archived`], other justifications are filtered-out.
pub fn encode_block<Block>(mut signed_block: SignedBlock<Block>) -> Vec<u8>
where
    Block: BlockT,
{
    if signed_block.block.header().number().is_zero() {
        let mut encoded_block = signed_block.encode();

        let encoded_block_length = encoded_block.len();

        // We extend encoding of genesis block with extra data such that the very first archived
        // segment can be produced right away, bootstrapping the farming process.
        //
        // Note: we add it to the end of the encoded block, so during decoding it'll actually be
        // ignored (unless `DecodeAll::decode_all()` is used) even though it is technically present
        // in encoded form.
        encoded_block.resize(RecordedHistorySegment::SIZE, 0);
        let mut rng = ChaCha8Rng::from_seed(
            signed_block
                .block
                .header()
                .state_root()
                .as_ref()
                .try_into()
                .expect("State root in Subspace must be 32 bytes, panic otherwise; qed"),
        );
        rng.fill(&mut encoded_block[encoded_block_length..]);

        encoded_block
    } else {
        // Filter out non-canonical justifications
        if let Some(justifications) = signed_block.justifications.take() {
            let mut filtered_justifications = justifications.into_iter().filter(|justification| {
                // Only Subspace justifications are to be archived
                let Some(subspace_justification) =
                    SubspaceJustification::try_from_justification(justification)
                        .and_then(|subspace_justification| subspace_justification.ok())
                else {
                    return false;
                };

                subspace_justification.must_be_archived()
            });

            if let Some(first_justification) = filtered_justifications.next() {
                let mut justifications = Justifications::from(first_justification);

                for justification in filtered_justifications {
                    justifications.append(justification);
                }

                signed_block.justifications = Some(justifications);
            }
        }

        signed_block.encode()
    }
}

/// Symmetrical to [`encode_block()`], used to decode previously encoded blocks
pub fn decode_block<Block>(mut encoded_block: &[u8]) -> Result<SignedBlock<Block>, codec::Error>
where
    Block: BlockT,
{
    SignedBlock::<Block>::decode(&mut encoded_block)
}

fn initialize_archiver<Block, Client, AS>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    subspace_link: SubspaceLink<Block>,
    client: &Client,
) -> sp_blockchain::Result<InitializedArchiver<Block>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    AS: AuxStore,
{
    let client_info = client.info();
    let best_block_number = client_info.best_number;
    let best_block_hash = client_info.best_hash;

    let confirmation_depth_k = client
        .runtime_api()
        .chain_constants(best_block_hash)?
        .confirmation_depth_k();

    let maybe_last_archived_block = find_last_archived_block(
        client,
        segment_headers_store,
        best_block_number.saturating_sub(confirmation_depth_k.into()),
    )?;
    let have_last_segment_header = maybe_last_archived_block.is_some();
    let mut best_archived_block = None;

    let mut archiver =
        if let Some((last_segment_header, last_archived_block, block_object_mappings)) =
            maybe_last_archived_block
        {
            // Continuing from existing initial state
            let last_archived_block_number = last_segment_header.last_archived_block().number;
            info!(
                %last_archived_block_number,
                "Resuming archiver from last archived block",
            );

            // Set initial value, this is needed in case only genesis block was archived and there
            // is nothing else available
            best_archived_block.replace((
                last_archived_block.block.hash(),
                *last_archived_block.block.header().number(),
            ));

            let last_archived_block_encoded = encode_block(last_archived_block);

            let archiver = Archiver::with_initial_state(
                subspace_link.kzg().clone(),
                last_segment_header,
                &last_archived_block_encoded,
                block_object_mappings,
            )
            .expect("Incorrect parameters for archiver");

            archiver
        } else {
            info!("Starting archiving from genesis");

            Archiver::new(subspace_link.kzg().clone()).expect("Incorrect parameters for archiver")
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
                .filter(|&blocks_to_archive_to| blocks_to_archive_to >= blocks_to_archive_from)
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
                "Archiving already produced blocks {}..={}",
                blocks_to_archive_from, blocks_to_archive_to,
            );

            let thread_pool = ThreadPoolBuilder::new()
                .num_threads(BLOCKS_TO_ARCHIVE_CONCURRENCY)
                .build()
                .map_err(|error| {
                    sp_blockchain::Error::Backend(format!(
                        "Failed to create thread pool for archiver initialization: {error}"
                    ))
                })?;
            // We need to limit number of threads to avoid running out of WASM instances
            let blocks_to_archive = thread_pool.install(|| {
                (blocks_to_archive_from..=blocks_to_archive_to)
                    .into_par_iter()
                    .map_init(
                        || client.runtime_api(),
                        |runtime_api, block_number| {
                            let block_hash = client
                                .hash(block_number.into())?
                                .expect("All blocks since last archived must be present; qed");

                            let block = client
                                .block(block_hash)?
                                .expect("All blocks since last archived must be present; qed");

                            let block_object_mappings = runtime_api
                                .validated_object_call_hashes(block_hash)
                                .and_then(|calls| {
                                    client.runtime_api().extract_block_object_mapping(
                                        *block.block.header().parent_hash(),
                                        block.block.clone(),
                                        calls,
                                    )
                                })
                                .unwrap_or_default();

                            Ok((block, block_object_mappings))
                        },
                    )
                    .collect::<sp_blockchain::Result<Vec<_>>>()
            })?;

            best_archived_block =
                blocks_to_archive
                    .last()
                    .map(|(block, _block_object_mappings)| {
                        (block.block.hash(), *block.block.header().number())
                    });

            for (signed_block, block_object_mappings) in blocks_to_archive {
                let block_number_to_archive = *signed_block.block.header().number();

                let encoded_block = encode_block(signed_block);

                debug!(
                    "Encoded block {} has size of {:.2} kiB",
                    block_number_to_archive,
                    encoded_block.len() as f32 / 1024.0
                );

                let archived_segments =
                    archiver.add_block(encoded_block, block_object_mappings, false);
                let new_segment_headers: Vec<SegmentHeader> = archived_segments
                    .iter()
                    .map(|archived_segment| archived_segment.segment_header)
                    .collect();

                older_archived_segments.extend(archived_segments);

                if !new_segment_headers.is_empty() {
                    segment_headers_store.add_segment_headers(&new_segment_headers)?;
                }
            }
        }
    }

    Ok(InitializedArchiver {
        confirmation_depth_k,
        archiver,
        older_archived_segments,
        best_archived_block: best_archived_block
            .expect("Must always set if there is no logical error; qed"),
    })
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
    if number.is_zero() {
        // Block zero is finalized already and generates unnecessary warning if called again
        return;
    }
    // We don't have anything useful to do with this result yet, the only source of errors was
    // logged already inside
    let _result: sp_blockchain::Result<_> = client.lock_import_and_run(|import_op| {
        // Ideally some handle to a synchronization oracle would be used to avoid unconditionally
        // notifying.
        client
            .apply_finality(import_op, hash, None, true)
            .map_err(|error| {
                warn!(
                    "Error applying finality to block {:?}: {}",
                    (hash, number),
                    error
                );
                error
            })?;

        debug!("Finalizing blocks up to ({:?}, {})", number, hash);

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
///
/// Archiver is only able to move forward and doesn't support reorgs. Upon restart it will check
/// [`SegmentHeadersStore`] and chain history to reconstruct "current" state it was in before last
/// shutdown and continue incrementally archiving blockchain history from there.
///
/// Archiving is triggered by block importing notification ([`SubspaceLink::block_importing_notification_stream`])
/// and tries to archive the block at [`ChainConstants::confirmation_depth_k`](sp_consensus_subspace::ChainConstants::confirmation_depth_k)
/// depth from the block being imported. Block import will then wait for archiver to acknowledge
/// processing, which is necessary for ensuring that when the next block is imported, inherents will
/// contain segment header of newly archived block (must happen exactly in the next block).
///
/// Once segment header is archived, notification ([`SubspaceLink::archived_segment_notification_stream`])
/// will be sent and archiver will be paused until all receivers have provided an acknowledgement
/// for it.
///
/// Archiving will be incremental during normal operation to decrease impact on block import and
/// non-incremental heavily parallel during sync process since parallel implementation is more
/// efficient overall and during sync only total sync time matters.
pub fn create_subspace_archiver<Block, Backend, Client, AS, SO>(
    segment_headers_store: SegmentHeadersStore<AS>,
    subspace_link: SubspaceLink<Block>,
    client: Arc<Client>,
    sync_oracle: SubspaceSyncOracle<SO>,
    telemetry: Option<TelemetryHandle>,
) -> sp_blockchain::Result<impl Future<Output = sp_blockchain::Result<()>> + Send + 'static>
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
    AS: AuxStore + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + 'static,
{
    let maybe_archiver = if segment_headers_store.max_segment_index().is_none() {
        Some(initialize_archiver(
            &segment_headers_store,
            subspace_link.clone(),
            client.as_ref(),
        )?)
    } else {
        None
    };

    Ok(async move {
        let archiver = match maybe_archiver {
            Some(archiver) => archiver,
            None => initialize_archiver(
                &segment_headers_store,
                subspace_link.clone(),
                client.as_ref(),
            )?,
        };

        let InitializedArchiver {
            confirmation_depth_k,
            mut archiver,
            older_archived_segments,
            best_archived_block: (mut best_archived_block_hash, mut best_archived_block_number),
        } = archiver;

        let mut block_importing_notification_stream = subspace_link
            .block_importing_notification_stream
            .subscribe();
        let archived_segment_notification_sender =
            subspace_link.archived_segment_notification_sender.clone();

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
                        .hash(block_number_to_archive)?
                        .expect("Older block by number must always exist"),
                )?
                .expect("Older block by number must always exist");

            let parent_block_hash = *block.block.header().parent_hash();
            let block_hash_to_archive = block.block.hash();

            debug!(
                "Archiving block {:?} ({})",
                block_number_to_archive, block_hash_to_archive
            );

            if parent_block_hash != best_archived_block_hash {
                let error = format!(
                    "Attempt to switch to a different fork beyond archiving depth, \
                    can't do it: parent block hash {}, best archived block hash {}",
                    parent_block_hash, best_archived_block_hash
                );
                return Err(sp_blockchain::Error::Consensus(sp_consensus::Error::Other(
                    error.into(),
                )));
            }

            best_archived_block_hash = block_hash_to_archive;

            let block_object_mappings = client
                .runtime_api()
                .validated_object_call_hashes(block_hash_to_archive)
                .and_then(|calls| {
                    client.runtime_api().extract_block_object_mapping(
                        parent_block_hash,
                        block.block.clone(),
                        calls,
                    )
                })
                .map_err(|error| {
                    sp_blockchain::Error::Application(
                        format!("Failed to retrieve block object mappings: {error}").into(),
                    )
                })?;

            let encoded_block = encode_block(block);
            debug!(
                "Encoded block {} has size of {:.2} kiB",
                block_number_to_archive,
                encoded_block.len() as f32 / 1024.0
            );

            let mut new_segment_headers = Vec::new();
            for archived_segment in archiver.add_block(
                encoded_block,
                block_object_mappings,
                !sync_oracle.is_major_syncing(),
            ) {
                let segment_header = archived_segment.segment_header;

                segment_headers_store.add_segment_headers(slice::from_ref(&segment_header))?;

                send_archived_segment_notification(
                    &archived_segment_notification_sender,
                    archived_segment,
                )
                .await;

                new_segment_headers.push(segment_header);
            }

            if !new_segment_headers.is_empty() {
                let maybe_block_number_to_finalize = segment_headers_store
                    .max_segment_index()
                    // Skip last `FINALIZATION_DEPTH_IN_SEGMENTS` archived segments
                    .and_then(|max_segment_index| {
                        max_segment_index.checked_sub(FINALIZATION_DEPTH_IN_SEGMENTS)
                    })
                    .and_then(|segment_index| {
                        segment_headers_store.get_segment_header(segment_index)
                    })
                    .map(|segment_header| segment_header.last_archived_block().number)
                    // Make sure not to finalize block number that does not yet exist (segment
                    // headers store may contain future blocks during initial sync)
                    .map(|block_number| best_archived_block_number.min(block_number.into()))
                    // Do not finalize blocks twice
                    .filter(|block_number| *block_number > client.info().finalized_number);

                if let Some(block_number_to_finalize) = maybe_block_number_to_finalize {
                    let block_hash_to_finalize = client
                        .hash(block_number_to_finalize)?
                        .expect("Block about to be finalized must always exist");
                    finalize_block(
                        client.as_ref(),
                        telemetry.clone(),
                        block_hash_to_finalize,
                        block_number_to_finalize,
                    );
                }
            }
        }

        Ok(())
    })
}

async fn send_archived_segment_notification(
    archived_segment_notification_sender: &SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment: NewArchivedSegment,
) {
    let segment_index = archived_segment.segment_header.segment_index();
    let (acknowledgement_sender, mut acknowledgement_receiver) =
        tracing_unbounded::<()>("subspace_acknowledgement", 100);
    // Keep `archived_segment` around until all acknowledgements are received since some receivers
    // might use weak references
    let archived_segment = Arc::new(archived_segment);
    let archived_segment_notification = ArchivedSegmentNotification {
        archived_segment: Arc::clone(&archived_segment),
        acknowledgement_sender,
    };

    archived_segment_notification_sender.notify(move || archived_segment_notification);

    while acknowledgement_receiver.next().await.is_some() {
        debug!(
            "Archived segment notification acknowledged: {}",
            segment_index
        );
    }
}
