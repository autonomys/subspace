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

//! Consensus archiver module.
//!
//! Contains implementation of archiving process in Subspace blockchain that convers blockchain
//! history (blocks) into archived history (pieces).

use crate::{
    ArchivedSegmentNotification, BlockImportingNotification, SubspaceLink,
    SubspaceNotificationSender, SubspaceSyncOracle,
};
use codec::{Decode, Encode};
use futures::StreamExt;
use log::{debug, info, warn};
use parking_lot::Mutex;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use sc_client_api::{AuxStore, Backend as BackendT, BlockBackend, Finalizer, LockImportRun};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_INFO};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor, One, Zero};
use sp_runtime::Saturating;
use std::error::Error;
use std::future::Future;
use std::slice;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{BlockNumber, RecordedHistorySegment, SegmentHeader, SegmentIndex};

/// This corresponds to default value of `--max-runtime-instances` in Substrate
const BLOCKS_TO_ARCHIVE_CONCURRENCY: usize = 8;

#[derive(Debug)]
struct SegmentHeadersStoreInner<AS> {
    aux_store: Arc<AS>,
    next_key_index: AtomicU16,
    /// In-memory cache of segment headers
    cache: Mutex<Vec<SegmentHeader>>,
}

/// Persistent storage of segment headers
#[derive(Debug)]
pub struct SegmentHeadersStore<AS> {
    inner: Arc<SegmentHeadersStoreInner<AS>>,
}

impl<AS> Clone for SegmentHeadersStore<AS> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<AS> SegmentHeadersStore<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"segment-headers";
    const INITIAL_CACHE_CAPACITY: usize = 1_000;

    /// Create new instance
    pub fn new(aux_store: Arc<AS>) -> sp_blockchain::Result<Self> {
        let mut cache = Vec::with_capacity(Self::INITIAL_CACHE_CAPACITY);
        let mut next_key_index = 0;

        debug!(
            target: "subspace",
            "Started loading segment headers into cache"
        );
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
        debug!(
            target: "subspace",
            "Finished loading segment headers into cache"
        );

        Ok(Self {
            inner: Arc::new(SegmentHeadersStoreInner {
                aux_store,
                next_key_index: AtomicU16::new(next_key_index),
                cache: Mutex::new(cache),
            }),
        })
    }

    /// Returns last observed segment index
    pub fn max_segment_index(&self) -> Option<SegmentIndex> {
        let segment_index = self.inner.cache.lock().len().checked_sub(1)? as u64;
        Some(SegmentIndex::from(segment_index))
    }

    /// Add segment headers
    pub fn add_segment_headers(
        &self,
        segment_headers: &[SegmentHeader],
    ) -> sp_blockchain::Result<()> {
        let mut maybe_last_segment_index = self.max_segment_index();
        let mut segment_headers_to_store = Vec::with_capacity(segment_headers.len());
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
}

/// How deep (in segments) should block be in order to be finalized.
///
/// This is required for full nodes to not prune recent history such that keep-up sync in Substrate
/// works even without archival nodes (initial sync will be done from DSN).
///
/// Ideally, we'd decouple pruning from finalization, but it may require invasive changes in
/// Substrate and is not worth it right now.
/// https://github.com/paritytech/substrate/discussions/14359
pub(crate) const FINALIZATION_DEPTH_IN_SEGMENTS: usize = 5;

fn find_last_archived_block<Block, Client, AS>(
    client: &Client,
    segment_headers_store: &SegmentHeadersStore<AS>,
    best_block_to_archive: NumberFor<Block>,
) -> sp_blockchain::Result<Option<(SegmentHeader, Block, BlockObjectMapping)>>
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
            .expect("Last archived block must always be retrievable; qed")
            .block;

        let block_object_mappings = client
            .runtime_api()
            .validated_object_call_hashes(last_archived_block_hash)
            .and_then(|calls| {
                client.runtime_api().extract_block_object_mapping(
                    *last_archived_block.header().parent_hash(),
                    last_archived_block.clone(),
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
    let Some(block) = client.block(genesis_hash)? else {
        return Ok(None);
    };
    let block = block.block;

    let block_object_mappings = client
        .runtime_api()
        .validated_object_call_hashes(genesis_hash)
        .and_then(|calls| {
            client.runtime_api().extract_block_object_mapping(
                *block.header().parent_hash(),
                block.clone(),
                calls,
            )
        })
        .unwrap_or_default();

    let encoded_block = encode_genesis_block(&block);

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

fn encode_genesis_block<Block>(block: &Block) -> Vec<u8>
where
    Block: BlockT,
{
    let mut encoded_block = block.encode();
    let encoded_block_length = encoded_block.len();

    // We extend encoding of genesis block with extra data such that the very first
    // archived segment can be produced right away, bootstrapping the farming
    // process.
    //
    // Note: we add it to the end of the encoded block, so during decoding it'll
    // actually be ignored (unless `DecodeAll::decode_all()` is used) even though it
    // is technically present in encoded form.
    encoded_block.resize(RecordedHistorySegment::SIZE, 0);
    let mut rng = ChaCha8Rng::from_seed(
        block
            .header()
            .state_root()
            .as_ref()
            .try_into()
            .expect("State root in Subspace must be 32 bytes, panic otherwise; qed"),
    );
    rng.fill(&mut encoded_block[encoded_block_length..]);

    encoded_block
}

fn initialize_archiver<Block, Client, AS>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    subspace_link: &SubspaceLink<Block>,
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
                target: "subspace",
                "Last archived block {}",
                last_archived_block_number,
            );

            // Set initial value, this is needed in case only genesis block was archived and there
            // is nothing else available
            best_archived_block.replace((
                last_archived_block.hash(),
                *last_archived_block.header().number(),
            ));

            let last_archived_block_encoded = if last_archived_block.header().number().is_zero() {
                encode_genesis_block(&last_archived_block)
            } else {
                last_archived_block.encode()
            };

            Archiver::with_initial_state(
                subspace_link.kzg().clone(),
                last_segment_header,
                &last_archived_block_encoded,
                block_object_mappings,
            )
            .expect("Incorrect parameters for archiver")
        } else {
            info!(target: "subspace", "Starting archiving from genesis");

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
                                .expect("All blocks since last archived must be present; qed")
                                .block;

                            let block_object_mappings = runtime_api
                                .validated_object_call_hashes(block_hash)
                                .and_then(|calls| {
                                    client.runtime_api().extract_block_object_mapping(
                                        *block.header().parent_hash(),
                                        block.clone(),
                                        calls,
                                    )
                                })
                                .unwrap_or_default();

                            Ok((block, block_object_mappings))
                        },
                    )
                    .collect::<sp_blockchain::Result<Vec<_>>>()
            })?;

            best_archived_block = blocks_to_archive
                .last()
                .map(|(block, _block_object_mappings)| (block.hash(), *block.header().number()));

            for (block, block_object_mappings) in blocks_to_archive {
                let block_number_to_archive = *block.header().number();

                let encoded_block = if block_number_to_archive.is_zero() {
                    encode_genesis_block(&block)
                } else {
                    block.encode()
                };

                debug!(
                    target: "subspace",
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
pub fn create_subspace_archiver<Block, Backend, Client, AS, SO>(
    segment_headers_store: SegmentHeadersStore<AS>,
    subspace_link: &SubspaceLink<Block>,
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
    let InitializedArchiver {
        confirmation_depth_k,
        mut archiver,
        older_archived_segments,
        best_archived_block: (mut best_archived_block_hash, mut best_archived_block_number),
    } = initialize_archiver(&segment_headers_store, subspace_link, client.as_ref())?;

    let mut block_importing_notification_stream = subspace_link
        .block_importing_notification_stream
        .subscribe();
    let archived_segment_notification_sender =
        subspace_link.archived_segment_notification_sender.clone();
    let segment_headers = Arc::clone(&subspace_link.segment_headers);

    Ok(async move {
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
                .expect("Older block by number must always exist")
                .block;

            let parent_block_hash = *block.header().parent_hash();
            let block_hash_to_archive = block.hash();

            debug!(
                target: "subspace",
                "Archiving block {:?} ({})",
                block_number_to_archive,
                block_hash_to_archive
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
                        block.clone(),
                        calls,
                    )
                })
                .map_err(|error| {
                    sp_blockchain::Error::Application(
                        format!("Failed to retrieve block object mappings: {error}").into(),
                    )
                })?;

            let encoded_block = block.encode();
            debug!(
                target: "subspace",
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
                let maybe_block_number_to_finalize = {
                    let mut segment_headers = segment_headers.lock();
                    segment_headers.put(block_number + One::one(), new_segment_headers);

                    // Skip last `FINALIZATION_DEPTH_IN_SEGMENTS` archived segments
                    segment_headers
                        .iter()
                        .flat_map(|(_k, v)| v.iter().rev())
                        .nth(FINALIZATION_DEPTH_IN_SEGMENTS)
                        .map(|segment_header| segment_header.last_archived_block().number)
                };

                if let Some(block_number_to_finalize) = maybe_block_number_to_finalize {
                    let block_hash_to_finalize = client
                        .hash(block_number_to_finalize.into())?
                        .expect("Block about to be finalized must always exist");
                    finalize_block(
                        client.as_ref(),
                        telemetry.clone(),
                        block_hash_to_finalize,
                        block_number_to_finalize.into(),
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
