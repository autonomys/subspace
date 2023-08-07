use crate::single_disk_plot::piece_cache::{DiskPieceCache, Offset};
use crate::utils::AsyncJoinOnDrop;
use crate::NodeClient;
use futures::lock::Mutex;
use futures::{select, FutureExt, StreamExt};
use parking_lot::RwLock;
use rayon::prelude::*;
use std::collections::HashMap;
use std::mem;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, SegmentIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::{ProviderRecord, RecordKey};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{KeyWrapper, LocalRecordProvider, UniqueRecordBinaryHeap};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

const WORKER_CHANNEL_CAPACITY: usize = 100;
/// Make caches available as they are building without waiting for the initialization to finish,
/// this number defines an interval in pieces after which cache is updated
const INTERMEDIATE_CACHE_UPDATE_INTERVAL: usize = 100;

#[derive(Debug, Clone)]
struct DiskPieceCacheState {
    stored_pieces: HashMap<RecordKey, Offset>,
    free_offsets: Vec<Offset>,
    backend: DiskPieceCache,
}

#[derive(Debug)]
enum WorkerCommand {
    ReplaceBackingCaches { new_caches: Vec<DiskPieceCache> },
    ForgetKey { key: RecordKey },
}

#[derive(Debug)]
struct CacheWorkerState {
    heap: UniqueRecordBinaryHeap<KeyWrapper<PieceIndex>>,
    last_segment_index: SegmentIndex,
}

/// Cache worker used to drive the cache
#[must_use = "Cache will not work unless its worker is running"]
pub struct CacheWorker<NC> {
    peer_id: PeerId,
    node_client: NC,
    /// It is important to always lock caches AFTER worker state in order to avoid deadlock!
    caches: Arc<RwLock<Vec<DiskPieceCacheState>>>,
    worker_receiver: Option<mpsc::Receiver<WorkerCommand>>,
}

impl<NC> CacheWorker<NC>
where
    NC: NodeClient,
{
    /// Run the cache worker with provided piece getter
    pub async fn run<PG>(mut self, piece_getter: PG)
    where
        PG: PieceGetter,
    {
        // Limit is dynamically set later
        // It is important to always lock worker state BEFORE caches in order to avoid deadlock!
        let worker_state = Mutex::new(CacheWorkerState {
            heap: UniqueRecordBinaryHeap::new(self.peer_id, 0),
            last_segment_index: SegmentIndex::ZERO,
        });

        let mut worker_receiver = self
            .worker_receiver
            .take()
            .expect("Always set during worker instantiation");

        if let Some(WorkerCommand::ReplaceBackingCaches { new_caches }) =
            worker_receiver.recv().await
        {
            self.initialize(&piece_getter, &worker_state, new_caches)
                .await;
        } else {
            // Piece cache is dropped before backing caches were sent
            return;
        }

        loop {
            select! {
                maybe_command = worker_receiver.recv().fuse() => {
                    let Some(command) = maybe_command else {
                        // Nothing else left to do
                        return;
                    };

                    self.handle_command(command, &piece_getter, &worker_state).await;
                }
                _ = self.keep_up_sync(&piece_getter, &worker_state).fuse() => {
                    // Keep-up sync only ends with subscription, which lasts for duration of an
                    // instance
                    return;
                }
            }
        }
    }

    async fn handle_command<PG>(
        &self,
        command: WorkerCommand,
        piece_getter: &PG,
        worker_state: &Mutex<CacheWorkerState>,
    ) where
        PG: PieceGetter,
    {
        match command {
            WorkerCommand::ReplaceBackingCaches { new_caches } => {
                self.initialize(piece_getter, worker_state, new_caches)
                    .await;
            }
            // TODO: Consider implementing optional re-sync of the piece instead of just forgetting
            WorkerCommand::ForgetKey { key } => {
                let mut worker_state = worker_state.lock().await;
                let mut caches = self.caches.write();

                for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                    let Some(offset) = cache.stored_pieces.remove(&key) else {
                        // Not this disk farm
                        continue;
                    };

                    // Making offset as unoccupied and remove corresponding key from heap
                    cache.free_offsets.push(offset);
                    match cache.backend.read_piece_index(offset) {
                        Some(piece_index) => {
                            worker_state.heap.remove(KeyWrapper(piece_index));
                        }
                        None => {
                            warn!(
                                %disk_farm_index,
                                %offset,
                                "Piece index out of range, this is likely an implementation bug, \
                                not freeing heap element"
                            );
                        }
                    }
                    return;
                }
            }
        }
    }

    async fn initialize<PG>(
        &self,
        piece_getter: &PG,
        worker_state: &Mutex<CacheWorkerState>,
        new_caches: Vec<DiskPieceCache>,
    ) where
        PG: PieceGetter,
    {
        info!("Initializing piece cache");
        let mut worker_state = worker_state.lock().await;
        // Pull old cache state since it will be replaced with a new one and reuse its allocations
        let cache_state = mem::take(&mut *self.caches.write());
        let mut stored_pieces = Vec::with_capacity(new_caches.len());
        let mut free_offsets = Vec::with_capacity(new_caches.len());
        for state in cache_state {
            stored_pieces.push(state.stored_pieces);
            free_offsets.push(state.free_offsets);
        }
        stored_pieces.resize(new_caches.len(), HashMap::default());
        free_offsets.resize(new_caches.len(), Vec::default());

        debug!("Collecting pieces that were in the cache before");

        // Build cache state of all backends
        let mut caches = stored_pieces
            .into_par_iter()
            .zip(free_offsets)
            .zip(new_caches)
            .map(|((mut stored_pieces, mut free_offsets), new_cache)| {
                let contents = new_cache.contents();
                stored_pieces.clear();
                stored_pieces.reserve(contents.len());
                free_offsets.clear();

                for (offset, maybe_piece_index) in contents {
                    match maybe_piece_index {
                        Some(piece_index) => {
                            stored_pieces
                                .insert(RecordKey::from(piece_index.hash().to_multihash()), offset);
                        }
                        None => {
                            free_offsets.push(offset);
                        }
                    }
                }

                DiskPieceCacheState {
                    stored_pieces,
                    free_offsets,
                    backend: new_cache,
                }
            })
            .collect::<Vec<_>>();

        info!("Synchronizing cache");

        let last_segment_index = match self.node_client.farmer_app_info().await {
            Ok(farmer_app_info) => farmer_app_info.protocol_info.history_size.segment_index(),
            Err(error) => {
                error!(
                    %error,
                    "Failed to get farmer app info from node, keeping old cache state without \
                    updates"
                );

                // Not the latest, but at least something
                *self.caches.write() = caches;
                return;
            }
        };

        worker_state.heap.clear();
        // Change limit to number of pieces
        worker_state.heap.set_limit(
            caches
                .iter()
                .map(|state| state.stored_pieces.len() + state.free_offsets.len())
                .sum::<usize>(),
        );

        for segment_index in SegmentIndex::ZERO..=last_segment_index {
            for piece_index in segment_index.segment_piece_indexes() {
                worker_state.heap.insert(KeyWrapper(piece_index));
            }
        }

        // This hashset is faster than `heap`
        // Clippy complains about `RecordKey`, but it is not changing here, so it is fine
        #[allow(clippy::mutable_key_type)]
        let mut inserted_piece_indices = worker_state
            .heap
            .keys()
            .map(|KeyWrapper(piece_index)| {
                (
                    RecordKey::from(piece_index.hash().to_multihash()),
                    *piece_index,
                )
            })
            .collect::<HashMap<_, _>>();

        caches.iter_mut().for_each(|state| {
            // Filter-out piece indices that are stored, but should not be as well as clean
            // `inserted_piece_indices` from already stored piece indices, leaving just those that are
            // still missing in cache
            state
                .stored_pieces
                .extract_if(|key, _offset| inserted_piece_indices.remove(key).is_none())
                .for_each(|(_piece_index, offset)| {
                    state.free_offsets.push(offset);
                });
        });

        // TODO: Can probably do concurrency here
        for (index, piece_index) in inserted_piece_indices.into_values().enumerate() {
            let result = piece_getter
                .get_piece(piece_index, PieceGetterRetryPolicy::Limited(1))
                .await;

            let piece = match result {
                Ok(Some(piece)) => piece,
                Ok(None) => {
                    debug!(%piece_index, "Couldn't find piece");
                    continue;
                }
                Err(error) => {
                    debug!(%error, %piece_index, "Failed to get piece for piece cache");
                    continue;
                }
            };

            // Find plot in which there is a place for new piece to be stored
            for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                let Some(offset) = cache.free_offsets.pop() else {
                    continue;
                };

                if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece) {
                    error!(
                        %error,
                        %disk_farm_index,
                        %piece_index,
                        %offset,
                        "Failed to write piece into cache"
                    );
                    continue;
                }
                cache
                    .stored_pieces
                    .insert(RecordKey::from(piece_index.hash().to_multihash()), offset);
            }

            if (index + 1) % INTERMEDIATE_CACHE_UPDATE_INTERVAL == 0 {
                *self.caches.write() = caches.clone();
            }
        }

        *self.caches.write() = caches;
        worker_state.last_segment_index = last_segment_index;

        info!("Finished cache initialization");
    }

    async fn keep_up_sync<PG>(&self, piece_getter: &PG, worker_state: &Mutex<CacheWorkerState>)
    where
        PG: PieceGetter,
    {
        let mut segment_headers_notifications =
            match self.node_client.subscribe_archived_segment_headers().await {
                Ok(segment_headers_notifications) => segment_headers_notifications,
                Err(error) => {
                    error!(%error, "Failed to subscribe to archived segments notifications");
                    return;
                }
            };

        // Keep up with segment indices that were potentially created since reinitialization,
        // depending on the size of the diff this may pause block production for a while (due to
        // subscription we have created above)
        self.keep_up_after_initial_sync(piece_getter, worker_state)
            .await;

        while let Some(segment_header) = segment_headers_notifications.next().await {
            let segment_index = segment_header.segment_index();
            debug!(%segment_index, "Starting to process newly archived segment");

            let mut worker_state = worker_state.lock().await;

            if worker_state.last_segment_index >= segment_index {
                continue;
            }

            // TODO: Can probably do concurrency here
            for piece_index in segment_index.segment_piece_indexes() {
                if !worker_state
                    .heap
                    .should_include_key(KeyWrapper(piece_index))
                {
                    trace!(%piece_index, "Piece doesn't need to be cached #1");

                    continue;
                }

                trace!(%piece_index, "Piece needs to be cached #1");

                let maybe_piece = match self.node_client.piece(piece_index).await {
                    Ok(maybe_piece) => maybe_piece,
                    Err(error) => {
                        error!(
                            %error,
                            %segment_index,
                            %piece_index,
                            "Failed to retrieve piece from node right after archiving, this \
                            should never happen and is an implementation bug"
                        );
                        continue;
                    }
                };

                let Some(piece) = maybe_piece else {
                    error!(
                        %segment_index,
                        %piece_index,
                        "Failed to retrieve piece from node right after archiving, this should \
                        never happen and is an implementation bug"
                    );
                    continue;
                };

                self.persist_piece_in_cache(piece_index, piece, &mut worker_state);
            }

            worker_state.last_segment_index = segment_index;

            match self
                .node_client
                .acknowledge_archived_segment_header(segment_index)
                .await
            {
                Ok(()) => {
                    debug!(%segment_index, "Acknowledged archived segment");
                }
                Err(error) => {
                    error!(%segment_index, ?error, "Failed to acknowledge archived segment");
                }
            };

            debug!(%segment_index, "Finished processing newly archived segment");
        }
    }

    async fn keep_up_after_initial_sync<PG>(
        &self,
        piece_getter: &PG,
        worker_state: &Mutex<CacheWorkerState>,
    ) where
        PG: PieceGetter,
    {
        let mut worker_state = worker_state.lock().await;
        let last_segment_index = match self.node_client.farmer_app_info().await {
            Ok(farmer_app_info) => farmer_app_info.protocol_info.history_size.segment_index(),
            Err(error) => {
                error!(
                    %error,
                    "Failed to get farmer app info from node, keeping old cache state without \
                    updates"
                );
                return;
            }
        };

        if last_segment_index <= worker_state.last_segment_index {
            return;
        }

        info!(
            "Syncing piece cache to the latest history size, this may pause block production if \
            takes too long"
        );

        // Keep up with segment indices that were potentially created since reinitialization
        let piece_indices = (worker_state.last_segment_index..=last_segment_index)
            .flat_map(|segment_index| segment_index.segment_piece_indexes());

        // TODO: Can probably do concurrency here
        for piece_index in piece_indices {
            let key = KeyWrapper(piece_index);
            if !worker_state.heap.should_include_key(key) {
                trace!(%piece_index, "Piece doesn't need to be cached #1");

                continue;
            }

            trace!(%piece_index, "Piece needs to be cached #1");

            let result = piece_getter
                .get_piece(piece_index, PieceGetterRetryPolicy::Limited(1))
                .await;

            let piece = match result {
                Ok(Some(piece)) => piece,
                Ok(None) => {
                    debug!(%piece_index, "Couldn't find piece");
                    continue;
                }
                Err(error) => {
                    debug!(
                        %error,
                        %piece_index,
                        "Failed to get piece for piece cache"
                    );
                    continue;
                }
            };

            self.persist_piece_in_cache(piece_index, piece, &mut worker_state);
        }

        info!("Finished syncing piece cache to the latest history size");

        worker_state.last_segment_index = last_segment_index;
    }

    /// This assumes it was already checked that piece needs to be stored, no verification for this
    /// is done internally and invariants will break if this assumption doesn't hold true
    fn persist_piece_in_cache(
        &self,
        piece_index: PieceIndex,
        piece: Piece,
        worker_state: &mut CacheWorkerState,
    ) {
        let record_key = RecordKey::from(piece_index.hash().to_multihash());
        let heap_key = KeyWrapper(piece_index);

        let mut caches = self.caches.write();
        match worker_state.heap.insert(heap_key) {
            // Entry is already occupied, we need to find and replace old piece with new one
            Some(KeyWrapper(old_piece_index)) => {
                for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                    let old_record_key = RecordKey::from(old_piece_index.hash().to_multihash());
                    let Some(offset) = cache.stored_pieces.remove(&old_record_key) else {
                        // Not this disk farm
                        continue;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece) {
                        error!(
                            %error,
                            %disk_farm_index,
                            %piece_index,
                            %offset,
                            "Failed to write piece into cache"
                        );
                    } else {
                        trace!(
                            %disk_farm_index,
                            %old_piece_index,
                            %piece_index,
                            %offset,
                            "Successfully replaced old cached piece"
                        );
                        cache.stored_pieces.insert(record_key, offset);
                    }
                    return;
                }

                warn!(
                    %old_piece_index,
                    %piece_index,
                    "Should have replaced cached piece, but it didn't happen, this is an \
                    implementation bug"
                );
            }
            // There is free space in cache, need to find a free spot and place piece there
            None => {
                for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                    let Some(offset) = cache.free_offsets.pop() else {
                        // Not this disk farm
                        continue;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece) {
                        error!(
                            %error,
                            %disk_farm_index,
                            %piece_index,
                            %offset,
                            "Failed to write piece into cache"
                        );
                    } else {
                        trace!(
                            %disk_farm_index,
                            %piece_index,
                            %offset,
                            "Successfully stored piece in cache"
                        );
                        cache.stored_pieces.insert(record_key, offset);
                    }
                    return;
                }

                warn!(
                    %piece_index,
                    "Should have inserted piece into cache, but it didn't happen, this is an \
                    implementation bug"
                );
            }
        };
    }
}

/// Piece cache that aggregates caches of multiple disks
#[derive(Debug, Clone)]
pub struct PieceCache {
    peer_id: PeerId,
    /// Individual disk caches where pieces are stored
    caches: Arc<RwLock<Vec<DiskPieceCacheState>>>,
    // We do not want to increase capacity unnecessarily on clone
    worker_sender: mpsc::Sender<WorkerCommand>,
}

impl PieceCache {
    /// Create new piece cache instance and corresponding worker.
    ///
    /// NOTE: Returned future is async, but does blocking operations and should be running in
    /// dedicated thread.
    pub fn new<NC>(node_client: NC, peer_id: PeerId) -> (Self, CacheWorker<NC>)
    where
        NC: NodeClient,
    {
        let caches = Arc::default();
        let (worker_sender, worker_receiver) = mpsc::channel(WORKER_CHANNEL_CAPACITY);

        let instance = Self {
            peer_id,
            caches: Arc::clone(&caches),
            worker_sender,
        };
        let worker = CacheWorker {
            peer_id,
            node_client,
            caches,
            worker_receiver: Some(worker_receiver),
        };

        (instance, worker)
    }

    /// Get piece from cache
    pub async fn get_piece(&self, key: RecordKey) -> Option<Piece> {
        let caches = Arc::clone(&self.caches);

        let maybe_piece_fut = tokio::task::spawn_blocking({
            let key = key.clone();
            let worker_sender = self.worker_sender.clone();

            move || {
                for (disk_farm_index, cache) in caches.read().iter().enumerate() {
                    let Some(&offset) = cache.stored_pieces.get(&key) else {
                        continue;
                    };
                    match cache.backend.read_piece(offset) {
                        Ok(maybe_piece) => {
                            return maybe_piece;
                        }
                        Err(error) => {
                            error!(
                                %error,
                                %disk_farm_index,
                                ?key,
                                %offset,
                                "Error while reading piece from cache, might be a disk corruption"
                            );

                            if let Err(error) =
                                worker_sender.blocking_send(WorkerCommand::ForgetKey { key })
                            {
                                trace!(%error, "Failed to send ForgetKey command to worker");
                            }

                            return None;
                        }
                    }
                }

                None
            }
        });

        match AsyncJoinOnDrop::new(maybe_piece_fut).await {
            Ok(maybe_piece) => maybe_piece,
            Err(error) => {
                error!(%error, ?key, "Piece reading task failed");
                None
            }
        }
    }

    pub async fn replace_backing_caches(&self, new_caches: Vec<DiskPieceCache>) {
        if let Err(error) = self
            .worker_sender
            .send(WorkerCommand::ReplaceBackingCaches { new_caches })
            .await
        {
            warn!(%error, "Failed to replace backing caches, worker exited");
        }
    }
}

impl LocalRecordProvider for PieceCache {
    fn record(&self, key: &RecordKey) -> Option<ProviderRecord> {
        // It is okay to take read lock here, writes locks are very infrequent and very short
        for cache in self.caches.read().iter() {
            if cache.stored_pieces.contains_key(key) {
                // Note: We store our own provider records locally without local addresses
                // to avoid redundant storage and outdated addresses. Instead these are
                // acquired on demand when returning a `ProviderRecord` for the local node.
                return Some(ProviderRecord {
                    key: key.clone(),
                    provider: self.peer_id,
                    expires: None,
                    addresses: Vec::new(),
                });
            };
        }

        None
    }
}
