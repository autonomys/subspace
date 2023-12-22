#[cfg(test)]
mod tests;

use crate::node_client::NodeClient;
use crate::single_disk_farm::piece_cache::{DiskPieceCache, Offset};
use crate::utils::AsyncJoinOnDrop;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parking_lot::RwLock;
use rayon::prelude::*;
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::{fmt, mem};
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::{ProviderRecord, RecordKey};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{KeyWrapper, LocalRecordProvider, UniqueRecordBinaryHeap};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

const WORKER_CHANNEL_CAPACITY: usize = 100;
const CONCURRENT_PIECES_TO_DOWNLOAD: usize = 1_000;
/// Make caches available as they are building without waiting for the initialization to finish,
/// this number defines an interval in pieces after which cache is updated
const INTERMEDIATE_CACHE_UPDATE_INTERVAL: usize = 100;
/// Get piece retry attempts number.
const PIECE_GETTER_RETRY_NUMBER: NonZeroU16 = NonZeroU16::new(4).expect("Not zero; qed");

type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Default, Debug)]
struct Handlers {
    progress: Handler<f32>,
}

#[derive(Debug, Clone)]
struct DiskPieceCacheState {
    stored_pieces: HashMap<RecordKey, Offset>,
    free_offsets: Vec<Offset>,
    backend: DiskPieceCache,
}

#[derive(Debug)]
enum WorkerCommand {
    ReplaceBackingCaches {
        new_caches: Vec<DiskPieceCache>,
        acknowledgement: oneshot::Sender<()>,
    },
    ForgetKey {
        key: RecordKey,
    },
}

#[derive(Debug)]
struct CacheWorkerState {
    heap: UniqueRecordBinaryHeap<KeyWrapper<PieceIndex>>,
    last_segment_index: SegmentIndex,
}

/// Cache worker used to drive the cache
#[derive(Debug)]
#[must_use = "Cache will not work unless its worker is running"]
pub struct CacheWorker<NC>
where
    NC: fmt::Debug,
{
    peer_id: PeerId,
    node_client: NC,
    caches: Arc<RwLock<Vec<DiskPieceCacheState>>>,
    handlers: Arc<Handlers>,
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
        let mut worker_state = CacheWorkerState {
            heap: UniqueRecordBinaryHeap::new(self.peer_id, 0),
            last_segment_index: SegmentIndex::ZERO,
        };

        let mut worker_receiver = self
            .worker_receiver
            .take()
            .expect("Always set during worker instantiation");

        if let Some(WorkerCommand::ReplaceBackingCaches {
            new_caches,
            acknowledgement,
        }) = worker_receiver.recv().await
        {
            self.initialize(&piece_getter, &mut worker_state, new_caches)
                .await;
            // Doesn't matter if receiver is still waiting for acknowledgement
            let _ = acknowledgement.send(());
        } else {
            // Piece cache is dropped before backing caches were sent
            return;
        }

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
        self.keep_up_after_initial_sync(&piece_getter, &mut worker_state)
            .await;

        loop {
            select! {
                maybe_command = worker_receiver.recv().fuse() => {
                    let Some(command) = maybe_command else {
                        // Nothing else left to do
                        return;
                    };

                    self.handle_command(command, &piece_getter, &mut worker_state).await;
                }
                maybe_segment_header = segment_headers_notifications.next().fuse() => {
                    if let Some(segment_header) = maybe_segment_header {
                        self.process_segment_header(segment_header, &mut worker_state).await;
                    } else {
                        // Keep-up sync only ends with subscription, which lasts for duration of an
                        // instance
                        return;
                    }
                }
            }
        }
    }

    async fn handle_command<PG>(
        &self,
        command: WorkerCommand,
        piece_getter: &PG,
        worker_state: &mut CacheWorkerState,
    ) where
        PG: PieceGetter,
    {
        match command {
            WorkerCommand::ReplaceBackingCaches {
                new_caches,
                acknowledgement,
            } => {
                self.initialize(piece_getter, worker_state, new_caches)
                    .await;
                // Doesn't matter if receiver is still waiting for acknowledgement
                let _ = acknowledgement.send(());
            }
            // TODO: Consider implementing optional re-sync of the piece instead of just forgetting
            WorkerCommand::ForgetKey { key } => {
                let mut caches = self.caches.write();

                for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                    let Some(offset) = cache.stored_pieces.remove(&key) else {
                        // Not this disk farm
                        continue;
                    };

                    // Making offset as unoccupied and remove corresponding key from heap
                    cache.free_offsets.push(offset);
                    match cache.backend.read_piece_index(offset) {
                        Ok(Some(piece_index)) => {
                            worker_state.heap.remove(KeyWrapper(piece_index));
                        }
                        Ok(None) => {
                            warn!(
                                %disk_farm_index,
                                %offset,
                                "Piece index out of range, this is likely an implementation bug, \
                                not freeing heap element"
                            );
                        }
                        Err(error) => {
                            error!(
                                %error,
                                %disk_farm_index,
                                ?key,
                                %offset,
                                "Error while reading piece from cache, might be a disk corruption"
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
        worker_state: &mut CacheWorkerState,
        new_caches: Vec<DiskPieceCache>,
    ) where
        PG: PieceGetter,
    {
        info!("Initializing piece cache");
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
                                .insert(RecordKey::from(piece_index.to_multihash()), offset);
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

        info!("Synchronizing piece cache");

        // TODO: Query from the DSN too such that we don't build outdated cache at start if node is
        //  not synced fully
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

        debug!(%last_segment_index, "Identified last segment index");

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
        let mut piece_indices_to_store = worker_state
            .heap
            .keys()
            .map(|KeyWrapper(piece_index)| {
                (RecordKey::from(piece_index.to_multihash()), *piece_index)
            })
            .collect::<HashMap<_, _>>();

        caches.iter_mut().for_each(|state| {
            // Filter-out piece indices that are stored, but should not be as well as clean
            // `inserted_piece_indices` from already stored piece indices, leaving just those that are
            // still missing in cache
            state
                .stored_pieces
                .extract_if(|key, _offset| piece_indices_to_store.remove(key).is_none())
                .for_each(|(_piece_index, offset)| {
                    state.free_offsets.push(offset);
                });
        });

        // Store whatever correct pieces are immediately available after restart
        *self.caches.write() = caches.clone();

        debug!(
            count = %piece_indices_to_store.len(),
            "Identified piece indices that should be cached",
        );

        let mut piece_indices_to_store = piece_indices_to_store.into_values();

        let download_piece = |piece_index| async move {
            trace!(%piece_index, "Downloading piece");

            let result = piece_getter
                .get_piece(
                    piece_index,
                    PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
                )
                .await;

            match result {
                Ok(Some(piece)) => {
                    trace!(%piece_index, "Downloaded piece successfully");

                    Some((piece_index, piece))
                }
                Ok(None) => {
                    debug!(%piece_index, "Couldn't find piece");
                    None
                }
                Err(error) => {
                    debug!(%error, %piece_index, "Failed to get piece for piece cache");
                    None
                }
            }
        };

        let pieces_to_download_total = piece_indices_to_store.len();
        let mut downloading_pieces = piece_indices_to_store
            .by_ref()
            .take(CONCURRENT_PIECES_TO_DOWNLOAD)
            .map(download_piece)
            .collect::<FuturesUnordered<_>>();

        let mut downloaded_pieces_count = 0;
        self.handlers.progress.call_simple(&0.0);
        while let Some(maybe_piece) = downloading_pieces.next().await {
            // Push another piece to download
            if let Some(piece_index_to_download) = piece_indices_to_store.next() {
                downloading_pieces.push(download_piece(piece_index_to_download));
            }

            let Some((piece_index, piece)) = maybe_piece else {
                continue;
            };

            // Find plot in which there is a place for new piece to be stored
            if !caches
                .iter_mut()
                .enumerate()
                .any(|(disk_farm_index, cache)| {
                    let Some(offset) = cache.free_offsets.pop() else {
                        return false;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece) {
                        error!(
                            %error,
                            %disk_farm_index,
                            %piece_index,
                            %offset,
                            "Failed to write piece into cache"
                        );
                        return false;
                    }
                    cache
                        .stored_pieces
                        .insert(RecordKey::from(piece_index.to_multihash()), offset);
                    true
                })
            {
                error!(
                    %piece_index,
                    "Failed to store piece in cache, there was no space"
                );
            }

            downloaded_pieces_count += 1;
            let progress = downloaded_pieces_count as f32 / pieces_to_download_total as f32 * 100.0;
            if downloaded_pieces_count % INTERMEDIATE_CACHE_UPDATE_INTERVAL == 0 {
                *self.caches.write() = caches.clone();

                info!("Piece cache sync {progress:.2}% complete");
            }
            self.handlers.progress.call_simple(&progress);
        }

        *self.caches.write() = caches;
        self.handlers.progress.call_simple(&100.0);
        worker_state.last_segment_index = last_segment_index;

        info!("Finished piece cache synchronization");
    }

    async fn process_segment_header(
        &self,
        segment_header: SegmentHeader,
        worker_state: &mut CacheWorkerState,
    ) {
        let segment_index = segment_header.segment_index();
        debug!(%segment_index, "Starting to process newly archived segment");

        if worker_state.last_segment_index < segment_index {
            debug!(%segment_index, "Downloading potentially useful pieces");

            // We do not insert pieces into cache/heap yet, so we don't know if all of these pieces
            // will be included, but there is a good chance they will be and we want to acknowledge
            // new segment header as soon as possible
            let pieces_to_maybe_include = segment_index
                .segment_piece_indexes()
                .into_iter()
                .filter(|&piece_index| {
                    let maybe_include = worker_state
                        .heap
                        .should_include_key(KeyWrapper(piece_index));
                    if !maybe_include {
                        trace!(%piece_index, "Piece doesn't need to be cached #1");
                    }

                    maybe_include
                })
                .map(|piece_index| async move {
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

                            return None;
                        }
                    };

                    let Some(piece) = maybe_piece else {
                        error!(
                            %segment_index,
                            %piece_index,
                            "Failed to retrieve piece from node right after archiving, this should \
                            never happen and is an implementation bug"
                        );

                        return None;
                    };

                    Some((piece_index, piece))
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_piece| async move { maybe_piece })
                .collect::<Vec<_>>()
                .await;

            debug!(%segment_index, "Downloaded potentially useful pieces");

            self.acknowledge_archived_segment_processing(segment_index)
                .await;

            // Go through potentially matching pieces again now that segment was acknowledged and
            // try to persist them if necessary
            for (piece_index, piece) in pieces_to_maybe_include {
                if !worker_state
                    .heap
                    .should_include_key(KeyWrapper(piece_index))
                {
                    trace!(%piece_index, "Piece doesn't need to be cached #2");

                    continue;
                }

                trace!(%piece_index, "Piece needs to be cached #1");

                self.persist_piece_in_cache(piece_index, piece, worker_state);
            }

            worker_state.last_segment_index = segment_index;
        } else {
            self.acknowledge_archived_segment_processing(segment_index)
                .await;
        }

        debug!(%segment_index, "Finished processing newly archived segment");
    }

    async fn acknowledge_archived_segment_processing(&self, segment_index: SegmentIndex) {
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
    }

    async fn keep_up_after_initial_sync<PG>(
        &self,
        piece_getter: &PG,
        worker_state: &mut CacheWorkerState,
    ) where
        PG: PieceGetter,
    {
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
                trace!(%piece_index, "Piece doesn't need to be cached #3");

                continue;
            }

            trace!(%piece_index, "Piece needs to be cached #2");

            let result = piece_getter
                .get_piece(
                    piece_index,
                    PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
                )
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

            self.persist_piece_in_cache(piece_index, piece, worker_state);
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
        let record_key = RecordKey::from(piece_index.to_multihash());
        let heap_key = KeyWrapper(piece_index);

        let mut caches = self.caches.write();
        match worker_state.heap.insert(heap_key) {
            // Entry is already occupied, we need to find and replace old piece with new one
            Some(KeyWrapper(old_piece_index)) => {
                for (disk_farm_index, cache) in caches.iter_mut().enumerate() {
                    let old_record_key = RecordKey::from(old_piece_index.to_multihash());
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
    handlers: Arc<Handlers>,
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
        let handlers = Arc::new(Handlers::default());

        let instance = Self {
            peer_id,
            caches: Arc::clone(&caches),
            handlers: Arc::clone(&handlers),
            worker_sender,
        };
        let worker = CacheWorker {
            peer_id,
            node_client,
            caches,
            handlers,
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

        match AsyncJoinOnDrop::new(maybe_piece_fut, false).await {
            Ok(maybe_piece) => maybe_piece,
            Err(error) => {
                error!(%error, ?key, "Piece reading task failed");
                None
            }
        }
    }

    /// Initialize replacement of backing caches, returns acknowledgement receiver that can be used
    /// to identify when cache initialization has finished
    pub async fn replace_backing_caches(
        &self,
        new_caches: Vec<DiskPieceCache>,
    ) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        if let Err(error) = self
            .worker_sender
            .send(WorkerCommand::ReplaceBackingCaches {
                new_caches,
                acknowledgement: sender,
            })
            .await
        {
            warn!(%error, "Failed to replace backing caches, worker exited");
        }

        receiver
    }

    /// Subscribe to cache sync notifications
    pub fn on_sync_progress(&self, callback: HandlerFn<f32>) -> HandlerId {
        self.handlers.progress.add(callback)
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
