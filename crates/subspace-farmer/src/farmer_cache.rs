//! A container that caches pieces
//!
//! Farmer cache is a container that orchestrates a bunch of piece and plot caches that together
//! persist pieces in a way that is easy to retrieve comparing to decoding pieces from plots.

#[cfg(test)]
mod tests;

use crate::farm::{MaybePieceStoredResult, PieceCache, PieceCacheId, PieceCacheOffset, PlotCache};
use crate::node_client::NodeClient;
use crate::utils::run_future_in_dedicated_thread;
use async_lock::RwLock as AsyncRwLock;
use event_listener_primitives::{Bag, HandlerId};
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{select, stream, FutureExt, StreamExt};
use rayon::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, mem};
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_farmer_components::PieceGetter;
use subspace_networking::libp2p::kad::{ProviderRecord, RecordKey};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{KeyWrapper, LocalRecordProvider, UniqueRecordBinaryHeap};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::{block_in_place, yield_now};
use tracing::{debug, error, info, trace, warn};

const WORKER_CHANNEL_CAPACITY: usize = 100;
const CONCURRENT_PIECES_TO_DOWNLOAD: usize = 1_000;
/// Make caches available as they are building without waiting for the initialization to finish,
/// this number defines an interval in pieces after which cache is updated
const INTERMEDIATE_CACHE_UPDATE_INTERVAL: usize = 100;
const INITIAL_SYNC_FARM_INFO_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// How long to wait for `is_piece_maybe_stored` response from plot cache before timing out in order
/// to prevent blocking of executor for too long
const IS_PIECE_MAYBE_STORED_TIMEOUT: Duration = Duration::from_millis(100);

type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Default, Debug)]
struct Handlers {
    progress: Handler<f32>,
}

#[derive(Debug, Clone)]
struct PieceCacheState {
    stored_pieces: HashMap<RecordKey, PieceCacheOffset>,
    free_offsets: VecDeque<PieceCacheOffset>,
    backend: Arc<dyn PieceCache>,
}

#[derive(Debug)]
enum WorkerCommand {
    ReplaceBackingCaches {
        new_piece_caches: Vec<Arc<dyn PieceCache>>,
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

/// Farmer cache worker used to drive the farmer cache backend
#[derive(Debug)]
#[must_use = "Farmer cache will not work unless its worker is running"]
pub struct FarmerCacheWorker<NC>
where
    NC: fmt::Debug,
{
    peer_id: PeerId,
    node_client: NC,
    piece_caches: Arc<AsyncRwLock<Vec<PieceCacheState>>>,
    plot_caches: Arc<PlotCaches>,
    handlers: Arc<Handlers>,
    worker_receiver: Option<mpsc::Receiver<WorkerCommand>>,
}

impl<NC> FarmerCacheWorker<NC>
where
    NC: NodeClient,
{
    /// Run the cache worker with provided piece getter.
    ///
    /// NOTE: Piece getter must not depend on farmer cache in order to avoid reference cycles!
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

        if let Some(WorkerCommand::ReplaceBackingCaches { new_piece_caches }) =
            worker_receiver.recv().await
        {
            self.initialize(&piece_getter, &mut worker_state, new_piece_caches)
                .await;
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
            WorkerCommand::ReplaceBackingCaches { new_piece_caches } => {
                self.initialize(piece_getter, worker_state, new_piece_caches)
                    .await;
            }
            // TODO: Consider implementing optional re-sync of the piece instead of just forgetting
            WorkerCommand::ForgetKey { key } => {
                let mut caches = self.piece_caches.write().await;

                for (cache_index, cache) in caches.iter_mut().enumerate() {
                    let Some(offset) = cache.stored_pieces.remove(&key) else {
                        // Not this disk farm
                        continue;
                    };

                    // Making offset as unoccupied and remove corresponding key from heap
                    cache.free_offsets.push_front(offset);
                    match cache.backend.read_piece_index(offset).await {
                        Ok(Some(piece_index)) => {
                            worker_state.heap.remove(KeyWrapper(piece_index));
                        }
                        Ok(None) => {
                            warn!(
                                %cache_index,
                                %offset,
                                "Piece index out of range, this is likely an implementation bug, \
                                not freeing heap element"
                            );
                        }
                        Err(error) => {
                            error!(
                                %error,
                                %cache_index,
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
        new_piece_caches: Vec<Arc<dyn PieceCache>>,
    ) where
        PG: PieceGetter,
    {
        info!("Initializing piece cache");
        // Pull old cache state since it will be replaced with a new one and reuse its allocations
        let cache_state = mem::take(&mut *self.piece_caches.write().await);
        let mut stored_pieces = Vec::with_capacity(new_piece_caches.len());
        let mut free_offsets = Vec::with_capacity(new_piece_caches.len());
        for mut state in cache_state {
            state.stored_pieces.clear();
            stored_pieces.push(state.stored_pieces);
            state.free_offsets.clear();
            free_offsets.push(state.free_offsets);
        }
        stored_pieces.resize(new_piece_caches.len(), HashMap::default());
        free_offsets.resize(new_piece_caches.len(), VecDeque::default());

        debug!("Collecting pieces that were in the cache before");

        // Build cache state of all backends
        let maybe_caches_futures = stored_pieces
            .into_iter()
            .zip(free_offsets)
            .zip(new_piece_caches)
            .enumerate()
            .map(
                |(index, ((mut stored_pieces, mut free_offsets), new_cache))| {
                    run_future_in_dedicated_thread(
                        move || async move {
                            // Hack with first collecting into `Option` with `Option::take()` call
                            // later is to satisfy compiler that gets confused about ownership
                            // otherwise
                            let mut maybe_contents = match new_cache.contents().await {
                                Ok(contents) => Some(contents),
                                Err(error) => {
                                    warn!(%index, %error, "Failed to get cache contents");

                                    None
                                }
                            };
                            let Some(mut contents) = maybe_contents.take() else {
                                drop(maybe_contents);

                                return PieceCacheState {
                                    stored_pieces,
                                    free_offsets,
                                    backend: new_cache,
                                };
                            };

                            stored_pieces.reserve(new_cache.max_num_elements() as usize);

                            while let Some(maybe_element_details) = contents.next().await {
                                let (offset, maybe_piece_index) = match maybe_element_details {
                                    Ok(element_details) => element_details,
                                    Err(error) => {
                                        warn!(
                                            %index,
                                            %error,
                                            "Failed to get cache contents element details"
                                        );
                                        break;
                                    }
                                };
                                match maybe_piece_index {
                                    Some(piece_index) => {
                                        stored_pieces.insert(
                                            RecordKey::from(piece_index.to_multihash()),
                                            offset,
                                        );
                                    }
                                    None => {
                                        free_offsets.push_back(offset);
                                    }
                                }

                                // Allow for task to be aborted
                                yield_now().await;
                            }

                            drop(maybe_contents);
                            drop(contents);

                            PieceCacheState {
                                stored_pieces,
                                free_offsets,
                                backend: new_cache,
                            }
                        },
                        format!("piece-cache.{index}"),
                    )
                },
            )
            .collect::<Result<Vec<_>, _>>();

        let caches_futures = match maybe_caches_futures {
            Ok(caches_futures) => caches_futures,
            Err(error) => {
                error!(
                    %error,
                    "Failed to spawn piece cache reading thread"
                );

                return;
            }
        };

        let mut caches = Vec::with_capacity(caches_futures.len());
        let mut caches_futures = caches_futures.into_iter().collect::<FuturesOrdered<_>>();

        while let Some(maybe_cache) = caches_futures.next().await {
            match maybe_cache {
                Ok(cache) => {
                    caches.push(cache);
                }
                Err(_cancelled) => {
                    error!("Piece cache reading thread panicked");

                    return;
                }
            };
        }

        info!("Synchronizing piece cache");

        let last_segment_index = loop {
            match self.node_client.farmer_app_info().await {
                Ok(farmer_app_info) => {
                    let last_segment_index =
                        farmer_app_info.protocol_info.history_size.segment_index();
                    // Wait for node to be either fully synced or to be aware of non-zero segment
                    // index, which would indicate it has started DSN sync and knows about
                    // up-to-date archived history.
                    //
                    // While this doesn't account for situations where node was offline for a long
                    // time and is aware of old segment headers, this is good enough for piece cache
                    // sync to proceed and should result in better user experience on average.
                    if !farmer_app_info.syncing || last_segment_index > SegmentIndex::ZERO {
                        break last_segment_index;
                    }
                }
                Err(error) => {
                    error!(
                        %error,
                        "Failed to get farmer app info from node, keeping old cache state without \
                        updates"
                    );

                    // Not the latest, but at least something
                    *self.piece_caches.write().await = caches;
                    return;
                }
            }

            tokio::time::sleep(INITIAL_SYNC_FARM_INFO_CHECK_INTERVAL).await;
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
                    state.free_offsets.push_front(offset);
                });
        });

        // Store whatever correct pieces are immediately available after restart
        self.piece_caches.write().await.clone_from(&caches);

        debug!(
            count = %piece_indices_to_store.len(),
            "Identified piece indices that should be cached",
        );

        let mut piece_indices_to_store = piece_indices_to_store.into_values().collect::<Vec<_>>();
        // Sort pieces such that they are in ascending order and have higher chance of download
        // overlapping with other processes like node's sync from DSN
        piece_indices_to_store.par_sort_unstable();
        let mut piece_indices_to_store = piece_indices_to_store.into_iter();

        let download_piece = |piece_index| async move {
            trace!(%piece_index, "Downloading piece");

            let result = piece_getter.get_piece(piece_index).await;

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

            let Some((piece_index, piece)) = &maybe_piece else {
                continue;
            };

            // Find plot in which there is a place for new piece to be stored
            let mut sorted_caches = caches.iter_mut().enumerate().collect::<Vec<_>>();
            // Sort piece caches by number of stored pieces to fill those that are less
            // populated first
            sorted_caches.sort_by_key(|(_, cache)| cache.stored_pieces.len());
            if !stream::iter(sorted_caches)
                .any(|(cache_index, cache)| async move {
                    let Some(offset) = cache.free_offsets.pop_front() else {
                        return false;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, *piece_index, piece).await
                    {
                        error!(
                            %error,
                            %cache_index,
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
                .await
            {
                error!(
                    %piece_index,
                    "Failed to store piece in cache, there was no space"
                );
            }

            downloaded_pieces_count += 1;
            // Do not print anything or send progress notification after last piece until piece
            // cache is written fully below
            if downloaded_pieces_count != pieces_to_download_total {
                let progress =
                    downloaded_pieces_count as f32 / pieces_to_download_total as f32 * 100.0;
                if downloaded_pieces_count % INTERMEDIATE_CACHE_UPDATE_INTERVAL == 0 {
                    self.piece_caches.write().await.clone_from(&caches);

                    info!("Piece cache sync {progress:.2}% complete");
                }

                self.handlers.progress.call_simple(&progress);
            }
        }

        *self.piece_caches.write().await = caches;
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
            // will be included, but there is a good chance they will be, and we want to acknowledge
            // new segment header as soon as possible
            let pieces_to_maybe_include = segment_index
                .segment_piece_indexes()
                .into_iter()
                .map(|piece_index| {
                    let worker_state = &*worker_state;

                    async move {
                        let should_store_in_piece_cache = worker_state
                            .heap
                            .should_include_key(KeyWrapper(piece_index));
                        let key = RecordKey::from(piece_index.to_multihash());
                        let should_store_in_plot_cache =
                            self.plot_caches.should_store(piece_index, &key).await;

                        if !(should_store_in_piece_cache || should_store_in_plot_cache) {
                            trace!(%piece_index, "Piece doesn't need to be cached #1");

                            return None;
                        }

                        let maybe_piece = match self.node_client.piece(piece_index).await {
                            Ok(maybe_piece) => maybe_piece,
                            Err(error) => {
                                error!(
                                    %error,
                                    %segment_index,
                                    %piece_index,
                                    "Failed to retrieve piece from node right after archiving, \
                                    this should never happen and is an implementation bug"
                                );

                                return None;
                            }
                        };

                        let Some(piece) = maybe_piece else {
                            error!(
                                %segment_index,
                                %piece_index,
                                "Failed to retrieve piece from node right after archiving, this \
                                should never happen and is an implementation bug"
                            );

                            return None;
                        };

                        Some((piece_index, piece))
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_piece| async move { maybe_piece })
                .collect::<Vec<_>>()
                .await;

            debug!(%segment_index, "Downloaded potentially useful pieces");

            self.acknowledge_archived_segment_processing(segment_index)
                .await;

            // TODO: Would be nice to have concurrency here, but heap is causing a bit of
            //  difficulties unfortunately
            // Go through potentially matching pieces again now that segment was acknowledged and
            // try to persist them if necessary
            for (piece_index, piece) in pieces_to_maybe_include {
                if !self
                    .plot_caches
                    .store_additional_piece(piece_index, &piece)
                    .await
                {
                    trace!(%piece_index, "Piece doesn't need to be cached in plot cache");
                }

                if !worker_state
                    .heap
                    .should_include_key(KeyWrapper(piece_index))
                {
                    trace!(%piece_index, "Piece doesn't need to be cached #2");

                    continue;
                }

                trace!(%piece_index, "Piece needs to be cached #1");

                self.persist_piece_in_cache(piece_index, piece, worker_state)
                    .await;
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

            let result = piece_getter.get_piece(piece_index).await;

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

            self.persist_piece_in_cache(piece_index, piece, worker_state)
                .await;
        }

        info!("Finished syncing piece cache to the latest history size");

        worker_state.last_segment_index = last_segment_index;
    }

    /// This assumes it was already checked that piece needs to be stored, no verification for this
    /// is done internally and invariants will break if this assumption doesn't hold true
    async fn persist_piece_in_cache(
        &self,
        piece_index: PieceIndex,
        piece: Piece,
        worker_state: &mut CacheWorkerState,
    ) {
        let record_key = RecordKey::from(piece_index.to_multihash());
        let heap_key = KeyWrapper(piece_index);

        let mut caches = self.piece_caches.write().await;
        match worker_state.heap.insert(heap_key) {
            // Entry is already occupied, we need to find and replace old piece with new one
            Some(KeyWrapper(old_piece_index)) => {
                for (cache_index, cache) in caches.iter_mut().enumerate() {
                    let old_record_key = RecordKey::from(old_piece_index.to_multihash());
                    let Some(offset) = cache.stored_pieces.remove(&old_record_key) else {
                        // Not this disk farm
                        continue;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece).await
                    {
                        error!(
                            %error,
                            %cache_index,
                            %piece_index,
                            %offset,
                            "Failed to write piece into cache"
                        );
                    } else {
                        trace!(
                            %cache_index,
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
                let mut sorted_caches = caches.iter_mut().enumerate().collect::<Vec<_>>();
                // Sort piece caches by number of stored pieces to fill those that are less
                // populated first
                sorted_caches.sort_by_key(|(_, cache)| cache.stored_pieces.len());
                for (cache_index, cache) in sorted_caches {
                    let Some(offset) = cache.free_offsets.pop_front() else {
                        // Not this disk farm
                        continue;
                    };

                    if let Err(error) = cache.backend.write_piece(offset, piece_index, &piece).await
                    {
                        error!(
                            %error,
                            %cache_index,
                            %piece_index,
                            %offset,
                            "Failed to write piece into cache"
                        );
                    } else {
                        trace!(
                            %cache_index,
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

#[derive(Debug)]
struct PlotCaches {
    /// Additional piece caches
    caches: AsyncRwLock<Vec<Arc<dyn PlotCache>>>,
    /// Next plot cache to use for storing pieces
    next_plot_cache: AtomicUsize,
}

impl PlotCaches {
    async fn should_store(&self, piece_index: PieceIndex, key: &RecordKey) -> bool {
        for (cache_index, cache) in self.caches.read().await.iter().enumerate() {
            match cache.is_piece_maybe_stored(key).await {
                Ok(MaybePieceStoredResult::No) => {
                    // Try another one if there is any
                }
                Ok(MaybePieceStoredResult::Vacant) => {
                    return true;
                }
                Ok(MaybePieceStoredResult::Yes) => {
                    // Already stored, nothing else left to do
                    return false;
                }
                Err(error) => {
                    warn!(
                        %cache_index,
                        %piece_index,
                        %error,
                        "Failed to check piece stored in cache"
                    );
                }
            }
        }

        false
    }

    /// Store a piece in additional downloaded pieces, if there is space for them
    async fn store_additional_piece(&self, piece_index: PieceIndex, piece: &Piece) -> bool {
        let plot_caches = self.caches.read().await;
        let plot_caches_len = plot_caches.len();

        // Store pieces in plots using round-robin distribution
        for _ in 0..plot_caches_len {
            let plot_cache_index =
                self.next_plot_cache.fetch_add(1, Ordering::Relaxed) % plot_caches_len;

            match plot_caches[plot_cache_index]
                .try_store_piece(piece_index, piece)
                .await
            {
                Ok(true) => {
                    return false;
                }
                Ok(false) => {
                    continue;
                }
                Err(error) => {
                    error!(
                        %error,
                        %piece_index,
                        %plot_cache_index,
                        "Failed to store additional piece in cache"
                    );
                    continue;
                }
            }
        }

        false
    }
}

/// Farmer cache that aggregates different kinds of caches of multiple disks.
///
/// Pieces in [`PieceCache`] are stored based on capacity and proximity of piece index to farmer's
/// network identity. If capacity is not enough to store all pieces in cache then pieces that are
/// further from network identity will be evicted, this is helpful for quick retrieval of pieces
/// from DSN as well as plotting purposes.
///
/// [`PlotCache`] is used as a supplementary cache and is primarily helpful for smaller farmers
/// where piece cache is not enough to store all the pieces on the network, while there is a lot of
/// space in the plot that is not used by sectors yet and can be leverage as extra caching space.
#[derive(Debug, Clone)]
pub struct FarmerCache {
    peer_id: PeerId,
    /// Individual dedicated piece caches
    piece_caches: Arc<AsyncRwLock<Vec<PieceCacheState>>>,
    /// Additional piece caches
    plot_caches: Arc<PlotCaches>,
    handlers: Arc<Handlers>,
    // We do not want to increase capacity unnecessarily on clone
    worker_sender: Arc<mpsc::Sender<WorkerCommand>>,
}

impl FarmerCache {
    /// Create new piece cache instance and corresponding worker.
    ///
    /// NOTE: Returned future is async, but does blocking operations and should be running in
    /// dedicated thread.
    pub fn new<NC>(node_client: NC, peer_id: PeerId) -> (Self, FarmerCacheWorker<NC>)
    where
        NC: NodeClient,
    {
        let caches = Arc::default();
        let (worker_sender, worker_receiver) = mpsc::channel(WORKER_CHANNEL_CAPACITY);
        let handlers = Arc::new(Handlers::default());

        let plot_caches = Arc::new(PlotCaches {
            caches: AsyncRwLock::default(),
            next_plot_cache: AtomicUsize::new(0),
        });

        let instance = Self {
            peer_id,
            piece_caches: Arc::clone(&caches),
            plot_caches: Arc::clone(&plot_caches),
            handlers: Arc::clone(&handlers),
            worker_sender: Arc::new(worker_sender),
        };
        let worker = FarmerCacheWorker {
            peer_id,
            node_client,
            piece_caches: caches,
            plot_caches,
            handlers,
            worker_receiver: Some(worker_receiver),
        };

        (instance, worker)
    }

    /// Get piece from cache
    pub async fn get_piece(&self, key: RecordKey) -> Option<Piece> {
        for (cache_index, cache) in self.piece_caches.read().await.iter().enumerate() {
            let Some(&offset) = cache.stored_pieces.get(&key) else {
                continue;
            };
            match cache.backend.read_piece(offset).await {
                Ok(maybe_piece) => {
                    return maybe_piece.map(|(_piece_index, piece)| piece);
                }
                Err(error) => {
                    error!(
                        %error,
                        %cache_index,
                        ?key,
                        %offset,
                        "Error while reading piece from cache, might be a disk corruption"
                    );

                    if let Err(error) = self
                        .worker_sender
                        .send(WorkerCommand::ForgetKey { key })
                        .await
                    {
                        trace!(%error, "Failed to send ForgetKey command to worker");
                    }

                    return None;
                }
            }
        }

        for cache in self.plot_caches.caches.read().await.iter() {
            if let Ok(Some(piece)) = cache.read_piece(&key).await {
                return Some(piece);
            }
        }

        None
    }

    /// Find piece in cache and return its retrieval details
    pub(crate) async fn find_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Option<(PieceCacheId, PieceCacheOffset)> {
        let key = RecordKey::from(piece_index.to_multihash());

        for cache in self.piece_caches.read().await.iter() {
            let Some(&offset) = cache.stored_pieces.get(&key) else {
                continue;
            };
            return Some((*cache.backend.id(), offset));
        }

        None
    }

    /// Try to store a piece in additional downloaded pieces, if there is space for them
    pub async fn maybe_store_additional_piece(&self, piece_index: PieceIndex, piece: &Piece) {
        let key = RecordKey::from(piece_index.to_multihash());

        let should_store = self.plot_caches.should_store(piece_index, &key).await;

        if !should_store {
            return;
        }

        self.plot_caches
            .store_additional_piece(piece_index, piece)
            .await;
    }

    /// Initialize replacement of backing caches
    pub async fn replace_backing_caches(
        &self,
        new_piece_caches: Vec<Arc<dyn PieceCache>>,
        new_plot_caches: Vec<Arc<dyn PlotCache>>,
    ) {
        if let Err(error) = self
            .worker_sender
            .send(WorkerCommand::ReplaceBackingCaches { new_piece_caches })
            .await
        {
            warn!(%error, "Failed to replace backing caches, worker exited");
        }

        *self.plot_caches.caches.write().await = new_plot_caches;
    }

    /// Subscribe to cache sync notifications
    pub fn on_sync_progress(&self, callback: HandlerFn<f32>) -> HandlerId {
        self.handlers.progress.add(callback)
    }
}

impl LocalRecordProvider for FarmerCache {
    fn record(&self, key: &RecordKey) -> Option<ProviderRecord> {
        for piece_cache in self.piece_caches.try_read()?.iter() {
            if piece_cache.stored_pieces.contains_key(key) {
                // Note: We store our own provider records locally without local addresses
                // to avoid redundant storage and outdated addresses. Instead, these are
                // acquired on demand when returning a `ProviderRecord` for the local node.
                return Some(ProviderRecord {
                    key: key.clone(),
                    provider: self.peer_id,
                    expires: None,
                    addresses: Vec::new(),
                });
            };
        }

        let found_fut = self
            .plot_caches
            .caches
            .try_read()?
            .iter()
            .map(|plot_cache| {
                let plot_cache = Arc::clone(plot_cache);

                async move {
                    matches!(
                        plot_cache.is_piece_maybe_stored(key).await,
                        Ok(MaybePieceStoredResult::Yes)
                    )
                }
            })
            .collect::<FuturesOrdered<_>>()
            .any(|found| async move { found });

        // TODO: Ideally libp2p would have an async API record store API,
        let found = block_in_place(|| {
            Handle::current()
                .block_on(tokio::time::timeout(
                    IS_PIECE_MAYBE_STORED_TIMEOUT,
                    found_fut,
                ))
                .unwrap_or_default()
        });

        // Note: We store our own provider records locally without local addresses
        // to avoid redundant storage and outdated addresses. Instead, these are
        // acquired on demand when returning a `ProviderRecord` for the local node.
        found.then_some(ProviderRecord {
            key: key.clone(),
            provider: self.peer_id,
            expires: None,
            addresses: Vec::new(),
        })
    }
}
