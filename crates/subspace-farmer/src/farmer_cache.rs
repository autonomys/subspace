//! A container that caches pieces
//!
//! Farmer cache is a container that orchestrates a bunch of piece and plot caches that together
//! persist pieces in a way that is easy to retrieve comparing to decoding pieces from plots.

mod metrics;
mod piece_cache_state;
#[cfg(test)]
mod tests;

use crate::farm::{MaybePieceStoredResult, PieceCache, PieceCacheId, PieceCacheOffset, PlotCache};
use crate::farmer_cache::metrics::FarmerCacheMetrics;
use crate::farmer_cache::piece_cache_state::PieceCachesState;
use crate::node_client::NodeClient;
use crate::utils::run_future_in_dedicated_thread;
use async_lock::RwLock as AsyncRwLock;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::mpsc;
use futures::future::FusedFuture;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{select, stream, FutureExt, SinkExt, Stream, StreamExt};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use rayon::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::future::join;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::{fmt, mem};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_farmer_components::PieceGetter;
use subspace_networking::libp2p::kad::{ProviderRecord, RecordKey};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{KeyWithDistance, LocalRecordProvider};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::{block_in_place, yield_now};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

const WORKER_CHANNEL_CAPACITY: usize = 100;
const SYNC_BATCH_SIZE: usize = 256;
const SYNC_CONCURRENT_BATCHES: usize = 4;
/// Make caches available as they are building without waiting for the initialization to finish,
/// this number defines an interval in pieces after which cache is updated
const INTERMEDIATE_CACHE_UPDATE_INTERVAL: usize = 100;
const INITIAL_SYNC_FARM_INFO_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// How long to wait for `is_piece_maybe_stored` response from plot cache before timing out in order
/// to prevent blocking of executor for too long
const IS_PIECE_MAYBE_STORED_TIMEOUT: Duration = Duration::from_millis(100);

type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;
type CacheIndex = u8;

#[derive(Default, Debug)]
struct Handlers {
    progress: Handler<f32>,
}

#[derive(Debug, Clone, Copy)]
struct FarmerCacheOffset {
    cache_index: CacheIndex,
    piece_offset: PieceCacheOffset,
}

impl FarmerCacheOffset {
    fn new(cache_index: CacheIndex, piece_offset: PieceCacheOffset) -> Self {
        Self {
            cache_index,
            piece_offset,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheBackend {
    backend: Arc<dyn PieceCache>,
    used_capacity: u32,
    total_capacity: u32,
}

impl std::ops::Deref for CacheBackend {
    type Target = Arc<dyn PieceCache>;

    fn deref(&self) -> &Self::Target {
        &self.backend
    }
}

impl CacheBackend {
    fn new(backend: Arc<dyn PieceCache>, total_capacity: u32) -> Self {
        Self {
            backend,
            used_capacity: 0,
            total_capacity,
        }
    }

    fn next_free(&mut self) -> Option<PieceCacheOffset> {
        let offset = self.used_capacity;
        if offset < self.total_capacity {
            self.used_capacity += 1;
            Some(PieceCacheOffset(offset))
        } else {
            debug!(?offset, total_capacity = ?self.total_capacity, "No free space in cache backend");
            None
        }
    }

    fn free_size(&self) -> u32 {
        self.total_capacity - self.used_capacity
    }
}

#[derive(Debug)]
struct CacheState {
    cache_stored_pieces: HashMap<KeyWithDistance, FarmerCacheOffset>,
    cache_free_offsets: Vec<FarmerCacheOffset>,
    backend: CacheBackend,
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

/// Farmer cache worker used to drive the farmer cache backend
#[derive(Debug)]
#[must_use = "Farmer cache will not work unless its worker is running"]
pub struct FarmerCacheWorker<NC>
where
    NC: fmt::Debug,
{
    peer_id: PeerId,
    node_client: NC,
    piece_caches: Arc<AsyncRwLock<PieceCachesState>>,
    plot_caches: Arc<PlotCaches>,
    handlers: Arc<Handlers>,
    worker_receiver: Option<mpsc::Receiver<WorkerCommand>>,
    metrics: Option<Arc<FarmerCacheMetrics>>,
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
        let mut last_segment_index_internal = SegmentIndex::ZERO;

        let mut worker_receiver = self
            .worker_receiver
            .take()
            .expect("Always set during worker instantiation");

        if let Some(WorkerCommand::ReplaceBackingCaches { new_piece_caches }) =
            worker_receiver.next().await
        {
            self.initialize(
                &piece_getter,
                &mut last_segment_index_internal,
                new_piece_caches,
            )
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
        self.keep_up_after_initial_sync(&piece_getter, &mut last_segment_index_internal)
            .await;

        loop {
            select! {
                maybe_command = worker_receiver.next() => {
                    let Some(command) = maybe_command else {
                        // Nothing else left to do
                        return;
                    };

                    self.handle_command(command, &piece_getter, &mut last_segment_index_internal).await;
                }
                maybe_segment_header = segment_headers_notifications.next().fuse() => {
                    if let Some(segment_header) = maybe_segment_header {
                        self.process_segment_header(&piece_getter, segment_header, &mut last_segment_index_internal).await;
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
        last_segment_index_internal: &mut SegmentIndex,
    ) where
        PG: PieceGetter,
    {
        match command {
            WorkerCommand::ReplaceBackingCaches { new_piece_caches } => {
                self.initialize(piece_getter, last_segment_index_internal, new_piece_caches)
                    .await;
            }
            // TODO: Consider implementing optional re-sync of the piece instead of just forgetting
            WorkerCommand::ForgetKey { key } => {
                let mut caches = self.piece_caches.write().await;
                let key = KeyWithDistance::new_with_record_key(self.peer_id, key);
                let Some(offset) = caches.remove_stored_piece(&key) else {
                    // Key not exist
                    return;
                };

                let cache_index = offset.cache_index;
                let piece_offset = offset.piece_offset;
                let Some(backend) = caches.get_backend(cache_index).cloned() else {
                    // Cache backend not exist
                    return;
                };

                caches.push_dangling_free_offset(offset);
                match backend.read_piece_index(piece_offset).await {
                    Ok(Some(piece_index)) => {
                        trace!(%piece_index, %cache_index, %piece_offset, "Forget piece");
                    }
                    Ok(None) => {
                        warn!(
                            %cache_index,
                            %piece_offset,
                            "Piece index out of range, this is likely an implementation bug, \
                            not freeing heap element"
                        );
                    }
                    Err(error) => {
                        error!(
                            %error,
                            %cache_index,
                            ?key,
                            %piece_offset,
                            "Error while reading piece from cache"
                        );
                    }
                }
            }
        }
    }

    async fn initialize<PG>(
        &self,
        piece_getter: &PG,
        last_segment_index_internal: &mut SegmentIndex,
        new_piece_caches: Vec<Arc<dyn PieceCache>>,
    ) where
        PG: PieceGetter,
    {
        info!("Initializing piece cache");

        // Pull old cache state since it will be replaced with a new one and reuse its allocations
        let (mut stored_pieces, mut dangling_free_offsets) =
            mem::take(&mut *self.piece_caches.write().await).reuse();

        debug!("Collecting pieces that were in the cache before");

        if let Some(metrics) = &self.metrics {
            metrics.piece_cache_capacity_total.set(0);
            metrics.piece_cache_capacity_used.set(0);
        }

        let peer_id = self.peer_id;

        // Build cache state of all backends
        let piece_caches_number = new_piece_caches.len();
        let maybe_caches_futures = new_piece_caches
            .into_iter()
            .enumerate()
            .filter_map(|(cache_index, new_cache)| {
                let total_capacity = new_cache.max_num_elements();
                let mut backend = CacheBackend::new(new_cache, total_capacity);
                let Ok(cache_index) = CacheIndex::try_from(cache_index) else {
                    warn!(
                        ?piece_caches_number,
                        "Too many piece caches provided, {cache_index} cache will be ignored",
                    );
                    return None;
                };

                if let Some(metrics) = &self.metrics {
                    metrics
                        .piece_cache_capacity_total
                        .inc_by(total_capacity as i64);
                }

                let init_fut = async move {
                    let used_capacity = &mut backend.used_capacity;

                    // Hack with first collecting into `Option` with `Option::take()` call
                    // later is to satisfy compiler that gets confused about ownership
                    // otherwise
                    let mut maybe_contents = match backend.backend.contents().await {
                        Ok(contents) => Some(contents),
                        Err(error) => {
                            warn!(%error, "Failed to get cache contents");

                            None
                        }
                    };

                    #[allow(clippy::mutable_key_type)]
                    let mut cache_stored_pieces = HashMap::new();
                    let mut cache_free_offsets = Vec::new();

                    let Some(mut contents) = maybe_contents.take() else {
                        drop(maybe_contents);

                        return CacheState {
                            cache_stored_pieces,
                            cache_free_offsets,
                            backend,
                        };
                    };

                    while let Some(maybe_element_details) = contents.next().await {
                        let (piece_offset, maybe_piece_index) = match maybe_element_details {
                            Ok(element_details) => element_details,
                            Err(error) => {
                                warn!(%error, "Failed to get cache contents element details");
                                break;
                            }
                        };
                        let offset = FarmerCacheOffset::new(cache_index, piece_offset);
                        match maybe_piece_index {
                            Some(piece_index) => {
                                *used_capacity = piece_offset.0 + 1;
                                let record_key = RecordKey::from(piece_index.to_multihash());
                                let key = KeyWithDistance::new_with_record_key(peer_id, record_key);
                                cache_stored_pieces.insert(key, offset);
                            }
                            None => {
                                // TODO: Optimize to not store all free offsets, only dangling
                                //  offsets are actually necessary
                                cache_free_offsets.push(offset);
                            }
                        }

                        // Allow for task to be aborted
                        yield_now().await;
                    }

                    drop(maybe_contents);
                    drop(contents);

                    CacheState {
                        cache_stored_pieces,
                        cache_free_offsets,
                        backend,
                    }
                };

                Some(run_future_in_dedicated_thread(
                    move || init_fut.instrument(info_span!("", %cache_index)),
                    format!("piece-cache.{cache_index}"),
                ))
            })
            .collect::<Result<Vec<_>, _>>();

        let caches_futures = match maybe_caches_futures {
            Ok(caches_futures) => caches_futures,
            Err(error) => {
                error!(%error, "Failed to spawn piece cache reading thread");

                return;
            }
        };

        let mut backends = Vec::with_capacity(caches_futures.len());
        let mut caches_futures = caches_futures.into_iter().collect::<FuturesOrdered<_>>();

        while let Some(maybe_cache) = caches_futures.next().await {
            match maybe_cache {
                Ok(cache) => {
                    let backend = cache.backend;
                    for (key, cache_offset) in cache.cache_stored_pieces {
                        if let Some(old_cache_offset) = stored_pieces.insert(key, cache_offset) {
                            dangling_free_offsets.push_front(old_cache_offset);
                        }
                    }
                    dangling_free_offsets.extend(
                        cache.cache_free_offsets.into_iter().filter(|free_offset| {
                            free_offset.piece_offset.0 < backend.used_capacity
                        }),
                    );
                    backends.push(backend);
                }
                Err(_cancelled) => {
                    error!("Piece cache reading thread panicked");

                    return;
                }
            };
        }

        let mut caches = PieceCachesState::new(stored_pieces, dangling_free_offsets, backends);

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

        // Collect all the piece indices that need to be stored, we will sort them later
        let segment_indices = Vec::from_iter(SegmentIndex::ZERO..=last_segment_index);
        // TODO: This may eventually be too much to store in memory, though right now it is a
        //  non-issue in practice
        let mut piece_indices_to_store = segment_indices
            .into_par_iter()
            .flat_map(|segment_index| {
                segment_index
                    .segment_piece_indexes()
                    .into_par_iter()
                    .map(|piece_index| {
                        (
                            KeyWithDistance::new(self.peer_id, piece_index.to_multihash()),
                            piece_index,
                        )
                    })
            })
            .collect::<Vec<_>>();

        // Sort pieces by distance from peer to piece such that they are in ascending order
        // and have higher chance of download
        piece_indices_to_store.par_sort_unstable_by(|(a_key, _), (b_key, _)| a_key.cmp(b_key));

        // `HashMap` is faster than `BTreeMap`
        let mut piece_indices_to_store = piece_indices_to_store
            .into_iter()
            .take(caches.total_capacity())
            .collect::<HashMap<_, _>>();

        let mut piece_caches_capacity_used = vec![0u32; caches.backends().len()];
        // Filter-out piece indices that are stored, but should not be as well as clean
        // `inserted_piece_indices` from already stored piece indices, leaving just those that are
        // still missing in cache
        caches.free_unneeded_stored_pieces(&mut piece_indices_to_store);

        if let Some(metrics) = &self.metrics {
            for offset in caches.stored_pieces_offsets() {
                piece_caches_capacity_used[usize::from(offset.cache_index)] += 1;
            }

            for cache_used in piece_caches_capacity_used {
                metrics
                    .piece_cache_capacity_used
                    .inc_by(i64::from(cache_used));
            }
        }

        // Store whatever correct pieces are immediately available after restart
        self.piece_caches.write().await.clone_from(&caches);

        debug!(
            count = %piece_indices_to_store.len(),
            "Identified piece indices that should be cached",
        );

        let pieces_to_download_total = piece_indices_to_store.len();
        let piece_indices_to_store = piece_indices_to_store
            .into_values()
            .collect::<Vec<_>>()
            // TODO: Allocating chunks here shouldn't be necessary, but otherwise it fails with
            //  confusing error described in https://github.com/rust-lang/rust/issues/64552 and
            //  similar upstream issues
            .chunks(SYNC_BATCH_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();

        let downloaded_pieces_count = AtomicUsize::new(0);
        let caches = Mutex::new(caches);
        self.handlers.progress.call_simple(&0.0);
        let piece_indices_to_store = piece_indices_to_store.into_iter().enumerate();

        let downloading_semaphore = &Semaphore::new(SYNC_BATCH_SIZE * SYNC_CONCURRENT_BATCHES);

        let downloading_pieces_stream =
            stream::iter(piece_indices_to_store.map(|(batch, piece_indices)| {
                let downloaded_pieces_count = &downloaded_pieces_count;
                let caches = &caches;

                async move {
                    let mut permit = downloading_semaphore
                        .acquire_many(SYNC_BATCH_SIZE as u32)
                        .await
                        .expect("Semaphore is never closed; qed");
                    debug!(%batch, num_pieces = %piece_indices.len(), "Downloading pieces");

                    let pieces_stream = match piece_getter.get_pieces(piece_indices).await {
                        Ok(pieces_stream) => pieces_stream,
                        Err(error) => {
                            error!(
                                %error,
                                "Failed to get pieces from piece getter"
                            );
                            return;
                        }
                    };
                    let mut pieces_stream = pieces_stream.enumerate();

                    while let Some((index, (piece_index, result))) = pieces_stream.next().await {
                        debug!(%batch, %index, %piece_index, "Downloaded piece");

                        let piece = match result {
                            Ok(Some(piece)) => {
                                trace!(%piece_index, "Downloaded piece successfully");
                                piece
                            }
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
                        // Release slot for future batches
                        permit.split(1);

                        let (offset, maybe_backend) = {
                            let mut caches = caches.lock();

                            // Find plot in which there is a place for new piece to be stored
                            let Some(offset) = caches.pop_free_offset() else {
                                error!(
                                    %piece_index,
                                    "Failed to store piece in cache, there was no space"
                                );
                                break;
                            };

                            (offset, caches.get_backend(offset.cache_index).cloned())
                        };

                        let cache_index = offset.cache_index;
                        let piece_offset = offset.piece_offset;

                        if let Some(backend) = maybe_backend
                            && let Err(error) =
                                backend.write_piece(piece_offset, piece_index, &piece).await
                        {
                            // TODO: Will likely need to cache problematic backend indices to avoid hitting it over and over again repeatedly
                            error!(
                                %error,
                                %cache_index,
                                %piece_index,
                                %piece_offset,
                                "Failed to write piece into cache"
                            );
                            continue;
                        }

                        let key = KeyWithDistance::new(self.peer_id, piece_index.to_multihash());
                        caches.lock().push_stored_piece(key, offset);

                        let prev_downloaded_pieces_count =
                            downloaded_pieces_count.fetch_add(1, Ordering::Relaxed);
                        // Do not print anything or send progress notification after last piece
                        // until piece cache is written fully below
                        if prev_downloaded_pieces_count != pieces_to_download_total {
                            let progress = prev_downloaded_pieces_count as f32
                                / pieces_to_download_total as f32
                                * 100.0;
                            if prev_downloaded_pieces_count % INTERMEDIATE_CACHE_UPDATE_INTERVAL
                                == 0
                            {
                                let mut piece_caches = self.piece_caches.write().await;
                                piece_caches.clone_from(&caches.lock());

                                info!("Piece cache sync {progress:.2}% complete");
                            }

                            self.handlers.progress.call_simple(&progress);
                        }
                    }
                }
            }));

        // Download several batches concurrently to make sure slow tail of one is compensated by
        // another
        downloading_pieces_stream
            // This allows to schedule new batch while previous batches partially completed, but
            // avoids excessive memory usage like when all futures are created upfront
            .buffer_unordered(SYNC_CONCURRENT_BATCHES * 2)
            // Simply drain everything
            .for_each(|()| async {})
            .await;

        *self.piece_caches.write().await = caches.into_inner();
        self.handlers.progress.call_simple(&100.0);
        *last_segment_index_internal = last_segment_index;

        info!("Finished piece cache synchronization");
    }

    async fn process_segment_header<PG>(
        &self,
        piece_getter: &PG,
        segment_header: SegmentHeader,
        last_segment_index_internal: &mut SegmentIndex,
    ) where
        PG: PieceGetter,
    {
        let segment_index = segment_header.segment_index();
        debug!(%segment_index, "Starting to process newly archived segment");

        if *last_segment_index_internal < segment_index {
            debug!(%segment_index, "Downloading potentially useful pieces");

            // We do not insert pieces into cache/heap yet, so we don't know if all of these pieces
            // will be included, but there is a good chance they will be, and we want to acknowledge
            // new segment header as soon as possible
            let pieces_to_maybe_include = segment_index
                .segment_piece_indexes()
                .into_iter()
                .map(|piece_index| async move {
                    let should_store_in_piece_cache = self
                        .piece_caches
                        .read()
                        .await
                        .should_include_key(self.peer_id, piece_index);

                    let key = RecordKey::from(piece_index.to_multihash());
                    let should_store_in_plot_cache =
                        self.plot_caches.should_store(piece_index, &key).await;

                    if !(should_store_in_piece_cache || should_store_in_plot_cache) {
                        trace!(%piece_index, "Piece doesn't need to be cached #1");

                        return None;
                    }

                    let maybe_piece_result =
                        self.node_client
                            .piece(piece_index)
                            .await
                            .inspect_err(|error| {
                                debug!(
                                    %error,
                                    %segment_index,
                                    %piece_index,
                                    "Failed to retrieve piece from node right after archiving"
                                );
                            });

                    if let Ok(Some(piece)) = maybe_piece_result {
                        return Some((piece_index, piece));
                    }

                    match piece_getter.get_piece(piece_index).await {
                        Ok(Some(piece)) => Some((piece_index, piece)),
                        Ok(None) => {
                            warn!(
                                %segment_index,
                                %piece_index,
                                "Failed to retrieve piece right after archiving"
                            );

                            None
                        }
                        Err(error) => {
                            warn!(
                                %error,
                                %segment_index,
                                %piece_index,
                                "Failed to retrieve piece right after archiving"
                            );

                            None
                        }
                    }
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
                if !self
                    .plot_caches
                    .store_additional_piece(piece_index, &piece)
                    .await
                {
                    trace!(%piece_index, "Piece doesn't need to be cached in plot cache");
                }

                if !self
                    .piece_caches
                    .read()
                    .await
                    .should_include_key(self.peer_id, piece_index)
                {
                    trace!(%piece_index, "Piece doesn't need to be cached #2");

                    continue;
                }

                trace!(%piece_index, "Piece needs to be cached #1");

                self.persist_piece_in_cache(piece_index, piece).await;
            }

            *last_segment_index_internal = segment_index;
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
        last_segment_index_internal: &mut SegmentIndex,
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

        if last_segment_index <= *last_segment_index_internal {
            return;
        }

        info!(
            "Syncing piece cache to the latest history size, this may pause block production if \
            takes too long"
        );

        // Keep up with segment indices that were potentially created since reinitialization
        let piece_indices = (*last_segment_index_internal..=last_segment_index)
            .flat_map(|segment_index| segment_index.segment_piece_indexes());

        // TODO: Download pieces concurrently
        for piece_index in piece_indices {
            if !self
                .piece_caches
                .read()
                .await
                .should_include_key(self.peer_id, piece_index)
            {
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

            self.persist_piece_in_cache(piece_index, piece).await;
        }

        info!("Finished syncing piece cache to the latest history size");

        *last_segment_index_internal = last_segment_index;
    }

    /// This assumes it was already checked that piece needs to be stored, no verification for this
    /// is done internally and invariants will break if this assumption doesn't hold true
    async fn persist_piece_in_cache(&self, piece_index: PieceIndex, piece: Piece) {
        let key = KeyWithDistance::new(self.peer_id, piece_index.to_multihash());
        let mut caches = self.piece_caches.write().await;
        match caches.should_replace(&key) {
            // Entry is already occupied, we need to find and replace old piece with new one
            Some((old_key, offset)) => {
                let cache_index = offset.cache_index;
                let piece_offset = offset.piece_offset;
                let Some(backend) = caches.get_backend(cache_index) else {
                    // Cache backend not exist
                    warn!(
                        %cache_index,
                        %piece_index,
                        "Should have a cached backend, but it didn't exist, this is an \
                        implementation bug"
                    );
                    return;
                };
                if let Err(error) = backend.write_piece(piece_offset, piece_index, &piece).await {
                    error!(
                        %error,
                        %cache_index,
                        %piece_index,
                        %piece_offset,
                        "Failed to write piece into cache"
                    );
                } else {
                    let old_piece_index = decode_piece_index_from_record_key(old_key.record_key());
                    trace!(
                        %cache_index,
                        %old_piece_index,
                        %piece_index,
                        %piece_offset,
                        "Successfully replaced old cached piece"
                    );
                    caches.push_stored_piece(key, offset);
                }
            }
            // There is free space in cache, need to find a free spot and place piece there
            None => {
                let Some(offset) = caches.pop_free_offset() else {
                    warn!(
                        %piece_index,
                        "Should have inserted piece into cache, but it didn't happen, this is an \
                        implementation bug"
                    );
                    return;
                };
                let cache_index = offset.cache_index;
                let piece_offset = offset.piece_offset;
                let Some(backend) = caches.get_backend(cache_index) else {
                    // Cache backend not exist
                    warn!(
                        %cache_index,
                        %piece_index,
                        "Should have a cached backend, but it didn't exist, this is an \
                        implementation bug"
                    );
                    return;
                };

                if let Err(error) = backend.write_piece(piece_offset, piece_index, &piece).await {
                    error!(
                        %error,
                        %cache_index,
                        %piece_index,
                        %piece_offset,
                        "Failed to write piece into cache"
                    );
                } else {
                    trace!(
                        %cache_index,
                        %piece_index,
                        %piece_offset,
                        "Successfully stored piece in cache"
                    );
                    if let Some(metrics) = &self.metrics {
                        metrics.piece_cache_capacity_used.inc();
                    }
                    caches.push_stored_piece(key, offset);
                }
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
    piece_caches: Arc<AsyncRwLock<PieceCachesState>>,
    /// Additional piece caches
    plot_caches: Arc<PlotCaches>,
    handlers: Arc<Handlers>,
    // We do not want to increase capacity unnecessarily on clone
    worker_sender: mpsc::Sender<WorkerCommand>,
    metrics: Option<Arc<FarmerCacheMetrics>>,
}

impl FarmerCache {
    /// Create new piece cache instance and corresponding worker.
    ///
    /// NOTE: Returned future is async, but does blocking operations and should be running in
    /// dedicated thread.
    pub fn new<NC>(
        node_client: NC,
        peer_id: PeerId,
        registry: Option<&mut Registry>,
    ) -> (Self, FarmerCacheWorker<NC>)
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
        let metrics = registry.map(|registry| Arc::new(FarmerCacheMetrics::new(registry)));

        let instance = Self {
            peer_id,
            piece_caches: Arc::clone(&caches),
            plot_caches: Arc::clone(&plot_caches),
            handlers: Arc::clone(&handlers),
            worker_sender,
            metrics: metrics.clone(),
        };
        let worker = FarmerCacheWorker {
            peer_id,
            node_client,
            piece_caches: caches,
            plot_caches,
            handlers,
            worker_receiver: Some(worker_receiver),
            metrics,
        };

        (instance, worker)
    }

    /// Get piece from cache
    pub async fn get_piece<Key>(&self, key: Key) -> Option<Piece>
    where
        RecordKey: From<Key>,
    {
        let key = RecordKey::from(key);
        let maybe_piece_found = {
            let key = KeyWithDistance::new_with_record_key(self.peer_id, key.clone());
            let caches = self.piece_caches.read().await;

            caches.get_stored_piece(&key).and_then(|offset| {
                let cache_index = offset.cache_index;
                let piece_offset = offset.piece_offset;
                Some((
                    piece_offset,
                    cache_index,
                    caches.get_backend(cache_index)?.clone(),
                ))
            })
        };

        if let Some((piece_offset, cache_index, backend)) = maybe_piece_found {
            match backend.read_piece(piece_offset).await {
                Ok(maybe_piece) => {
                    return match maybe_piece {
                        Some((_piece_index, piece)) => {
                            if let Some(metrics) = &self.metrics {
                                metrics.cache_get_hit.inc();
                            }
                            Some(piece)
                        }
                        None => {
                            error!(
                                %cache_index,
                                %piece_offset,
                                ?key,
                                "Piece was expected to be in cache, but wasn't found there"
                            );
                            if let Some(metrics) = &self.metrics {
                                metrics.cache_get_error.inc();
                            }
                            None
                        }
                    };
                }
                Err(error) => {
                    error!(
                        %error,
                        %cache_index,
                        ?key,
                        %piece_offset,
                        "Error while reading piece from cache"
                    );

                    if let Err(error) = self
                        .worker_sender
                        .clone()
                        .send(WorkerCommand::ForgetKey { key })
                        .await
                    {
                        trace!(%error, "Failed to send ForgetKey command to worker");
                    }

                    if let Some(metrics) = &self.metrics {
                        metrics.cache_get_error.inc();
                    }
                    return None;
                }
            }
        }

        for cache in self.plot_caches.caches.read().await.iter() {
            if let Ok(Some(piece)) = cache.read_piece(&key).await {
                if let Some(metrics) = &self.metrics {
                    metrics.cache_get_hit.inc();
                }
                return Some(piece);
            }
        }

        if let Some(metrics) = &self.metrics {
            metrics.cache_get_miss.inc();
        }
        None
    }

    /// Get pieces from cache.
    ///
    /// Number of elements in returned stream is the same as number of unique `piece_indices`.
    pub async fn get_pieces<'a, PieceIndices>(
        &'a self,
        piece_indices: PieceIndices,
    ) -> impl Stream<Item = (PieceIndex, Option<Piece>)> + Send + Unpin + 'a
    where
        PieceIndices: IntoIterator<Item = PieceIndex, IntoIter: Send + 'a> + Send + 'a,
    {
        let mut pieces_to_get_from_plot_cache = Vec::new();

        let pieces_to_read_from_piece_cache = {
            let caches = self.piece_caches.read().await;
            // Pieces to read from piece cache grouped by backend for efficiency reasons
            let mut pieces_to_read_from_piece_cache =
                HashMap::<CacheIndex, (CacheBackend, HashMap<_, _>)>::new();

            for piece_index in piece_indices {
                let key = RecordKey::from(piece_index.to_multihash());

                let offset = match caches.get_stored_piece(&KeyWithDistance::new_with_record_key(
                    self.peer_id,
                    key.clone(),
                )) {
                    Some(offset) => offset,
                    None => {
                        pieces_to_get_from_plot_cache.push((piece_index, key));
                        continue;
                    }
                };

                let cache_index = offset.cache_index;
                let piece_offset = offset.piece_offset;

                match pieces_to_read_from_piece_cache.entry(cache_index) {
                    Entry::Occupied(mut entry) => {
                        let (_backend, pieces) = entry.get_mut();
                        pieces.insert(piece_offset, (piece_index, key));
                    }
                    Entry::Vacant(entry) => {
                        let backend = match caches.get_backend(cache_index) {
                            Some(backend) => backend.clone(),
                            None => {
                                pieces_to_get_from_plot_cache.push((piece_index, key));
                                continue;
                            }
                        };
                        entry
                            .insert((backend, HashMap::from([(piece_offset, (piece_index, key))])));
                    }
                }
            }

            pieces_to_read_from_piece_cache
        };

        let (tx, mut rx) = mpsc::unbounded();

        let fut = async move {
            let tx = &tx;

            let mut reading_from_piece_cache = pieces_to_read_from_piece_cache
                .into_iter()
                .map(|(cache_index, (backend, mut pieces_to_get))| async move {
                    let mut pieces_stream = match backend
                        .read_pieces(Box::new(
                            pieces_to_get
                                .keys()
                                .copied()
                                .collect::<Vec<_>>()
                                .into_iter(),
                        ))
                        .await
                    {
                        Ok(pieces_stream) => pieces_stream,
                        Err(error) => {
                            error!(
                                %error,
                                %cache_index,
                                "Error while reading pieces from cache"
                            );

                            if let Some(metrics) = &self.metrics {
                                metrics.cache_get_error.inc_by(pieces_to_get.len() as u64);
                            }
                            for (piece_index, _key) in pieces_to_get.into_values() {
                                tx.unbounded_send((piece_index, None)).expect(
                                    "This future isn't polled after receiver is dropped; qed",
                                );
                            }
                            return;
                        }
                    };

                    while let Some(maybe_piece) = pieces_stream.next().await {
                        let result = match maybe_piece {
                            Ok((piece_offset, Some((piece_index, piece)))) => {
                                pieces_to_get.remove(&piece_offset);

                                if let Some(metrics) = &self.metrics {
                                    metrics.cache_get_hit.inc();
                                }
                                (piece_index, Some(piece))
                            }
                            Ok((piece_offset, None)) => {
                                let Some((piece_index, key)) = pieces_to_get.remove(&piece_offset)
                                else {
                                    debug!(
                                        %cache_index,
                                        %piece_offset,
                                        "Received piece offset that was not expected"
                                    );
                                    continue;
                                };

                                error!(
                                    %cache_index,
                                    %piece_index,
                                    %piece_offset,
                                    ?key,
                                    "Piece was expected to be in cache, but wasn't found there"
                                );
                                if let Some(metrics) = &self.metrics {
                                    metrics.cache_get_error.inc();
                                }
                                (piece_index, None)
                            }
                            Err(error) => {
                                error!(
                                    %error,
                                    %cache_index,
                                    "Error while reading piece from cache"
                                );

                                if let Some(metrics) = &self.metrics {
                                    metrics.cache_get_error.inc();
                                }
                                continue;
                            }
                        };

                        tx.unbounded_send(result)
                            .expect("This future isn't polled after receiver is dropped; qed");
                    }

                    if pieces_to_get.is_empty() {
                        return;
                    }

                    if let Some(metrics) = &self.metrics {
                        metrics.cache_get_error.inc_by(pieces_to_get.len() as u64);
                    }
                    for (piece_offset, (piece_index, key)) in pieces_to_get {
                        error!(
                            %cache_index,
                            %piece_index,
                            %piece_offset,
                            ?key,
                            "Piece cache didn't return an entry for offset"
                        );

                        // Uphold invariant of the method that some result should be returned
                        // for every unique piece index
                        tx.unbounded_send((piece_index, None))
                            .expect("This future isn't polled after receiver is dropped; qed");
                    }
                })
                .collect::<FuturesUnordered<_>>();
            // TODO: Can't use this due to https://github.com/rust-lang/rust/issues/64650
            // Simply drain everything
            // .for_each(|()| async {})

            // TODO: Remove once https://github.com/rust-lang/rust/issues/64650 is resolved
            let reading_from_piece_cache_fut = async move {
                while let Some(()) = reading_from_piece_cache.next().await {
                    // Simply drain everything
                }
            };

            let reading_from_plot_cache_fut = async {
                if pieces_to_get_from_plot_cache.is_empty() {
                    return;
                }

                for cache in self.plot_caches.caches.read().await.iter() {
                    // Iterating over offsets in reverse order to both traverse elements in async code
                    // and being able to efficiently remove entries without extra allocations
                    for offset in (0..pieces_to_get_from_plot_cache.len()).rev() {
                        let (piece_index, key) = &pieces_to_get_from_plot_cache[offset];

                        if let Ok(Some(piece)) = cache.read_piece(key).await {
                            if let Some(metrics) = &self.metrics {
                                metrics.cache_get_hit.inc();
                            }
                            tx.unbounded_send((*piece_index, Some(piece)))
                                .expect("This future isn't polled after receiver is dropped; qed");

                            // Due to iteration in reverse order and swapping using elements at the end,
                            // this doesn't affect processing of the elements
                            pieces_to_get_from_plot_cache.swap_remove(offset);
                        }
                    }

                    if pieces_to_get_from_plot_cache.is_empty() {
                        return;
                    }
                }

                if let Some(metrics) = &self.metrics {
                    metrics
                        .cache_get_miss
                        .inc_by(pieces_to_get_from_plot_cache.len() as u64);
                }

                for (piece_index, _key) in pieces_to_get_from_plot_cache {
                    tx.unbounded_send((piece_index, None))
                        .expect("This future isn't polled after receiver is dropped; qed");
                }
            };

            join!(reading_from_piece_cache_fut, reading_from_plot_cache_fut).await
        };
        let mut fut = Box::pin(fut.fuse());

        // Drive above future and stream back any pieces that were downloaded so far
        stream::poll_fn(move |cx| {
            if !fut.is_terminated() {
                // Result doesn't matter, we'll need to poll stream below anyway
                let _ = fut.poll_unpin(cx);
            }

            if let Poll::Ready(maybe_result) = rx.poll_next_unpin(cx) {
                return Poll::Ready(maybe_result);
            }

            // Exit will be done by the stream above
            Poll::Pending
        })
    }

    /// Returns a filtered list of pieces that were found in farmer cache, order is not guaranteed
    pub async fn has_pieces(&self, mut piece_indices: Vec<PieceIndex>) -> Vec<PieceIndex> {
        let mut pieces_to_find = HashMap::<PieceIndex, RecordKey>::from_iter(
            piece_indices
                .iter()
                .map(|piece_index| (*piece_index, RecordKey::from(piece_index.to_multihash()))),
        );

        // Quick check in piece caches
        {
            let piece_caches = self.piece_caches.read().await;
            pieces_to_find.retain(|_piece_index, key| {
                let distance_key = KeyWithDistance::new(self.peer_id, key.clone());
                !piece_caches.contains_stored_piece(&distance_key)
            });
        }

        // Early exit if everything is cached
        if pieces_to_find.is_empty() {
            return piece_indices;
        }

        // Check plot caches concurrently
        if let Some(plot_caches) = self.plot_caches.caches.try_read() {
            let plot_caches = &plot_caches;
            let not_found = pieces_to_find
                .into_iter()
                .map(|(piece_index, key)| async move {
                    let key = &key;

                    let found = plot_caches
                        .iter()
                        .map(|plot_cache| async {
                            matches!(
                                plot_cache.is_piece_maybe_stored(key).await,
                                Ok(MaybePieceStoredResult::Yes)
                            )
                        })
                        .collect::<FuturesUnordered<_>>()
                        .any(|found| async move { found })
                        .await;

                    if found {
                        None
                    } else {
                        Some(piece_index)
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_piece_index| async move { maybe_piece_index })
                .collect::<HashSet<_>>()
                .await;
            piece_indices.retain(|piece_index| !not_found.contains(piece_index));
        }
        piece_indices
    }

    /// Find piece in cache and return its retrieval details
    pub async fn find_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Option<(PieceCacheId, PieceCacheOffset)> {
        let caches = self.piece_caches.read().await;

        self.find_piece_internal(&caches, piece_index)
    }

    /// Find pieces in cache and return their retrieval details
    pub async fn find_pieces<PieceIndices>(
        &self,
        piece_indices: PieceIndices,
    ) -> Vec<(PieceIndex, PieceCacheId, PieceCacheOffset)>
    where
        PieceIndices: IntoIterator<Item = PieceIndex>,
    {
        let caches = self.piece_caches.read().await;

        piece_indices
            .into_iter()
            .filter_map(|piece_index| {
                self.find_piece_internal(&caches, piece_index)
                    .map(|(cache_id, piece_offset)| (piece_index, cache_id, piece_offset))
            })
            .collect()
    }

    fn find_piece_internal(
        &self,
        caches: &PieceCachesState,
        piece_index: PieceIndex,
    ) -> Option<(PieceCacheId, PieceCacheOffset)> {
        let key = KeyWithDistance::new(self.peer_id, piece_index.to_multihash());

        let Some(offset) = caches.get_stored_piece(&key) else {
            if let Some(metrics) = &self.metrics {
                metrics.cache_find_miss.inc();
            }

            return None;
        };
        let piece_offset = offset.piece_offset;

        if let Some(backend) = caches.get_backend(offset.cache_index) {
            if let Some(metrics) = &self.metrics {
                metrics.cache_find_hit.inc();
            }
            return Some((*backend.id(), piece_offset));
        }

        if let Some(metrics) = &self.metrics {
            metrics.cache_find_miss.inc();
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
            .clone()
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
        let distance_key = KeyWithDistance::new(self.peer_id, key.clone());
        if self
            .piece_caches
            .try_read()?
            .contains_stored_piece(&distance_key)
        {
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

/// Extracts the `PieceIndex` from a `RecordKey`.
fn decode_piece_index_from_record_key(key: &RecordKey) -> PieceIndex {
    let len = key.as_ref().len();
    let s = len - PieceIndex::SIZE;

    let mut piece_index_bytes = [0u8; PieceIndex::SIZE];
    piece_index_bytes.copy_from_slice(&key.as_ref()[s..]);

    PieceIndex::from_bytes(piece_index_bytes)
}
