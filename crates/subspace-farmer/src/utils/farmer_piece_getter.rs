use crate::farmer_cache::FarmerCache;
use crate::node_client::NodeClient;
use crate::utils::plotted_pieces::PlottedPieces;
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::PieceGetter;
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use tracing::{debug, error, trace};

const MAX_RANDOM_WALK_ROUNDS: usize = 15;

/// Retry policy for getting pieces from DSN cache
pub struct DsnCacheRetryPolicy {
    /// Max number of retries when trying to get piece from DSN cache
    pub max_retries: u16,
    /// Exponential backoff between retries
    pub backoff: ExponentialBackoff,
}

struct Inner<FarmIndex, PV, NC> {
    piece_provider: PieceProvider<PV>,
    farmer_cache: FarmerCache,
    node_client: NC,
    plotted_pieces: Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
    dsn_cache_retry_policy: DsnCacheRetryPolicy,
    in_progress_pieces: Mutex<HashMap<PieceIndex, Arc<AsyncMutex<Option<Piece>>>>>,
}

pub struct FarmerPieceGetter<FarmIndex, PV, NC> {
    inner: Arc<Inner<FarmIndex, PV, NC>>,
}

impl<FarmIndex, PV, NC> fmt::Debug for FarmerPieceGetter<FarmIndex, PV, NC> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FarmerPieceGetter").finish_non_exhaustive()
    }
}

impl<FarmIndex, PV, NC> Clone for FarmerPieceGetter<FarmIndex, PV, NC> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<FarmIndex, PV, NC> FarmerPieceGetter<FarmIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    pub fn new(
        piece_provider: PieceProvider<PV>,
        farmer_cache: FarmerCache,
        node_client: NC,
        plotted_pieces: Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
        dsn_cache_retry_policy: DsnCacheRetryPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                piece_provider,
                farmer_cache,
                node_client,
                plotted_pieces,
                dsn_cache_retry_policy,
                in_progress_pieces: Mutex::default(),
            }),
        }
    }

    /// Fast way to get piece using various caches
    pub async fn get_piece_fast(&self, piece_index: PieceIndex) -> Option<Piece> {
        let in_progress_piece_mutex = Arc::new(AsyncMutex::new(None));
        // Take lock before anything else, set to `None` when another piece getting is already in
        // progress
        let mut local_in_progress_piece_guard = Some(in_progress_piece_mutex.lock().await);
        let in_progress_piece_mutex = self
            .inner
            .in_progress_pieces
            .lock()
            .entry(piece_index)
            .and_modify(|_mutex| {
                local_in_progress_piece_guard.take();
            })
            .or_insert_with(|| Arc::clone(&in_progress_piece_mutex))
            .clone();

        // If piece is already in progress, just wait for it
        if local_in_progress_piece_guard.is_none() {
            trace!(%piece_index, "Piece is already in progress, waiting for result #1");
            // Doesn't matter if it was successful or not here
            return in_progress_piece_mutex.lock().await.clone();
        }

        // Otherwise try to get the piece without releasing lock to make sure successfully
        // downloaded piece gets stored
        let maybe_piece = self.get_piece_fast_internal(piece_index).await;
        // Store the result for others to observe
        if let Some(mut in_progress_piece) = local_in_progress_piece_guard {
            in_progress_piece.clone_from(&maybe_piece);
            self.inner.in_progress_pieces.lock().remove(&piece_index);
        }
        maybe_piece
    }

    async fn get_piece_fast_internal(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key = RecordKey::from(piece_index.to_multihash());

        let inner = &self.inner;

        trace!(%piece_index, "Getting piece from farmer cache");
        if let Some(piece) = inner.farmer_cache.get_piece(key).await {
            trace!(%piece_index, "Got piece from farmer cache successfully");
            return Some(piece);
        }

        // L2 piece acquisition
        trace!(%piece_index, "Getting piece from DSN L2 cache");
        if let Some(piece) = inner.piece_provider.get_piece_from_cache(piece_index).await {
            trace!(%piece_index, "Got piece from DSN L2 cache");
            inner
                .farmer_cache
                .maybe_store_additional_piece(piece_index, &piece)
                .await;
            return Some(piece);
        }

        // Try node's RPC before reaching to L1 (archival storage on DSN)
        trace!(%piece_index, "Getting piece from node");
        match inner.node_client.piece(piece_index).await {
            Ok(Some(piece)) => {
                trace!(%piece_index, "Got piece from node successfully");
                inner
                    .farmer_cache
                    .maybe_store_additional_piece(piece_index, &piece)
                    .await;
                return Some(piece);
            }
            Ok(None) => {
                // Nothing to do
            }
            Err(error) => {
                error!(
                    %error,
                    %piece_index,
                    "Failed to retrieve first segment piece from node"
                );
            }
        }

        None
    }

    /// Slow way to get piece using archival storage
    pub async fn get_piece_slow(&self, piece_index: PieceIndex) -> Option<Piece> {
        let in_progress_piece_mutex = Arc::new(AsyncMutex::new(None));
        // Take lock before anything else, set to `None` when another piece getting is already in
        // progress
        let mut local_in_progress_piece_guard = Some(in_progress_piece_mutex.lock().await);
        let in_progress_piece_mutex = self
            .inner
            .in_progress_pieces
            .lock()
            .entry(piece_index)
            .and_modify(|_mutex| {
                local_in_progress_piece_guard.take();
            })
            .or_insert_with(|| Arc::clone(&in_progress_piece_mutex))
            .clone();

        // If piece is already in progress, wait for it to see if it was successful
        if local_in_progress_piece_guard.is_none() {
            trace!(%piece_index, "Piece is already in progress, waiting for result #2");
            if let Some(piece) = in_progress_piece_mutex.lock().await.clone() {
                trace!(
                    %piece_index,
                    "Piece was already in progress and downloaded successfully #1"
                );
                return Some(piece);
            }
        }

        // Otherwise try to get the piece without releasing lock to make sure successfully
        // downloaded piece gets stored
        let maybe_piece = self.get_piece_slow_internal(piece_index).await;
        // Store the result for others to observe
        if let Some(mut in_progress_piece) = local_in_progress_piece_guard {
            in_progress_piece.clone_from(&maybe_piece);
            self.inner.in_progress_pieces.lock().remove(&piece_index);
        }
        maybe_piece
    }

    /// Slow way to get piece using archival storage
    async fn get_piece_slow_internal(&self, piece_index: PieceIndex) -> Option<Piece> {
        let inner = &self.inner;

        trace!(%piece_index, "Getting piece from local plot");
        let maybe_read_piece_fut = inner
            .plotted_pieces
            .try_read()
            .and_then(|plotted_pieces| plotted_pieces.read_piece(piece_index));

        if let Some(read_piece_fut) = maybe_read_piece_fut {
            if let Some(piece) = read_piece_fut.await {
                trace!(%piece_index, "Got piece from local plot successfully");
                inner
                    .farmer_cache
                    .maybe_store_additional_piece(piece_index, &piece)
                    .await;
                return Some(piece);
            }
        }

        // L1 piece acquisition
        trace!(%piece_index, "Getting piece from DSN L1.");

        let archival_storage_search_result = inner
            .piece_provider
            .get_piece_from_archival_storage(piece_index, MAX_RANDOM_WALK_ROUNDS)
            .await;

        if let Some(piece) = archival_storage_search_result {
            trace!(%piece_index, "DSN L1 lookup succeeded");
            inner
                .farmer_cache
                .maybe_store_additional_piece(piece_index, &piece)
                .await;
            return Some(piece);
        }

        None
    }

    /// Downgrade to [`WeakFarmerPieceGetter`] in order to break reference cycles with internally
    /// used [`Arc`]
    pub fn downgrade(&self) -> WeakFarmerPieceGetter<FarmIndex, PV, NC> {
        WeakFarmerPieceGetter {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

#[async_trait]
impl<FarmIndex, PV, NC> PieceGetter for FarmerPieceGetter<FarmIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let in_progress_piece_mutex = Arc::new(AsyncMutex::new(None));
        // Take lock before anything else, set to `None` when another piece getting is already in
        // progress
        let mut local_in_progress_piece_guard = Some(in_progress_piece_mutex.lock().await);
        let in_progress_piece_mutex = self
            .inner
            .in_progress_pieces
            .lock()
            .entry(piece_index)
            .and_modify(|_mutex| {
                local_in_progress_piece_guard.take();
            })
            .or_insert_with(|| Arc::clone(&in_progress_piece_mutex))
            .clone();

        // If piece is already in progress, wait for it to see if it was successful
        if local_in_progress_piece_guard.is_none() {
            trace!(%piece_index, "Piece is already in progress, waiting for result #3");
            if let Some(piece) = in_progress_piece_mutex.lock().await.clone() {
                trace!(
                    %piece_index,
                    "Piece was already in progress and downloaded successfully #2"
                );
                return Ok(Some(piece));
            }
        }

        {
            let retries = AtomicU32::new(0);
            let max_retries = u32::from(self.inner.dsn_cache_retry_policy.max_retries);
            let mut backoff = self.inner.dsn_cache_retry_policy.backoff.clone();
            backoff.reset();

            let maybe_piece_fut = retry(backoff, || async {
                let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

                if let Some(piece) = self.get_piece_fast_internal(piece_index).await {
                    trace!(%piece_index, current_attempt, "Got piece from DSN L2 cache");
                    return Ok(Some(piece));
                }
                if current_attempt >= max_retries {
                    if max_retries > 0 {
                        debug!(
                            %piece_index,
                            current_attempt,
                            max_retries,
                            "Couldn't get a piece from DSN L2. No retries left"
                        );
                    }
                    return Ok(None);
                }

                trace!(%piece_index, current_attempt, "Couldn't get a piece from DSN L2, retrying...");

                Err(backoff::Error::transient("Couldn't get piece from DSN"))
            });

            if let Ok(Some(piece)) = maybe_piece_fut.await {
                trace!(%piece_index, "Got piece from cache successfully");
                // Store successfully downloaded piece for others to observe
                if let Some(mut in_progress_piece) = local_in_progress_piece_guard {
                    in_progress_piece.replace(piece.clone());
                    self.inner.in_progress_pieces.lock().remove(&piece_index);
                }
                return Ok(Some(piece));
            }
        };

        if let Some(piece) = self.get_piece_slow_internal(piece_index).await {
            // Store successfully downloaded piece for others to observe
            if let Some(mut in_progress_piece) = local_in_progress_piece_guard {
                in_progress_piece.replace(piece.clone());
                self.inner.in_progress_pieces.lock().remove(&piece_index);
            }
            return Ok(Some(piece));
        }

        debug!(
            %piece_index,
            "Cannot acquire piece: all methods yielded empty result"
        );
        Ok(None)
    }
}

/// Weak farmer piece getter, can be upgraded to [`FarmerPieceGetter`]
pub struct WeakFarmerPieceGetter<FarmIndex, PV, NC> {
    inner: Weak<Inner<FarmIndex, PV, NC>>,
}

impl<FarmIndex, PV, NC> fmt::Debug for WeakFarmerPieceGetter<FarmIndex, PV, NC> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("WeakFarmerPieceGetter")
            .finish_non_exhaustive()
    }
}

impl<FarmIndex, PV, NC> Clone for WeakFarmerPieceGetter<FarmIndex, PV, NC> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl<FarmIndex, PV, NC> PieceGetter for WeakFarmerPieceGetter<FarmIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let Some(piece_getter) = self.upgrade() else {
            debug!("Farmer piece getter upgrade didn't succeed");
            return Ok(None);
        };

        piece_getter.get_piece(piece_index).await
    }
}

impl<FarmIndex, PV, NC> WeakFarmerPieceGetter<FarmIndex, PV, NC> {
    /// Try to upgrade to [`FarmerPieceGetter`] if there is at least one other instance of it alive
    pub fn upgrade(&self) -> Option<FarmerPieceGetter<FarmIndex, PV, NC>> {
        Some(FarmerPieceGetter {
            inner: self.inner.upgrade()?,
        })
    }
}
