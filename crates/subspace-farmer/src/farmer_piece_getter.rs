//! Farmer-specific piece getter

use crate::farm::plotted_pieces::PlottedPieces;
use crate::farmer_cache::FarmerCache;
use crate::node_client::NodeClient;
use async_lock::{
    Mutex as AsyncMutex, MutexGuardArc as AsyncMutexGuardArc, RwLock as AsyncRwLock, Semaphore,
};
use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_farmer_components::PieceGetter;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use tracing::{debug, error, trace};

pub mod piece_validator;

const MAX_RANDOM_WALK_ROUNDS: usize = 15;

struct InProgressPieceGetting<'a> {
    piece_index: PieceIndex,
    in_progress_piece: AsyncMutexGuardArc<Option<Piece>>,
    in_progress_pieces: &'a Mutex<HashMap<PieceIndex, Arc<AsyncMutex<Option<Piece>>>>>,
}

impl<'a> Drop for InProgressPieceGetting<'a> {
    fn drop(&mut self) {
        self.in_progress_pieces.lock().remove(&self.piece_index);
    }
}

impl<'a> InProgressPieceGetting<'a> {
    fn store_piece_getting_result(mut self, maybe_piece: &Option<Piece>) {
        self.in_progress_piece.clone_from(maybe_piece);
    }
}

enum InProgressPiece<'a> {
    Getting(InProgressPieceGetting<'a>),
    // If piece is already in progress, just wait for it
    Waiting {
        in_progress_piece_mutex: Arc<AsyncMutex<Option<Piece>>>,
    },
}

impl<'a> InProgressPiece<'a> {
    fn new(
        piece_index: PieceIndex,
        in_progress_pieces: &'a Mutex<HashMap<PieceIndex, Arc<AsyncMutex<Option<Piece>>>>>,
    ) -> Self {
        let in_progress_piece_mutex = Arc::new(AsyncMutex::new(None));
        // Take lock before anything else, set to `None` when another piece getting is already in
        // progress
        let mut local_in_progress_piece_guard = Some(
            in_progress_piece_mutex
                .try_lock_arc()
                .expect("Just created; qed"),
        );
        let in_progress_piece_mutex = in_progress_pieces
            .lock()
            .entry(piece_index)
            .and_modify(|_mutex| {
                local_in_progress_piece_guard.take();
            })
            .or_insert_with(|| Arc::clone(&in_progress_piece_mutex))
            .clone();

        if let Some(in_progress_piece) = local_in_progress_piece_guard {
            // Store guard and details necessary to remove entry from `in_progress_pieces` after
            // piece getting is complete (in `Drop` impl)
            Self::Getting(InProgressPieceGetting {
                piece_index,
                in_progress_piece,
                in_progress_pieces,
            })
        } else {
            // Piece getting is already in progress, only mutex is needed to wait for its result
            Self::Waiting {
                in_progress_piece_mutex,
            }
        }
    }
}

/// Retry policy for getting pieces from DSN cache
#[derive(Debug)]
pub struct DsnCacheRetryPolicy {
    /// Max number of retries when trying to get piece from DSN cache
    pub max_retries: u16,
    /// Exponential backoff between retries
    pub backoff: ExponentialBackoff,
}

struct Inner<FarmIndex, CacheIndex, PV, NC> {
    piece_provider: PieceProvider<PV>,
    farmer_cache: FarmerCache<CacheIndex>,
    node_client: NC,
    plotted_pieces: Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
    dsn_cache_retry_policy: DsnCacheRetryPolicy,
    in_progress_pieces: Mutex<HashMap<PieceIndex, Arc<AsyncMutex<Option<Piece>>>>>,
    request_semaphore: Arc<Semaphore>,
}

/// Farmer-specific piece getter.
///
/// Implements [`PieceGetter`] for plotting purposes, but useful outside of that as well.
pub struct FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
    inner: Arc<Inner<FarmIndex, CacheIndex, PV, NC>>,
}

impl<FarmIndex, CacheIndex, PV, NC> fmt::Debug
    for FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FarmerPieceGetter").finish_non_exhaustive()
    }
}

impl<FarmIndex, CacheIndex, PV, NC> Clone for FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<FarmIndex, CacheIndex, PV, NC> FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    CacheIndex: Hash + Eq + Copy + fmt::Debug + fmt::Display + Send + Sync + 'static,
    usize: From<CacheIndex>,
    CacheIndex: TryFrom<usize>,
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    /// Create new instance
    pub fn new(
        piece_provider: PieceProvider<PV>,
        farmer_cache: FarmerCache<CacheIndex>,
        node_client: NC,
        plotted_pieces: Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
        dsn_cache_retry_policy: DsnCacheRetryPolicy,
        request_concurrency: NonZeroUsize,
    ) -> Self {
        let request_semaphore = Arc::new(Semaphore::new(request_concurrency.get()));
        Self {
            inner: Arc::new(Inner {
                piece_provider,
                farmer_cache,
                node_client,
                plotted_pieces,
                dsn_cache_retry_policy,
                in_progress_pieces: Mutex::default(),
                request_semaphore,
            }),
        }
    }

    /// Fast way to get piece using various caches
    pub async fn get_piece_fast(&self, piece_index: PieceIndex) -> Option<Piece> {
        let _guard = self.inner.request_semaphore.acquire().await;

        match InProgressPiece::new(piece_index, &self.inner.in_progress_pieces) {
            InProgressPiece::Getting(in_progress_piece_getting) => {
                // Try to get the piece without releasing lock to make sure successfully
                // downloaded piece gets stored
                let maybe_piece = self.get_piece_fast_internal(piece_index).await;
                // Store the result for others to observe
                in_progress_piece_getting.store_piece_getting_result(&maybe_piece);
                maybe_piece
            }
            InProgressPiece::Waiting {
                in_progress_piece_mutex,
            } => {
                trace!(%piece_index, "Piece is already in progress, waiting for result #1");
                // Doesn't matter if it was successful or not here
                in_progress_piece_mutex.lock().await.clone()
            }
        }
    }

    async fn get_piece_fast_internal(&self, piece_index: PieceIndex) -> Option<Piece> {
        let inner = &self.inner;

        trace!(%piece_index, "Getting piece from farmer cache");
        if let Some(piece) = inner
            .farmer_cache
            .get_piece(piece_index.to_multihash())
            .await
        {
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
        let _guard = self.inner.request_semaphore.acquire().await;

        match InProgressPiece::new(piece_index, &self.inner.in_progress_pieces) {
            InProgressPiece::Getting(in_progress_piece_getting) => {
                // Try to get the piece without releasing lock to make sure successfully
                // downloaded piece gets stored
                let maybe_piece = self.get_piece_slow_internal(piece_index).await;
                // Store the result for others to observe
                in_progress_piece_getting.store_piece_getting_result(&maybe_piece);
                maybe_piece
            }
            InProgressPiece::Waiting {
                in_progress_piece_mutex,
            } => {
                trace!(%piece_index, "Piece is already in progress, waiting for result #2");
                if let Some(piece) = in_progress_piece_mutex.lock().await.clone() {
                    trace!(
                        %piece_index,
                        "Piece was already in progress and downloaded successfully #1"
                    );
                    return Some(piece);
                }

                // Try again just in case
                self.get_piece_slow_internal(piece_index).await
            }
        }
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

    async fn get_piece_internal(&self, piece_index: PieceIndex) -> Option<Piece> {
        {
            let retries = AtomicU32::new(0);
            let max_retries = u32::from(self.inner.dsn_cache_retry_policy.max_retries);
            let mut backoff = self.inner.dsn_cache_retry_policy.backoff.clone();
            backoff.reset();

            let maybe_piece_fut = retry(backoff, || async {
                let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

                if let Some(piece) = self.get_piece_fast_internal(piece_index).await {
                    trace!(%piece_index, current_attempt, "Got piece fast");
                    return Ok(Some(piece));
                }
                if current_attempt >= max_retries {
                    if max_retries > 0 {
                        debug!(
                            %piece_index,
                            current_attempt,
                            max_retries,
                            "Couldn't get a piece fast. No retries left"
                        );
                    }
                    return Ok(None);
                }

                trace!(%piece_index, current_attempt, "Couldn't get a piece fast, retrying...");

                Err(backoff::Error::transient("Couldn't get piece fast"))
            });

            if let Ok(Some(piece)) = maybe_piece_fut.await {
                trace!(%piece_index, "Got piece from cache successfully");
                return Some(piece);
            }
        };

        if let Some(piece) = self.get_piece_slow_internal(piece_index).await {
            return Some(piece);
        }

        debug!(
            %piece_index,
            "Cannot acquire piece: all methods yielded empty result"
        );
        None
    }

    /// Downgrade to [`WeakFarmerPieceGetter`] in order to break reference cycles with internally
    /// used [`Arc`]
    pub fn downgrade(&self) -> WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
        WeakFarmerPieceGetter {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

#[async_trait]
impl<FarmIndex, CacheIndex, PV, NC> PieceGetter for FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    CacheIndex: Hash + Eq + Copy + fmt::Debug + fmt::Display + Send + Sync + 'static,
    usize: From<CacheIndex>,
    CacheIndex: TryFrom<usize>,
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let _guard = self.inner.request_semaphore.acquire().await;

        match InProgressPiece::new(piece_index, &self.inner.in_progress_pieces) {
            InProgressPiece::Getting(in_progress_piece_getting) => {
                // Try to get the piece without releasing lock to make sure successfully
                // downloaded piece gets stored
                let maybe_piece = self.get_piece_internal(piece_index).await;
                // Store the result for others to observe
                in_progress_piece_getting.store_piece_getting_result(&maybe_piece);
                Ok(maybe_piece)
            }
            InProgressPiece::Waiting {
                in_progress_piece_mutex,
            } => {
                trace!(%piece_index, "Piece is already in progress, waiting for result #3");
                if let Some(piece) = in_progress_piece_mutex.lock().await.clone() {
                    trace!(
                        %piece_index,
                        "Piece was already in progress and downloaded successfully #2"
                    );
                    return Ok(Some(piece));
                }

                // Try again just in case
                Ok(self.get_piece_internal(piece_index).await)
            }
        }
    }
}

/// Weak farmer piece getter, can be upgraded to [`FarmerPieceGetter`]
pub struct WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
    inner: Weak<Inner<FarmIndex, CacheIndex, PV, NC>>,
}

impl<FarmIndex, CacheIndex, PV, NC> fmt::Debug
    for WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeakFarmerPieceGetter")
            .finish_non_exhaustive()
    }
}

impl<FarmIndex, CacheIndex, PV, NC> Clone for WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl<FarmIndex, CacheIndex, PV, NC> PieceGetter
    for WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>
where
    FarmIndex: Hash + Eq + Copy + fmt::Debug + Send + Sync + 'static,
    usize: From<FarmIndex>,
    CacheIndex: Hash + Eq + Copy + fmt::Debug + fmt::Display + Send + Sync + 'static,
    usize: From<CacheIndex>,
    CacheIndex: TryFrom<usize>,
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

impl<FarmIndex, CacheIndex, PV, NC> WeakFarmerPieceGetter<FarmIndex, CacheIndex, PV, NC> {
    /// Try to upgrade to [`FarmerPieceGetter`] if there is at least one other instance of it alive
    pub fn upgrade(&self) -> Option<FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>> {
        Some(FarmerPieceGetter {
            inner: self.inner.upgrade()?,
        })
    }
}
