//! Farmer-specific piece getter

use crate::farm::plotted_pieces::PlottedPieces;
use crate::farmer_cache::FarmerCache;
use crate::node_client::NodeClient;
use async_lock::{RwLock as AsyncRwLock, Semaphore};
use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::channel::mpsc;
use futures::future::FusedFuture;
use futures::stream::FuturesUnordered;
use futures::{stream, FutureExt, Stream, StreamExt};
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_farmer_components::PieceGetter;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use tracing::{debug, error, trace};

pub mod piece_validator;

const MAX_RANDOM_WALK_ROUNDS: usize = 15;

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
                request_semaphore,
            }),
        }
    }

    /// Fast way to get piece using various caches
    pub async fn get_piece_fast(&self, piece_index: PieceIndex) -> Option<Piece> {
        let _guard = self.inner.request_semaphore.acquire().await;

        self.get_piece_fast_internal(piece_index).await
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

        self.get_piece_slow_internal(piece_index).await
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
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        let _guard = self.inner.request_semaphore.acquire().await;

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
                return Ok(Some(piece));
            }
        };

        if let Some(piece) = self.get_piece_slow_internal(piece_index).await {
            return Ok(Some(piece));
        }

        debug!(
            %piece_index,
            "Cannot acquire piece: all methods yielded empty result"
        );
        Ok(None)
    }

    async fn get_pieces<'a, PieceIndices>(
        &'a self,
        piece_indices: PieceIndices,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    >
    where
        PieceIndices: IntoIterator<Item = PieceIndex, IntoIter: Send> + Send + 'a,
    {
        let (tx, mut rx) = mpsc::unbounded();

        let fut = async move {
            let tx = &tx;

            debug!("Getting pieces from farmer cache");
            let mut pieces_not_found_in_farmer_cache = Vec::new();
            let mut pieces_in_farmer_cache =
                self.inner.farmer_cache.get_pieces(piece_indices).await;

            while let Some((piece_index, maybe_piece)) = pieces_in_farmer_cache.next().await {
                let Some(piece) = maybe_piece else {
                    pieces_not_found_in_farmer_cache.push(piece_index);
                    continue;
                };
                tx.unbounded_send((piece_index, Ok(Some(piece))))
                    .expect("This future isn't polled after receiver is dropped; qed");
            }

            if pieces_not_found_in_farmer_cache.is_empty() {
                return;
            }

            debug!(
                remaining_piece_count = %pieces_not_found_in_farmer_cache.len(),
                "Getting pieces from DSN cache"
            );
            let mut pieces_not_found_in_dsn_cache = Vec::new();
            let mut pieces_in_dsn_cache = self
                .inner
                .piece_provider
                .get_from_cache(pieces_not_found_in_farmer_cache)
                .await;

            while let Some((piece_index, maybe_piece)) = pieces_in_dsn_cache.next().await {
                let Some(piece) = maybe_piece else {
                    pieces_not_found_in_dsn_cache.push(piece_index);
                    continue;
                };
                // TODO: Would be nice to have concurrency here
                self.inner
                    .farmer_cache
                    .maybe_store_additional_piece(piece_index, &piece)
                    .await;
                tx.unbounded_send((piece_index, Ok(Some(piece))))
                    .expect("This future isn't polled after receiver is dropped; qed");
            }

            if pieces_not_found_in_dsn_cache.is_empty() {
                return;
            }

            debug!(
                remaining_piece_count = %pieces_not_found_in_dsn_cache.len(),
                "Getting pieces from node"
            );
            let pieces_not_found_on_node = pieces_not_found_in_dsn_cache
                .into_iter()
                .map(|piece_index| async move {
                    match self.inner.node_client.piece(piece_index).await {
                        Ok(Some(piece)) => {
                            trace!(%piece_index, "Got piece from node successfully");
                            self.inner
                                .farmer_cache
                                .maybe_store_additional_piece(piece_index, &piece)
                                .await;

                            tx.unbounded_send((piece_index, Ok(Some(piece))))
                                .expect("This future isn't polled after receiver is dropped; qed");
                            None
                        }
                        Ok(None) => Some(piece_index),
                        Err(error) => {
                            error!(
                                %error,
                                %piece_index,
                                "Failed to retrieve first segment piece from node"
                            );
                            Some(piece_index)
                        }
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_piece_index| async move { maybe_piece_index })
                .collect::<Vec<_>>()
                .await;

            if pieces_not_found_on_node.is_empty() {
                return;
            }

            debug!(
                remaining_piece_count = %pieces_not_found_on_node.len(),
                "Some pieces were not easily reachable"
            );
            pieces_not_found_on_node
                .into_iter()
                .map(|piece_index| async move {
                    let maybe_piece = self.get_piece_slow_internal(piece_index).await;

                    tx.unbounded_send((piece_index, Ok(maybe_piece)))
                        .expect("This future isn't polled after receiver is dropped; qed");
                })
                .collect::<FuturesUnordered<_>>()
                // Simply drain everything
                .for_each(|()| async {})
                .await;
        };
        let mut fut = Box::pin(fut.fuse());

        // Drive above future and stream back any pieces that were downloaded so far
        Ok(Box::new(stream::poll_fn(move |cx| {
            if !fut.is_terminated() {
                // Result doesn't matter, we'll need to poll stream below anyway
                let _ = fut.poll_unpin(cx);
            }

            if let Poll::Ready(maybe_result) = rx.poll_next_unpin(cx) {
                return Poll::Ready(maybe_result);
            }

            // Exit will be done by the stream above
            Poll::Pending
        })))
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

/// This wrapper allows us to return the stream, which in turn depends on `piece_getter` that was
/// previously on the stack of the inner function. What this wrapper does is create a
/// self-referential data structure, so we can move both together, while still implementing `Stream`
/// trait as necessary.
#[ouroboros::self_referencing]
struct StreamWithPieceGetter<FarmIndex, CacheIndex, PV, NC>
where
    FarmIndex: 'static,
    CacheIndex: 'static,
    PV: 'static,
    NC: 'static,
{
    piece_getter: FarmerPieceGetter<FarmIndex, CacheIndex, PV, NC>,
    #[borrows(piece_getter)]
    #[covariant]
    stream:
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'this>,
}

impl<FarmIndex, CacheIndex, PV, NC> Stream for StreamWithPieceGetter<FarmIndex, CacheIndex, PV, NC>
where
    FarmIndex: 'static,
    CacheIndex: 'static,
    PV: 'static,
    NC: 'static,
{
    type Item = (PieceIndex, anyhow::Result<Option<Piece>>);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .with_stream_mut(|stream| stream.poll_next_unpin(cx))
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
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        let Some(piece_getter) = self.upgrade() else {
            debug!("Farmer piece getter upgrade didn't succeed");
            return Ok(None);
        };

        piece_getter.get_piece(piece_index).await
    }

    async fn get_pieces<'a, PieceIndices>(
        &'a self,
        piece_indices: PieceIndices,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    >
    where
        PieceIndices: IntoIterator<Item = PieceIndex, IntoIter: Send> + Send + 'a,
    {
        let Some(piece_getter) = self.upgrade() else {
            debug!("Farmer piece getter upgrade didn't succeed");
            return Ok(Box::new(stream::iter(
                piece_indices
                    .into_iter()
                    .map(|piece_index| (piece_index, Ok(None))),
            )));
        };

        // TODO: This is necessary due to more complex lifetimes not yet supported by ouroboros, see
        //  https://github.com/someguynamedjosh/ouroboros/issues/112
        let piece_indices = piece_indices.into_iter().collect::<Vec<_>>();
        let stream_with_piece_getter =
            StreamWithPieceGetter::try_new_async_send(piece_getter, move |piece_getter| {
                piece_getter.get_pieces(piece_indices)
            })
            .await?;

        Ok(Box::new(stream_with_piece_getter))
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
