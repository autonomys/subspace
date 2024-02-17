use crate::farmer_cache::FarmerCache;
use crate::utils::plotted_pieces::PlottedPieces;
use crate::NodeClient;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::error::Error;
use std::sync::{Arc, Weak};
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator, RetryPolicy};
use tracing::{debug, error, trace};

const MAX_RANDOM_WALK_ROUNDS: usize = 15;

struct Inner<PV, NC> {
    piece_provider: PieceProvider<PV>,
    farmer_cache: FarmerCache,
    node_client: NC,
    plotted_pieces: Arc<Mutex<Option<PlottedPieces>>>,
}

pub struct FarmerPieceGetter<PV, NC> {
    inner: Arc<Inner<PV, NC>>,
}

impl<PV, NC> Clone for FarmerPieceGetter<PV, NC> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<PV, NC> FarmerPieceGetter<PV, NC> {
    pub fn new(
        piece_provider: PieceProvider<PV>,
        farmer_cache: FarmerCache,
        node_client: NC,
        plotted_pieces: Arc<Mutex<Option<PlottedPieces>>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                piece_provider,
                farmer_cache,
                node_client,
                plotted_pieces,
            }),
        }
    }

    /// Downgrade to [`WeakFarmerPieceGetter`] in order to break reference cycles with internally
    /// used [`Arc`]
    pub fn downgrade(&self) -> WeakFarmerPieceGetter<PV, NC> {
        WeakFarmerPieceGetter {
            inner: Arc::downgrade(&self.inner),
        }
    }

    fn convert_retry_policy(retry_policy: PieceGetterRetryPolicy) -> RetryPolicy {
        match retry_policy {
            PieceGetterRetryPolicy::Limited(retries) => RetryPolicy::Limited(retries),
            PieceGetterRetryPolicy::Unlimited => RetryPolicy::Unlimited,
        }
    }
}

#[async_trait]
impl<PV, NC> PieceGetter for FarmerPieceGetter<PV, NC>
where
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let key = RecordKey::from(piece_index.to_multihash());

        let inner = &self.inner;

        trace!(%piece_index, "Getting piece from farmer cache");
        if let Some(piece) = inner.farmer_cache.get_piece(key).await {
            trace!(%piece_index, "Got piece from farmer cache successfully");
            return Ok(Some(piece));
        }

        // L2 piece acquisition
        trace!(%piece_index, "Getting piece from DSN L2 cache");
        let maybe_piece = inner
            .piece_provider
            .get_piece_from_dsn_cache(piece_index, Self::convert_retry_policy(retry_policy))
            .await?;

        if maybe_piece.is_some() {
            trace!(%piece_index, "Got piece from DSN L2 cache successfully");
            return Ok(maybe_piece);
        }

        // Try node's RPC before reaching to L1 (archival storage on DSN)
        trace!(%piece_index, "Getting piece from node");
        match inner.node_client.piece(piece_index).await {
            Ok(Some(piece)) => {
                trace!(%piece_index, "Got piece from node successfully");
                return Ok(Some(piece));
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

        trace!(%piece_index, "Getting piece from local plot");
        let maybe_read_piece_fut = inner
            .plotted_pieces
            .lock()
            .as_ref()
            .and_then(|plotted_pieces| plotted_pieces.read_piece(&piece_index));

        if let Some(read_piece_fut) = maybe_read_piece_fut {
            if let Some(piece) = read_piece_fut.await {
                trace!(%piece_index, "Got piece from local plot successfully");
                return Ok(Some(piece));
            }
        }

        // L1 piece acquisition
        trace!(%piece_index, "Getting piece from DSN L1.");

        let archival_storage_search_result = inner
            .piece_provider
            .get_piece_from_archival_storage(piece_index, MAX_RANDOM_WALK_ROUNDS)
            .await;

        if archival_storage_search_result.is_some() {
            trace!(%piece_index, "DSN L1 lookup succeeded");

            return Ok(archival_storage_search_result);
        }

        debug!(
            %piece_index,
            "Cannot acquire piece: all methods yielded empty result"
        );
        Ok(None)
    }
}

/// Weak farmer piece getter, can be upgraded to [`FarmerPieceGetter`]
#[derive(Debug)]
pub struct WeakFarmerPieceGetter<PV, NC> {
    inner: Weak<Inner<PV, NC>>,
}

impl<PV, NC> Clone for WeakFarmerPieceGetter<PV, NC> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl<PV, NC> PieceGetter for WeakFarmerPieceGetter<PV, NC>
where
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let Some(piece_getter) = self.upgrade() else {
            debug!("Farmer piece getter upgrade didn't succeed");
            return Ok(None);
        };

        piece_getter.get_piece(piece_index, retry_policy).await
    }
}

impl<PV, NC> WeakFarmerPieceGetter<PV, NC> {
    /// Try to upgrade to [`FarmerPieceGetter`] if there is at least one other instance of it alive
    pub fn upgrade(&self) -> Option<FarmerPieceGetter<PV, NC>> {
        Some(FarmerPieceGetter {
            inner: self.inner.upgrade()?,
        })
    }
}
