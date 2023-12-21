//! Provides methods to retrieve pieces from DSN.

use crate::utils::multihash::ToMultihash;
use crate::{Node, PieceByIndexRequest, PieceByIndexResponse};
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use libp2p::PeerId;
use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex};
use tracing::{debug, trace, warn};

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);

/// Validates piece against using its commitment.
#[async_trait]
pub trait PieceValidator: Sync + Send {
    /// Validates piece against using its commitment.
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece>;
}

/// Stub implementation for piece validation.
pub struct NoPieceValidator;

/// Defines retry policy on error during piece acquiring.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub enum RetryPolicy {
    /// Retry N times (including zero)
    Limited(u16),
    /// No restrictions on retries
    Unlimited,
}

impl Default for RetryPolicy {
    #[inline]
    fn default() -> Self {
        Self::Limited(0)
    }
}

#[async_trait]
impl PieceValidator for NoPieceValidator {
    async fn validate_piece(&self, _: PeerId, _: PieceIndex, piece: Piece) -> Option<Piece> {
        Some(piece)
    }
}

/// Piece provider with cancellation and optional piece validator.
pub struct PieceProvider<PV> {
    node: Node,
    piece_validator: Option<PV>,
}

impl<PV> PieceProvider<PV>
where
    PV: PieceValidator,
{
    /// Creates new piece provider.
    pub fn new(node: Node, piece_validator: Option<PV>) -> Self {
        Self {
            node,
            piece_validator,
        }
    }

    // Get from piece cache (L2)
    async fn get_piece_from_cache(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key = piece_index.to_multihash();

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_providers_result = request_batch.get_providers(key).await;

        match get_providers_result {
            Ok(mut get_providers_stream) => {
                while let Some(provider_id) = get_providers_stream.next().await {
                    trace!(%piece_index, %provider_id, "get_providers returned an item");

                    let request_result = request_batch
                        .send_generic_request(provider_id, PieceByIndexRequest { piece_index })
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                            trace!(%provider_id, %piece_index, ?key, "Piece request succeeded.");

                            if let Some(validator) = &self.piece_validator {
                                return validator
                                    .validate_piece(provider_id, piece_index, piece)
                                    .await;
                            } else {
                                return Some(piece);
                            }
                        }
                        Ok(PieceByIndexResponse { piece: None }) => {
                            debug!(%provider_id, %piece_index, ?key, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            debug!(%provider_id, %piece_index, ?key, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index,?key, ?err, "get_providers returned an error");
            }
        }

        None
    }

    /// Returns piece by its index from farmer's piece cache (L2).
    /// Uses retry policy for error handling.
    pub async fn get_piece_from_dsn_cache(
        &self,
        piece_index: PieceIndex,
        retry_policy: RetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        trace!(%piece_index, "Piece request.");

        let backoff = ExponentialBackoff {
            initial_interval: GET_PIECE_INITIAL_INTERVAL,
            max_interval: GET_PIECE_MAX_INTERVAL,
            // Try until we get a valid piece
            max_elapsed_time: None,
            multiplier: 1.75,
            ..ExponentialBackoff::default()
        };

        let retries = AtomicU64::default();

        retry(backoff, || async {
            let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

            if let Some(piece) = self.get_piece_from_cache(piece_index).await {
                trace!(%piece_index, current_attempt, "Got piece");
                return Ok(Some(piece));
            }

            match retry_policy {
                RetryPolicy::Limited(max_retries) => {
                    if current_attempt >= max_retries.into() {
                        if max_retries > 0 {
                            debug!(
                                %piece_index,
                                current_attempt,
                                max_retries,
                                "Couldn't get a piece from DSN L2. No retries left."
                            );
                        }
                        return Ok(None);
                    }

                    max_retries as u64
                }
                RetryPolicy::Unlimited => u64::MAX,
            };

            trace!(%piece_index, current_attempt, "Couldn't get a piece from DSN L2. Retrying...");

            Err(backoff::Error::transient(
                "Couldn't get piece from DSN".into(),
            ))
        })
        .await
    }

    /// Get piece from a particular peer.
    pub async fn get_piece_from_peer(
        &self,
        peer_id: PeerId,
        piece_index: PieceIndex,
    ) -> Option<Piece> {
        let request_result = self
            .node
            .send_generic_request(peer_id, PieceByIndexRequest { piece_index })
            .await;

        match request_result {
            Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                trace!(%peer_id, %piece_index, "Piece request succeeded.");

                if let Some(validator) = &self.piece_validator {
                    return validator.validate_piece(peer_id, piece_index, piece).await;
                } else {
                    return Some(piece);
                }
            }
            Ok(PieceByIndexResponse { piece: None }) => {
                debug!(%peer_id, %piece_index, "Piece request returned empty piece.");
            }
            Err(error) => {
                debug!(%peer_id, %piece_index, ?error, "Piece request failed.");
            }
        }

        None
    }

    /// Get piece from archival storage (L1). The algorithm tries to get a piece from currently
    /// connected peers and falls back to random walking.
    pub async fn get_piece_from_archival_storage(
        &self,
        piece_index: PieceIndex,
        max_random_walking_rounds: usize,
    ) -> Option<Piece> {
        // TODO: consider using retry policy for L1 lookups as well.
        trace!(%piece_index, "Getting piece from archival storage..");

        let connected_peers = {
            let connected_peers = match self.node.connected_peers().await {
                Ok(connected_peers) => connected_peers,
                Err(err) => {
                    debug!(%piece_index, ?err, "Cannot get connected peers (DSN L1 lookup)");

                    Default::default()
                }
            };

            HashSet::<PeerId>::from_iter(connected_peers)
        };

        if connected_peers.is_empty() {
            debug!(%piece_index, "Cannot acquire piece from no connected peers (DSN L1 lookup)");
        } else {
            for peer_id in connected_peers.iter() {
                let maybe_piece = self.get_piece_from_peer(*peer_id, piece_index).await;

                if maybe_piece.is_some() {
                    trace!(%piece_index, %peer_id, "DSN L1 lookup from connected peers succeeded");

                    return maybe_piece;
                }
            }
        }

        trace!(%piece_index, "Getting piece from DSN L1 using random walk.");
        let random_walk_result = self
            .get_piece_by_random_walking(piece_index, max_random_walking_rounds)
            .await;

        if random_walk_result.is_some() {
            trace!(%piece_index, "DSN L1 lookup via random walk succeeded");

            return random_walk_result;
        } else {
            debug!(
                %piece_index,
                %max_random_walking_rounds,
                "Cannot acquire piece from DSN L1: random walk failed"
            );
        }

        None
    }

    /// Get piece from L1 by random walking
    async fn get_piece_by_random_walking(
        &self,
        piece_index: PieceIndex,
        walking_rounds: usize,
    ) -> Option<Piece> {
        for round in 0..walking_rounds {
            debug!(%piece_index, round, "Random walk round");

            let result = self
                .get_piece_by_random_walking_from_single_round(piece_index, round)
                .await;

            if result.is_some() {
                return result;
            }
        }

        debug!(%piece_index, "Random walking piece retrieval failed.");

        None
    }

    /// Get piece from L1 by random walking (single round)
    async fn get_piece_by_random_walking_from_single_round(
        &self,
        piece_index: PieceIndex,
        round: usize,
    ) -> Option<Piece> {
        trace!(%piece_index, "get_piece_by_random_walking round");

        // Random walk key
        let key = PeerId::random();

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_closest_peers_result = request_batch.get_closest_peers(key.into()).await;

        match get_closest_peers_result {
            Ok(mut get_closest_peers_stream) => {
                while let Some(peer_id) = get_closest_peers_stream.next().await {
                    trace!(%piece_index, %peer_id, %round, "get_closest_peers returned an item");

                    let request_result = request_batch
                        .send_generic_request(peer_id, PieceByIndexRequest { piece_index })
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                            trace!(%peer_id, %piece_index, ?key, %round,  "Piece request succeeded.");

                            if let Some(validator) = &self.piece_validator {
                                return validator.validate_piece(peer_id, piece_index, piece).await;
                            } else {
                                return Some(piece);
                            }
                        }
                        Ok(PieceByIndexResponse { piece: None }) => {
                            debug!(%peer_id, %piece_index, ?key, %round, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            debug!(%peer_id, %piece_index, ?key, %round, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index, ?key, ?err, %round, "get_closest_peers returned an error");
            }
        }

        None
    }
}
