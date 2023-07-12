//! Provides methods to retrieve pieces from DSN.

use crate::utils::multihash::ToMultihash;
use crate::{Node, PieceByHashRequest, PieceByHashResponse};
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use libp2p::PeerId;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex};
use tracing::{debug, error, trace, warn};

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(3);
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

    // Get from piece cache (L2) or archival storage (L1)
    async fn get_piece_from_storage(&self, piece_index: PieceIndex) -> Option<Piece> {
        let piece_index_hash = piece_index.hash();
        let key = piece_index_hash.to_multihash();

        let get_providers_result = self.node.get_providers(key).await;

        match get_providers_result {
            Ok(mut get_providers_stream) => {
                while let Some(provider_id) = get_providers_stream.next().await {
                    trace!(%piece_index, %provider_id, "get_providers returned an item");

                    let request_result = self
                        .node
                        .send_generic_request(provider_id, PieceByHashRequest { piece_index_hash })
                        .await;

                    match request_result {
                        Ok(PieceByHashResponse { piece: Some(piece) }) => {
                            trace!(%provider_id, %piece_index, ?key, "Piece request succeeded.");

                            if let Some(validator) = &self.piece_validator {
                                return validator
                                    .validate_piece(provider_id, piece_index, piece)
                                    .await;
                            } else {
                                return Some(piece);
                            }
                        }
                        Ok(PieceByHashResponse { piece: None }) => {
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

    /// Returns piece by its index. Uses retry policy for error handling.
    pub async fn get_piece(
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
            ..ExponentialBackoff::default()
        };

        let retries = AtomicU64::default();

        retry(backoff, || async {
            let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

            if let Some(piece) = self.get_piece_from_storage(piece_index).await {
                trace!(%piece_index, current_attempt, "Got piece");
                return Ok(Some(piece));
            }

            match retry_policy {
                RetryPolicy::Limited(max_retries) => {
                    if current_attempt >= max_retries.into() {
                        if max_retries > 0 {
                            error!(
                                %piece_index,
                                current_attempt,
                                max_retries,
                                "Couldn't get a piece from DSN. No retries left."
                            );
                        }
                        return Ok(None);
                    }

                    max_retries as u64
                }
                RetryPolicy::Unlimited => u64::MAX,
            };

            debug!(%piece_index, current_attempt, "Couldn't get a piece from DSN. Retrying...");

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
        let piece_index_hash = piece_index.hash();
        let key = piece_index_hash.to_multihash();

        let request_result = self
            .node
            .send_generic_request(peer_id, PieceByHashRequest { piece_index_hash })
            .await;

        match request_result {
            Ok(PieceByHashResponse { piece: Some(piece) }) => {
                trace!(%peer_id, %piece_index, ?key, "Piece request succeeded.");

                if let Some(validator) = &self.piece_validator {
                    return validator.validate_piece(peer_id, piece_index, piece).await;
                } else {
                    return Some(piece);
                }
            }
            Ok(PieceByHashResponse { piece: None }) => {
                debug!(%peer_id, %piece_index, ?key, "Piece request returned empty piece.");
            }
            Err(error) => {
                debug!(%peer_id, %piece_index, ?key, ?error, "Piece request failed.");
            }
        }

        None
    }
}
