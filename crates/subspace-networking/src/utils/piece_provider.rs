use crate::utils::multihash::ToMultihash;
use crate::{Node, PieceByHashRequest, PieceByHashResponse};
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use libp2p::PeerId;
use std::error::Error;
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash};
use tracing::{debug, trace, warn};

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait]
pub trait PieceValidator: Sync + Send {
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece>;
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
    pub fn new(node: Node, piece_validator: Option<PV>) -> Self {
        Self {
            node,
            piece_validator,
        }
    }

    // Get from piece cache (L2) or archival storage (L1)
    async fn get_piece_from_storage(&self, piece_index: PieceIndex) -> Option<Piece> {
        let piece_index_hash = PieceIndexHash::from_index(piece_index);
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

    pub async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        trace!(%piece_index, "Piece request.");

        let backoff = ExponentialBackoff {
            initial_interval: GET_PIECE_INITIAL_INTERVAL,
            max_interval: GET_PIECE_MAX_INTERVAL,
            // Try until we get a valid piece
            max_elapsed_time: None,
            ..ExponentialBackoff::default()
        };

        retry(backoff, || async {
            if let Some(piece) = self.get_piece_from_storage(piece_index).await {
                trace!(%piece_index, "Got piece");
                return Ok(Some(piece));
            }

            warn!(%piece_index, "Couldn't get a piece from DSN. Retrying...");

            Err(backoff::Error::transient(
                "Couldn't get piece from DSN".into(),
            ))
        })
        .await
    }
}
