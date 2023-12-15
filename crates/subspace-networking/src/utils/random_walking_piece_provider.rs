//! Provides methods to retrieve pieces from DSN L1 via random walk.

use crate::utils::piece_provider::PieceValidator;
use crate::{Node, PieceByIndexRequest, PieceByIndexResponse};
use futures::StreamExt;
use libp2p::PeerId;
use subspace_core_primitives::{Piece, PieceIndex};
use tracing::{debug, trace, warn};

/// Piece provider with cancellation and optional piece validator.
pub struct RandomWalkingPieceProvider<PV> {
    node: Node,
    piece_validator: Option<PV>,
}

impl<PV> RandomWalkingPieceProvider<PV>
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

    /// Get piece from L1
    pub async fn get_piece(&self, piece_index: PieceIndex, walking_rounds: usize) -> Option<Piece> {
        for round in 0..walking_rounds {
            debug!(%piece_index, round, "Random walk round");

            let result = self.get_piece_by_random_walking(piece_index).await;

            if result.is_some() {
                return result;
            }
        }

        debug!(%piece_index, "Random walking piece retrieval failed.");

        None
    }

    /// Get piece from L1 by random walking
    async fn get_piece_by_random_walking(&self, piece_index: PieceIndex) -> Option<Piece> {
        trace!(%piece_index, "get_piece_by_random_walking round");

        // Random walk key
        let key = PeerId::random();

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_closest_peers_result = request_batch.get_closest_peers(key.into()).await;

        match get_closest_peers_result {
            Ok(mut get_closest_peers_stream) => {
                while let Some(peer_id) = get_closest_peers_stream.next().await {
                    trace!(%piece_index, %peer_id, "get_closest_peers returned an item");

                    let request_result = request_batch
                        .send_generic_request(peer_id, PieceByIndexRequest { piece_index })
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                            trace!(%peer_id, %piece_index, ?key, "Piece request succeeded.");

                            if let Some(validator) = &self.piece_validator {
                                return validator.validate_piece(peer_id, piece_index, piece).await;
                            } else {
                                return Some(piece);
                            }
                        }
                        Ok(PieceByIndexResponse { piece: None }) => {
                            debug!(%peer_id, %piece_index, ?key, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            debug!(%peer_id, %piece_index, ?key, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index, ?key, ?err, "get_closest_peers returned an error");
            }
        }

        None
    }
}
