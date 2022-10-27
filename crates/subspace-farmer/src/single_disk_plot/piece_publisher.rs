use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PieceIndex, PieceIndexHash};
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::{Node, ToMultihash};
use tokio::time::sleep;
use tracing::{debug, error, trace};

/// Defines a duration between piece publishing calls.
const PUBLISH_PIECE_BY_SECTOR_WAITING_DURATION_IN_SECS: u64 = 1;

// Piece-by-sector DSN publishing helper.
pub(crate) struct PieceSectorPublisher {
    dsn_node: Node,
    cancelled: Arc<AtomicBool>,
}

impl PieceSectorPublisher {
    pub(crate) fn new(dsn_node: Node, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            dsn_node,
            cancelled,
        }
    }

    fn check_cancellation(&self) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        if self.cancelled.load(Ordering::Acquire) {
            debug!("Piece publishing was cancelled.");

            return Err("Piece publishing was cancelled.".into());
        }

        Ok(())
    }

    // Publishes pieces-by-sector to DSN in bulk. Supports cancellation.
    pub(crate) async fn publish_pieces(
        &self,
        pieces_indexes: Vec<PieceIndex>,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        for piece_index in pieces_indexes {
            'attempts: loop {
                self.check_cancellation()?;

                let key = PieceIndexHash::from_index(piece_index)
                    .to_multihash_by_code(MultihashCode::Sector);

                // TODO: rework to piece announcing (pull-model) after fixing
                // TODO: as an alternative - support multiple PeerID via CRDT-structure
                // https://github.com/libp2p/rust-libp2p/issues/3048
                let result = self
                    .dsn_node
                    .put_value(key, self.dsn_node.id().to_bytes())
                    .await;

                if let Err(error) = result {
                    error!(?error, %piece_index, ?key, "Piece publishing for a sector returned an error");

                    // pause before retrying
                    sleep(Duration::from_secs(
                        PUBLISH_PIECE_BY_SECTOR_WAITING_DURATION_IN_SECS,
                    ))
                    .await;
                } else {
                    trace!(%piece_index, ?key, "Piece publishing for a sector succeeded");

                    break 'attempts;
                }
            }
        }

        Ok(())
    }
}
