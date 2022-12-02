use futures::StreamExt;
use parity_scale_codec::Encode;
use std::collections::BTreeSet;
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
#[derive(Clone)]
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
                // https://github.com/libp2p/rust-libp2p/issues/3048
                let set = BTreeSet::from_iter(vec![self.dsn_node.id().to_bytes()]);

                let result = self.dsn_node.put_value(key, set.encode()).await;

                match result {
                    Ok(mut stream) => {
                        if stream.next().await.is_some() {
                            trace!(%piece_index, ?key, "Piece publishing for a sector succeeded");
                            break 'attempts;
                        } else {
                            trace!(%piece_index, ?key, "Piece publishing for a sector failed");
                        }
                    }
                    Err(error) => {
                        error!(?error, %piece_index, ?key, "Piece publishing for a sector returned an error");

                        // pause before retrying
                        sleep(Duration::from_secs(
                            PUBLISH_PIECE_BY_SECTOR_WAITING_DURATION_IN_SECS,
                        ))
                        .await;
                    }
                }
            }
        }

        Ok(())
    }
}
