use crate::node::Node;
use crate::utils::multihash::ToMultihash;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use std::error::Error;
use std::time::Duration;
use subspace_core_primitives::{PieceIndex, PieceIndexHash};
use tracing::{debug, trace};

/// Defines initial duration between put_piece calls.
const PUT_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
/// Defines max duration between put_piece calls.
const PUT_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(30);

pub async fn announce_single_piece_with_backoff(
    piece_index: PieceIndex,
    node: &Node,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let backoff = ExponentialBackoff {
        initial_interval: PUT_PIECE_INITIAL_INTERVAL,
        max_interval: PUT_PIECE_MAX_INTERVAL,
        // Try until we get a valid piece
        max_elapsed_time: None,
        ..ExponentialBackoff::default()
    };

    retry(backoff, || announce_single_piece(piece_index, node)).await
}

async fn announce_single_piece(
    piece_index: PieceIndex,
    node: &Node,
) -> Result<(), backoff::Error<Box<dyn Error + Send + Sync + 'static>>> {
    let key = PieceIndexHash::from_index(piece_index).to_multihash();

    let result = node.start_announcing(key.into()).await;

    match result {
        Err(error) => {
            debug!(?error, %piece_index, ?key, "Piece publishing for a sector returned an error");

            Err(backoff::Error::transient("Piece publishing failed".into()))
        }
        Ok(mut stream) => {
            if stream.next().await.is_some() {
                trace!(%piece_index, ?key, "Piece publishing for a sector succeeded");

                Ok(())
            } else {
                debug!(%piece_index, ?key, "Piece publishing for a sector failed");

                Err(backoff::Error::transient(
                    "Piece publishing was unsuccessful".into(),
                ))
            }
        }
    }
}
