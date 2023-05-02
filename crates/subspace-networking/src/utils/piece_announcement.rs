use crate::node::Node;
use crate::utils::multihash::ToMultihash;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use std::error::Error;
use std::time::Duration;
use subspace_core_primitives::{PieceIndex, PieceIndexHash};
use tracing::{debug, trace};

/// Defines initial duration between put_piece calls.
const PUT_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
/// Defines max duration between put_piece calls.
const PUT_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(30);

fn default_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: PUT_PIECE_INITIAL_INTERVAL,
        max_interval: PUT_PIECE_MAX_INTERVAL,
        // Try until we get a valid piece
        max_elapsed_time: None,
        ..ExponentialBackoff::default()
    }
}

pub async fn announce_single_piece_index_with_backoff(
    piece_index: PieceIndex,
    node: &Node,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    retry(default_backoff(), || {
        announce_single_piece_index_hash(piece_index.hash(), node)
    })
    .await
}

pub async fn announce_single_piece_index_hash_with_backoff(
    piece_index_hash: PieceIndexHash,
    node: &Node,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    retry(default_backoff(), || {
        announce_single_piece_index_hash(piece_index_hash, node)
    })
    .await
}

pub async fn announce_single_piece_index_hash(
    piece_index_hash: PieceIndexHash,
    node: &Node,
) -> Result<(), backoff::Error<Box<dyn Error + Send + Sync + 'static>>> {
    let key = piece_index_hash.to_multihash();

    let local_announcing_result = node.start_local_announcing(key.into()).await;
    match local_announcing_result {
        Err(error) => {
            debug!(
                ?error,
                ?piece_index_hash,
                ?key,
                "Local piece publishing for a sector returned an error"
            );

            return Err(backoff::Error::transient(
                "Local piece publishing failed".into(),
            ));
        }
        Ok(false) => {
            debug!(
                ?piece_index_hash,
                ?key,
                "Local piece publishing for a sector failed"
            );

            return Err(backoff::Error::transient(
                "Local piece publishing was unsuccessful".into(),
            ));
        }
        Ok(true) => {
            trace!(
                ?piece_index_hash,
                ?key,
                "Local piece publishing for a sector succeeded"
            );
        }
    };

    Ok(())
}
