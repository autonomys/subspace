use crate::node::Node;
use crate::utils::multihash::ToMultihash;
use crate::{PieceAnnouncementRequest, PieceAnnouncementResponse};
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use libp2p::multihash::Multihash;
use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;
use subspace_core_primitives::PieceIndexHash;
use tracing::{debug, trace, warn};

const MAX_PEERS_TO_ACKNOWLEDGE: usize = 20; // Similar to Kademlia

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
                "Local piece publishing returned an error"
            );

            return Err(backoff::Error::transient(
                "Local piece publishing failed".into(),
            ));
        }
        Ok(false) => {
            debug!(?piece_index_hash, ?key, "Local piece publishing failed");

            return Err(backoff::Error::transient(
                "Local piece publishing was unsuccessful".into(),
            ));
        }
        Ok(true) => {
            trace!(?piece_index_hash, ?key, "Local piece publishing succeeded");
        }
    };

    let public_announce_result = announce_key(node, key).await;
    match public_announce_result {
        Err(error) => {
            debug!(
                ?error,
                ?piece_index_hash,
                ?key,
                "Public piece publishing returned an error"
            );

            Err(backoff::Error::transient(
                "Public piece publishing failed".into(),
            ))
        }
        Ok(false) => {
            debug!(
                ?piece_index_hash,
                ?key,
                "Public piece publishing for a sector failed"
            );

            Err(backoff::Error::transient(
                "Public piece publishing was unsuccessful".into(),
            ))
        }
        Ok(true) => {
            trace!(
                ?piece_index_hash,
                ?key,
                "Public piece publishing for a sector succeeded"
            );

            Ok(())
        }
    }
}

/// Announce key using Kademlia `get_closest_peers` and custom requests.
async fn announce_key(
    node: &Node,
    key: Multihash,
) -> Result<bool, Box<dyn Error + Send + Sync + 'static>> {
    let get_peers_result = node.get_closest_peers(key).await;

    let mut get_peers_stream = match get_peers_result {
        Ok(get_peers_stream) => get_peers_stream,
        Err(err) => {
            warn!(?err, "get_closest_peers returned an error");

            return Err(err.into());
        }
    };

    let mut contacted_peers = HashSet::new();
    let mut acknowledged_peers = HashSet::new();
    let external_addresses: Vec<Vec<u8>> = node
        .external_addresses()
        .iter()
        .map(|addr| addr.to_vec())
        .collect();
    while let Some(peer_id) = get_peers_stream.next().await {
        trace!(?key, %peer_id, "get_closest_peers returned an item");

        if contacted_peers.contains(&peer_id) {
            continue; // skip duplicated PeerId
        }

        contacted_peers.insert(peer_id);

        let request_result = node
            .send_generic_request(
                peer_id,
                PieceAnnouncementRequest {
                    piece_index_hash: key.to_bytes(),
                    addresses: external_addresses.clone(),
                },
            )
            .await;

        match request_result {
            Ok(PieceAnnouncementResponse::Success) => {
                trace!(
                    %peer_id,
                    ?key,
                    "Piece announcement request succeeded."
                );
            }
            Err(error) => {
                debug!(%peer_id, ?key, ?error, "Piece announcement request failed.");
            }
        }

        acknowledged_peers.insert(peer_id);

        // we hit the target peer number
        if acknowledged_peers.len() >= MAX_PEERS_TO_ACKNOWLEDGE {
            return Ok(true);
        }
    }

    // we publish the key to at least one peer
    Ok(!acknowledged_peers.is_empty())
}
