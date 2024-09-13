#![allow(dead_code)] // TODO: enable after the domain-sync implementation

use crate::mmr::get_offchain_key;
use crate::mmr::request_handler::{generate_protocol_name, MmrRequest, MmrResponse, MAX_MMR_ITEMS};
use futures::channel::oneshot;
use parity_scale_codec::{Decode, Encode};
use sc_network::{IfDisconnected, NetworkRequest, PeerId, RequestFailure};
use sc_network_sync::SyncingService;
use sp_blockchain::HeaderBackend;
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::{DbExternalities, OffchainStorage, StorageKind};
use sp_mmr_primitives::utils::NodesUtils;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::BlockNumber;
use tokio::time::sleep;
use tracing::{debug, error, trace};

const SYNC_PAUSE: Duration = Duration::from_secs(5);

/// Synchronize MMR-leafs from remote offchain storage of the synced peer.
pub async fn mmr_sync<Block, Client, NR, OS>(
    fork_id: Option<String>,
    client: Arc<Client>,
    network_service: NR,
    sync_service: Arc<SyncingService<Block>>,
    offchain_storage: OS,
    target_block: Option<BlockNumber>,
) -> Result<(), sp_blockchain::Error>
where
    Block: BlockT,
    NR: NetworkRequest,
    Client: HeaderBackend<Block>,
    OS: OffchainStorage,
{
    debug!("MMR sync started.");
    let info = client.info();
    let protocol_name = generate_protocol_name(info.genesis_hash, fork_id.as_deref());

    let mut offchain_db = OffchainDb::new(offchain_storage);

    // Look for existing local MMR-nodes
    let mut starting_position = {
        let mut starting_position: Option<u32> = None;
        for position in 0..=u32::MAX {
            let canon_key = get_offchain_key(position.into());
            if offchain_db
                .local_storage_get(StorageKind::PERSISTENT, &canon_key)
                .is_none()
            {
                starting_position = Some(position);
                break;
            }
        }

        match starting_position {
            None => {
                error!("Can't get starting MMR position - MMR storage is corrupted.");
                return Err(sp_blockchain::Error::Application(
                    "Can't get starting MMR position - MMR storage is corrupted.".into(),
                ));
            }
            Some(last_processed_position) => {
                debug!("MMR-sync last processed position: {last_processed_position}");

                last_processed_position
            }
        }
    };

    'outer: loop {
        let peers_info = match sync_service.peers_info().await {
            Ok(peers_info) => peers_info,
            Err(error) => {
                error!("Peers info request returned an error: {error}",);
                sleep(SYNC_PAUSE).await;

                continue;
            }
        };

        //  Enumerate peers until we find a suitable source for MMR
        'peers: for (peer_id, peer_info) in peers_info.iter() {
            trace!("MMR sync. peer = {peer_id}, info = {:?}", peer_info);

            if !peer_info.is_synced {
                trace!("MMR sync skipped (not synced). peer = {peer_id}");

                continue;
            }

            // Request MMR until target block reached.
            loop {
                let target_position = {
                    let best_block = if let Some(target_block) = target_block {
                        target_block
                    } else {
                        let best_block: u32 = peer_info.best_number.try_into().map_err(|_| {
                            sp_blockchain::Error::Application(
                                "Can't convert best block from peer info.".into(),
                            )
                        })?;

                        best_block
                    };

                    let nodes = NodesUtils::new(best_block.into());

                    let target_position = nodes.size().saturating_sub(1);

                    debug!(
                        "MMR-sync. Best block={}, Node target position={}",
                        best_block, target_position
                    );

                    target_position
                };

                let request = MmrRequest {
                    starting_position,
                    limit: MAX_MMR_ITEMS,
                };
                let response =
                    send_mmr_request(protocol_name.clone(), *peer_id, request, &network_service)
                        .await;

                match response {
                    Ok(response) => {
                        trace!("Response: {:?}", response.mmr_data.len());

                        if response.mmr_data.is_empty() {
                            debug!("Empty response from peer={}", peer_id);
                            break;
                        }

                        // Save the MMR-nodes from response to the local storage
                        'data: for (position, data) in response.mmr_data.iter() {
                            // Ensure continuous sync
                            if *position == starting_position {
                                let canon_key = get_offchain_key((*position).into());
                                offchain_db.local_storage_set(
                                    StorageKind::PERSISTENT,
                                    &canon_key,
                                    data,
                                );

                                starting_position += 1;
                            } else {
                                debug!("MMR-sync gap detected={peer_id}, position={position}",);
                                break 'data; // We don't support gaps in MMR data
                            }
                        }
                    }
                    Err(error) => {
                        debug!("MMR sync request failed. peer = {peer_id}: {error}");

                        continue 'peers;
                    }
                }

                // Actual MMR-nodes may exceed this number, however, we will catch up with the rest
                // when we sync the remaining data (consensus and domain chains).
                if target_position <= starting_position.into() {
                    debug!("Target position reached: {target_position}");
                    break 'outer;
                }
            }
        }
        debug!(%starting_position, "No synced peers to handle the MMR-sync. Pausing...",);
        sleep(SYNC_PAUSE).await;
    }

    debug!("MMR sync finished.");

    Ok(())
}

/// MMR-sync error
#[derive(Debug, thiserror::Error)]
pub enum MmrResponseError {
    #[error("MMR request failed: {0}")]
    RequestFailed(#[from] RequestFailure),

    #[error("MMR request canceled")]
    RequestCanceled,

    #[error("MMR request failed: invalid protocol")]
    InvalidProtocol,

    #[error("Failed to decode response: {0}")]
    DecodeFailed(String),
}

async fn send_mmr_request<NR: NetworkRequest>(
    protocol_name: String,
    peer_id: PeerId,
    request: MmrRequest,
    network_service: &NR,
) -> Result<MmrResponse, MmrResponseError> {
    let (tx, rx) = oneshot::channel();

    debug!("Sending request: {request:?}  (peer={peer_id})");

    let encoded_request = request.encode();

    network_service.start_request(
        peer_id,
        protocol_name.clone().into(),
        encoded_request,
        None,
        tx,
        IfDisconnected::ImmediateError,
    );

    let result = rx.await.map_err(|_| MmrResponseError::RequestCanceled)?;

    match result {
        Ok((data, response_protocol_name)) => {
            if response_protocol_name != protocol_name.into() {
                return Err(MmrResponseError::InvalidProtocol);
            }

            let response = decode_mmr_response(&data).map_err(MmrResponseError::DecodeFailed)?;

            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}

fn decode_mmr_response(mut response: &[u8]) -> Result<MmrResponse, String> {
    let response = MmrResponse::decode(&mut response)
        .map_err(|error| format!("Failed to decode state response: {error}"))?;

    Ok(response)
}
