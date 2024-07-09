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
) where
    Block: BlockT,
    NR: NetworkRequest,
    Client: HeaderBackend<Block>,
    OS: OffchainStorage,
{
    debug!("MMR sync started.");
    let info = client.info();
    let protocol_name = generate_protocol_name(info.genesis_hash, fork_id.as_deref());

    let mut offchain_db = OffchainDb::new(offchain_storage);

    // Look for existing local MMR-entries
    let mut starting_block = {
        let mut starting_block: Option<BlockNumber> = None;
        for block_number in 0..=BlockNumber::MAX {
            let canon_key = get_offchain_key(block_number.into());
            if offchain_db
                .local_storage_get(StorageKind::PERSISTENT, &canon_key)
                .is_none()
            {
                starting_block = Some(block_number);
                break;
            }
        }

        match starting_block {
            None => {
                error!("Can't get starting MMR block - MMR storage is corrupted.");
                return;
            }
            Some(last_processed_block) => {
                debug!("MMR-sync last processed block: {last_processed_block}");

                last_processed_block
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
                let target_block_number = {
                    let best_block = sync_service.best_seen_block().await;

                    match best_block {
                        Ok(Some(block)) => {
                            debug!("MMR-sync. Best seen block={block}");

                            block
                        }
                        Ok(None) => {
                            debug!("Can't obtain best sync block for MMR-sync.");
                            break 'peers;
                        }
                        Err(err) => {
                            error!("Can't obtain best sync block for MMR-sync. Error={err}");
                            break 'peers;
                        }
                    }
                };

                let request = MmrRequest {
                    starting_block,
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

                        // Save the MMR-items from response to the local storage
                        'data: for (block_number, data) in response.mmr_data.iter() {
                            // Ensure continuous sync
                            if *block_number == starting_block {
                                let canon_key = get_offchain_key((*block_number).into());
                                offchain_db.local_storage_set(
                                    StorageKind::PERSISTENT,
                                    &canon_key,
                                    data,
                                );

                                starting_block += 1;
                            } else {
                                debug!(
                                    "MMR-sync gap detected={peer_id}, block_number={block_number}",
                                );
                                break 'data; // We don't support gaps in MMR data
                            }
                        }
                    }
                    Err(error) => {
                        debug!("MMR sync request failed. peer = {peer_id}: {error}");

                        continue 'peers;
                    }
                }

                // Actual MMR-items may exceed this number, however, we will catch up with the rest
                // when we sync the remaining data (consensus and domain chains).
                if target_block_number <= starting_block.into() {
                    debug!("Target block number reached: {target_block_number}");
                    break 'outer;
                }
            }
        }
        debug!("No synced peers to handle the MMR-sync. Pausing...",);
        sleep(SYNC_PAUSE).await;
    }

    debug!("MMR sync finished.");
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
