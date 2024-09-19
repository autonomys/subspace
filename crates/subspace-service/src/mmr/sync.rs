#![allow(dead_code)] // TODO: enable after the domain-sync implementation

use crate::mmr::get_offchain_key;
use crate::mmr::request_handler::{generate_protocol_name, MmrRequest, MmrResponse, MAX_MMR_ITEMS};
use futures::channel::oneshot;
use mmr_lib::util::MemStore;
use parity_scale_codec::{Decode, Encode};
use sc_network::{IfDisconnected, NetworkRequest, PeerId, RequestFailure};
use sc_network_sync::SyncingService;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::{DbExternalities, OffchainStorage, StorageKind};
use sp_core::{Hasher, H256};
use sp_mmr_primitives::utils::NodesUtils;
use sp_mmr_primitives::{mmr_lib, DataOrHash, MmrApi};
use sp_runtime::traits::{Block as BlockT, Keccak256, NumberFor};
use sp_subspace_mmr::MmrLeaf;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{BlockHash, BlockNumber};
use tokio::time::sleep;
use tracing::{debug, error, trace};

type Node<H, L> = DataOrHash<H, L>;
type MmrLeafOf = MmrLeaf<BlockNumber, BlockHash>;
type NodeOf = Node<Keccak256, MmrLeafOf>;
type MemStoreOf = MemStore<NodeOf>;
type MmrRef<'a> = mmr_lib::MMR<NodeOf, MmrHasher, &'a MemStoreOf>;

/// Default Merging & Hashing behavior for MMR.
pub struct MmrHasher;

impl mmr_lib::Merge for MmrHasher {
    type Item = NodeOf;

    fn merge(left: &Self::Item, right: &Self::Item) -> mmr_lib::Result<Self::Item> {
        let mut concat = left.hash().as_ref().to_vec();
        concat.extend_from_slice(right.hash().as_ref());

        Ok(Node::Hash(Keccak256::hash(&concat)))
    }
}

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
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
    OS: OffchainStorage,
{
    debug!("MMR sync started.");
    let info = client.info();
    let protocol_name = generate_protocol_name(info.genesis_hash, fork_id.as_deref());

    let mut offchain_db = OffchainDb::new(offchain_storage.clone());

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

                    if !verify_mmr_data(client, offchain_storage, target_position) {
                        return Err(sp_blockchain::Error::Application(
                            "Can't get starting MMR position - data verification failed.".into(),
                        ));
                    }

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

pub(crate) fn verify_mmr_data<Block, OS, Client>(
    client: Arc<Client>,
    offchain_storage: OS,
    target_position: u64,
) -> bool
where
    Block: BlockT,
    OS: OffchainStorage,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
{
    let store = MemStoreOf::default();
    let mut mmr = MmrRef::new(0, &store);
    let mut leaves_num = 0u32;

    debug!("Verifying MMR data...");

    let mut offchain_db = OffchainDb::new(offchain_storage);

    for position in 0..=target_position {
        let canon_key = get_offchain_key(position);
        let Some(data) = offchain_db.local_storage_get(StorageKind::PERSISTENT, &canon_key) else {
            error!(%target_position, %position, "Can't get MMR data.");

            return false;
        };

        let node = match NodeOf::decode(&mut data.as_slice()) {
            Ok(node) => node,
            Err(err) => {
                error!(%position, ?err, "MMR data verification: error during leaf acquiring");
                return false;
            }
        };

        if matches!(node, NodeOf::Data(_),) {
            if let Err(err) = mmr.push(node) {
                error!(%position, ?err, "MMR data verification: error during adding the node.");
                return false;
            }
            leaves_num += 1;
        }
    }

    let block_number = leaves_num;
    let Ok(Some(hash)) = client.hash(block_number.into()) else {
        error!(%target_position, %block_number, "MMR data verification: error during hash acquisition");
        return false;
    };

    let mmr_root = mmr.get_root();
    trace!("MMR root: {:?}", mmr_root);
    let api_root = client.runtime_api().mmr_root(hash);
    trace!("API root: {:?}", api_root);

    let Ok(Node::Hash(mmr_root_hash)) = mmr_root.clone() else {
        error!(%target_position, %block_number, ?mmr_root, "Can't get MMR root from local storage.");
        return false;
    };

    let Ok(Ok(api_root_hash)) = api_root else {
        error!(%target_position, %block_number, ?mmr_root, "Can't get MMR root from API.");
        return false;
    };

    if api_root_hash != mmr_root_hash {
        error!(?api_root_hash, ?mmr_root_hash, "MMR data hashes differ.");
        return false;
    }

    debug!("MMR data verified");

    true
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
