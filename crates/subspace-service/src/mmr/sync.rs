use crate::mmr::get_offchain_key;
use crate::mmr::request_handler::{generate_protocol_name, MmrRequest, MmrResponse, MAX_MMR_ITEMS};
use crate::sync_from_dsn::LOG_TARGET;
use futures::channel::oneshot;
use parity_scale_codec::{Decode, Encode};
use sc_network::{IfDisconnected, NetworkRequest, PeerId, RequestFailure};
use sc_network_sync::SyncingService;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::{DbExternalities, OffchainStorage, StorageKind};
use sp_core::{Hasher, H256};
use sp_mmr_primitives::mmr_lib::{MMRStoreReadOps, MMRStoreWriteOps};
use sp_mmr_primitives::utils::NodesUtils;
use sp_mmr_primitives::{mmr_lib, DataOrHash, MmrApi};
use sp_runtime::traits::{Block as BlockT, Keccak256, NumberFor};
use sp_subspace_mmr::MmrLeaf;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{BlockHash, BlockNumber};
use tokio::time::sleep;
use tracing::{debug, error, trace};

type Node<H, L> = DataOrHash<H, L>;
type MmrLeafOf = MmrLeaf<BlockNumber, BlockHash>;
type NodeOf = Node<Keccak256, MmrLeafOf>;
type MmrOf<OS> = mmr_lib::MMR<NodeOf, MmrHasher, OffchainMmrStorage<OS>>;

pub(crate) fn decode_mmr_data(mut data: &[u8]) -> mmr_lib::Result<NodeOf> {
    let node = match NodeOf::decode(&mut data) {
        Ok(node) => node,
        Err(err) => {
            error!(target: LOG_TARGET, ?err, "Can't decode MMR data");

            return Err(mmr_lib::Error::StoreError(
                "Can't decode MMR data".to_string(),
            ));
        }
    };

    Ok(node)
}

struct OffchainMmrStorage<OS: OffchainStorage> {
    offchain_db: RefCell<OffchainDb<OS>>,
}

impl<OS: OffchainStorage> OffchainMmrStorage<OS> {
    fn new(offchain_storage: OS) -> Self {
        let offchain_db = OffchainDb::new(offchain_storage);

        Self {
            offchain_db: RefCell::new(offchain_db),
        }
    }
}

impl<OS: OffchainStorage> MMRStoreReadOps<NodeOf> for OffchainMmrStorage<OS> {
    fn get_elem(&self, pos: u64) -> mmr_lib::Result<Option<NodeOf>> {
        let canon_key = get_offchain_key(pos);
        let Some(data) = self
            .offchain_db
            .borrow_mut()
            .local_storage_get(StorageKind::PERSISTENT, &canon_key)
        else {
            error!(target: LOG_TARGET, %pos, "Can't get MMR data.");

            return Ok(None);
        };

        let node = decode_mmr_data(data.as_slice());

        node.map(Some)
    }
}

impl<OS: OffchainStorage> MMRStoreWriteOps<NodeOf> for OffchainMmrStorage<OS> {
    fn append(&mut self, pos: u64, elems: Vec<NodeOf>) -> mmr_lib::Result<()> {
        let mut current_pos = pos;
        for elem in elems {
            let data = elem.encode();

            let canon_key = get_offchain_key(current_pos);
            self.offchain_db.borrow_mut().local_storage_set(
                StorageKind::PERSISTENT,
                &canon_key,
                &data,
            );

            current_pos += 1;
        }

        Ok(())
    }
}

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

/// Synchronize and verification MMR-leafs from remote offchain storage of the synced peer.
pub(crate) struct MmrSync<Client, Block, OS: OffchainStorage> {
    client: Arc<Client>,
    mmr: MmrOf<OS>,
    leaves_number: u32,
    _data: PhantomData<Block>,
}

impl<Client, Block, OS> MmrSync<Client, Block, OS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
    OS: OffchainStorage,
{
    pub fn new(client: Arc<Client>, offchain_storage: OS) -> Self {
        Self {
            client,
            mmr: MmrOf::new(0, OffchainMmrStorage::new(offchain_storage)),
            leaves_number: 0,
            _data: Default::default(),
        }
    }

    // TODO: Add support for MMR-sync reruns from non-zero starting point.
    /// Synchronize MMR-leafs from remote offchain storage of the synced peer.
    pub(crate) async fn sync<NR>(
        &mut self,
        fork_id: Option<String>,
        network_service: NR,
        sync_service: Arc<SyncingService<Block>>,
        target_block: BlockNumber,
    ) -> Result<(), sp_blockchain::Error>
    where
        NR: NetworkRequest,
    {
        debug!(target: LOG_TARGET, "MMR sync started.");
        let info = self.client.info();
        let protocol_name = generate_protocol_name(info.genesis_hash, fork_id.as_deref());

        let mut leaves_number = 0u32;
        let mut starting_position = 0;

        'outer: loop {
            let peers_info = match sync_service.peers_info().await {
                Ok(peers_info) => peers_info,
                Err(error) => {
                    error!(target: LOG_TARGET, "Peers info request returned an error: {error}",);
                    sleep(SYNC_PAUSE).await;
                    continue;
                }
            };

            //  Enumerate peers until we find a suitable source for MMR
            'peers: for (peer_id, peer_info) in peers_info.iter() {
                trace!(target: LOG_TARGET, "MMR sync. peer = {peer_id}, info = {:?}", peer_info);

                if !peer_info.is_synced {
                    trace!(target: LOG_TARGET, "MMR sync skipped (not synced). peer = {peer_id}");

                    continue;
                }

                // Request MMR until target block reached.
                loop {
                    let target_position = {
                        let nodes = NodesUtils::new(target_block.into());

                        let target_position = nodes.size().saturating_sub(1);

                        debug!(
                            target: LOG_TARGET,
                            "MMR-sync. Target block={}, Node target position={}",
                            target_block, target_position
                        );

                        target_position
                    };

                    let request = MmrRequest {
                        starting_position,
                        limit: MAX_MMR_ITEMS,
                    };
                    let response = send_mmr_request(
                        protocol_name.clone(),
                        *peer_id,
                        request,
                        &network_service,
                    )
                    .await;

                    match response {
                        Ok(response) => {
                            trace!(target: LOG_TARGET, "Response: {:?}", response.mmr_data.len());

                            if response.mmr_data.is_empty() {
                                debug!(target: LOG_TARGET, "Empty response from peer={}", peer_id);
                                break;
                            }

                            // Save the MMR-nodes from response to the local storage
                            'data: for (position, data) in response.mmr_data.iter() {
                                // Ensure continuous sync
                                if *position != starting_position {
                                    debug!(
                                        target: LOG_TARGET,
                                        ?peer_info,
                                        %starting_position,
                                        %position,
                                        "MMR sync error: incorrect starting position."
                                    );

                                    continue 'peers;
                                }

                                let node = decode_mmr_data(data);

                                let node = match node {
                                    Ok(node) => node,
                                    Err(err) => {
                                        debug!(target: LOG_TARGET, ?peer_info, ?err, %position, "Can't decode MMR data received from the peer.");

                                        continue 'peers;
                                    }
                                };

                                if matches!(node, Node::Data(_)) {
                                    if let Err(err) = self.mmr.push(node) {
                                        debug!(target: LOG_TARGET, ?peer_info, ?err, %position, "Can't add MMR data received from the peer.");

                                        return Err(sp_blockchain::Error::Backend(
                                            "Can't add MMR data to the MMR storage".to_string(),
                                        ));
                                    }

                                    leaves_number += 1;
                                }

                                starting_position += 1;

                                // Did we collect all the necessary data from the last response?
                                if u64::from(*position) >= target_position {
                                    debug!(target: LOG_TARGET, %target_position, "MMR-sync: target position reached.");
                                    break 'data;
                                }
                            }
                        }
                        Err(error) => {
                            debug!(target: LOG_TARGET, "MMR sync request failed. peer = {peer_id}: {error}");

                            continue 'peers;
                        }
                    }

                    // Should we request a new portion of the data from the last peer?
                    if target_position <= starting_position.into() {
                        if let Err(err) = self.mmr.commit() {
                            error!(target: LOG_TARGET, ?err, "MMR commit failed.");

                            return Err(sp_blockchain::Error::Application(
                                "Failed to commit MMR data.".into(),
                            ));
                        }

                        // Actual MMR-nodes may exceed this number, however, we will catch up with the rest
                        // when we sync the remaining data (consensus and domain chains).
                        debug!(target: LOG_TARGET, "Target position reached: {target_position}");

                        break 'outer;
                    }
                }
            }
            debug!(target: LOG_TARGET, %starting_position, "No synced peers to handle the MMR-sync. Pausing...",);
            sleep(SYNC_PAUSE).await;
        }

        debug!(target: LOG_TARGET, "MMR sync finished.");
        self.leaves_number = leaves_number;
        Ok(())
    }

    pub(crate) fn verify_mmr_data(&self) -> Result<(), sp_blockchain::Error> {
        debug!(target: LOG_TARGET, "Verifying MMR data...");

        let block_number = self.leaves_number;
        let Some(hash) = self.client.hash(block_number.into())? else {
            error!(target: LOG_TARGET, %block_number, "MMR data verification: error during hash acquisition");
            return Err(sp_blockchain::Error::UnknownBlock(
                "Failed to get Block hash for Number: {block_number:?}".to_string(),
            ));
        };

        let mmr_root = self.mmr.get_root();
        trace!(target: LOG_TARGET, "MMR root: {:?}", mmr_root);
        let api_root = self.client.runtime_api().mmr_root(hash);
        trace!(target: LOG_TARGET, "API root: {:?}", api_root);

        let Ok(Node::Hash(mmr_root_hash)) = mmr_root.clone() else {
            error!(target: LOG_TARGET, %block_number, ?mmr_root, "Can't get MMR root from local storage.");
            return Err(sp_blockchain::Error::Application(
                "Can't get MMR root from local storage".into(),
            ));
        };

        let Ok(Ok(api_root_hash)) = api_root else {
            error!(target: LOG_TARGET, %block_number, ?mmr_root, "Can't get MMR root from API.");
            return Err(sp_blockchain::Error::Application(
                "Can't get MMR root from API.".into(),
            ));
        };

        if api_root_hash != mmr_root_hash {
            error!(target: LOG_TARGET, ?api_root_hash, ?mmr_root_hash, "MMR data hashes differ.");
            return Err(sp_blockchain::Error::Application(
                "MMR data hashes differ.".into(),
            ));
        }

        debug!(target: LOG_TARGET, "MMR data verified");

        Ok(())
    }
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

    debug!(target: LOG_TARGET, "Sending request: {request:?}  (peer={peer_id})");

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
