// Remove after adding domain snap-sync
#![allow(dead_code)]

use crate::domains::request_handler::{
    generate_protocol_name, LastConfirmedBlockRequest, LastConfirmedBlockResponse,
};
use async_trait::async_trait;
use domain_runtime_primitives::Balance;
use futures::channel::oneshot;
use parity_scale_codec::{Decode, Encode};
use sc_network::{IfDisconnected, NetworkRequest, PeerId, RequestFailure};
use sc_network_sync::SyncingService;
use sp_blockchain::HeaderBackend;
use sp_core::{Hasher, KeccakHasher};
use sp_domains::{DomainId, ExecutionReceiptFor};
use sp_runtime::traits::{Block as BlockT, Header};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, trace};

pub(crate) mod request_handler;

const REQUEST_PAUSE: Duration = Duration::from_secs(5);

/// Last confirmed domain block info error
#[derive(Debug, thiserror::Error)]
pub enum LastConfirmedDomainBlockResponseError {
    #[error("Last confirmed domain block info request failed: {0}")]
    RequestFailed(#[from] RequestFailure),

    #[error("Last confirmed domain block info request canceled")]
    RequestCanceled,

    #[error("Last confirmed domain block info request failed: invalid protocol")]
    InvalidProtocol,

    #[error("Failed to decode response: {0}")]
    DecodeFailed(String),
}

#[async_trait]
pub trait LastDomainBlockReceiptProvider<Block: BlockT, CBlock: BlockT>: Send {
    async fn get_execution_receipt(
        &self,
        block_hash: Option<CBlock::Hash>,
    ) -> Option<ExecutionReceiptFor<Block::Header, CBlock, Balance>>;
}

#[async_trait]
impl<Block: BlockT, CBlock: BlockT> LastDomainBlockReceiptProvider<Block, CBlock> for () {
    async fn get_execution_receipt(
        &self,
        _: Option<CBlock::Hash>,
    ) -> Option<ExecutionReceiptFor<Block::Header, CBlock, Balance>> {
        None
    }
}

#[async_trait]
impl<Block, CBlock, Client, NR> LastDomainBlockReceiptProvider<Block, CBlock>
    for LastDomainBlockInfoReceiver<Block, Client, NR>
where
    Block: BlockT,
    CBlock: BlockT,
    NR: NetworkRequest + Sync + Send,
    Client: HeaderBackend<Block>,
{
    async fn get_execution_receipt(
        &self,
        block_hash: Option<CBlock::Hash>,
    ) -> Option<ExecutionReceiptFor<Block::Header, CBlock, Balance>> {
        self.get_last_confirmed_domain_block_receipt::<CBlock>(block_hash)
            .await
    }
}

pub struct LastDomainBlockInfoReceiver<Block, Client, NR>
where
    Block: BlockT,
    NR: NetworkRequest,
    Client: HeaderBackend<Block>,
{
    domain_id: DomainId,
    fork_id: Option<String>,
    client: Arc<Client>,
    network_service: NR,
    sync_service: Arc<SyncingService<Block>>,
}

impl<Block, Client, NR> LastDomainBlockInfoReceiver<Block, Client, NR>
where
    Block: BlockT,
    NR: NetworkRequest,
    Client: HeaderBackend<Block>,
{
    pub fn new(
        domain_id: DomainId,
        fork_id: Option<String>,
        client: Arc<Client>,
        network_service: NR,
        sync_service: Arc<SyncingService<Block>>,
    ) -> Self {
        Self {
            domain_id,
            fork_id,
            client,
            network_service,
            sync_service,
        }
    }
    pub async fn get_last_confirmed_domain_block_receipt<CBlock: BlockT>(
        &self,
        block_hash: Option<CBlock::Hash>,
    ) -> Option<ExecutionReceiptFor<Block::Header, CBlock, Balance>> {
        const ATTEMPTS_NUMBER: u32 = 5;
        const PEERS_THRESHOLD: usize = 5;

        let info = self.client.info();
        let protocol_name = generate_protocol_name(info.genesis_hash, self.fork_id.as_deref());

        debug!(domain_id=%self.domain_id, %protocol_name, "Started obtaining domain info...");

        let mut receipts = BTreeMap::new();
        let mut receipts_hashes = BTreeMap::new();
        let mut peers_hashes = BTreeMap::new();

        for attempt in 0..ATTEMPTS_NUMBER {
            let peers_info = match self.sync_service.peers_info().await {
                Ok(peers_info) => peers_info,
                Err(error) => {
                    error!("Peers info request returned an error: {error}",);
                    sleep(REQUEST_PAUSE).await;

                    continue;
                }
            };

            //  Enumerate peers until we find a suitable source for domain info
            'peers: for (peer_id, peer_info) in peers_info.iter() {
                debug!(
                    "Domain data request. peer = {peer_id}, info = {:?}",
                    peer_info
                );

                if peers_hashes.contains_key(peer_id) {
                    trace!(%attempt, %peer_id, "Peer receipt has been already collected.");

                    continue 'peers;
                }

                if !peer_info.is_synced {
                    trace!(%attempt, %peer_id, "Domain data request skipped (not synced).");

                    continue 'peers;
                }

                let request = LastConfirmedBlockRequest::<CBlock> {
                    domain_id: self.domain_id,
                    block_hash,
                };

                let response = send_request::<NR, CBlock, Block::Header>(
                    protocol_name.clone(),
                    *peer_id,
                    request,
                    &self.network_service,
                )
                .await;

                match response {
                    Ok(response) => {
                        trace!(%attempt, "Response from a peer {peer_id},",);

                        let receipt = response.last_confirmed_block_receipt;
                        let receipt_hash = KeccakHasher::hash(&receipt.encode());

                        peers_hashes.insert(*peer_id, receipt_hash);
                        receipts.insert(receipt_hash, receipt);
                        receipts_hashes
                            .entry(receipt_hash)
                            .and_modify(|count: &mut u32| *count += 1)
                            .or_insert(1u32);
                    }
                    Err(error) => {
                        debug!(%attempt, "Domain info request failed. peer = {peer_id}: {error}");

                        continue 'peers;
                    }
                }
            }
            debug!(
                domain_id=%self.domain_id,
                "No synced peers to handle the domain confirmed block info request. Pausing..."
            );

            if peers_hashes.len() >= PEERS_THRESHOLD {
                break;
            }

            sleep(REQUEST_PAUSE).await;
        }

        if peers_hashes.len() < PEERS_THRESHOLD {
            debug!(peers=%peers_hashes.len(), "Couldn't pass peer threshold for receipts.");
        }

        // Find the receipt with the maximum votes
        if let Some(max_receipt_vote) = receipts_hashes.values().max() {
            if let Some((receipt_hash, _)) = receipts_hashes
                .iter()
                .find(|(_, vote)| max_receipt_vote == *vote)
            {
                return receipts.get(receipt_hash).cloned();
            }
        } else {
            debug!("Couldn't find last confirmed domain block execution receipt: no receipts.");
        }

        error!("Couldn't find last confirmed domain block execution receipt.");
        None
    }
}

async fn send_request<NR: NetworkRequest, Block: BlockT, DomainHeader: Header>(
    protocol_name: String,
    peer_id: PeerId,
    request: LastConfirmedBlockRequest<Block>,
    network_service: &NR,
) -> Result<LastConfirmedBlockResponse<Block, DomainHeader>, LastConfirmedDomainBlockResponseError>
{
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

    let result = rx
        .await
        .map_err(|_| LastConfirmedDomainBlockResponseError::RequestCanceled)?;

    match result {
        Ok((data, response_protocol_name)) => {
            if response_protocol_name != protocol_name.into() {
                return Err(LastConfirmedDomainBlockResponseError::InvalidProtocol);
            }

            let response = decode_response(&data)
                .map_err(LastConfirmedDomainBlockResponseError::DecodeFailed)?;

            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}

fn decode_response<Block: BlockT, DomainHeader: Header>(
    mut response: &[u8],
) -> Result<LastConfirmedBlockResponse<Block, DomainHeader>, String> {
    let response = LastConfirmedBlockResponse::decode(&mut response).map_err(|error| {
        format!("Failed to decode last confirmed domain block info response: {error}")
    })?;

    Ok(response)
}
