// Remove after adding domain snap-sync
#![allow(dead_code)]
pub mod snap_sync_orchestrator;

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
use sp_domains::{DomainId, ExecutionReceiptFor};
use sp_runtime::traits::{Block as BlockT, Header};
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
        let info = self.client.info();
        let protocol_name = generate_protocol_name(info.genesis_hash, self.fork_id.as_deref());

        debug!(domain_id=%self.domain_id, %protocol_name, "Started obtaining domain info...");

        loop {
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

                if !peer_info.is_synced {
                    trace!("Domain data request skipped (not synced). peer = {peer_id}");

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
                        trace!("Response from a peer {peer_id},",);

                        return Some(response.last_confirmed_block_receipt);
                    }
                    Err(error) => {
                        debug!("Domain info request failed. peer = {peer_id}: {error}");

                        continue 'peers;
                    }
                }
            }
            debug!(
                domain_id=%self.domain_id,
                "No synced peers to handle the domain confirmed block infor request. Pausing..."
            );

            sleep(REQUEST_PAUSE).await;
        }
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
