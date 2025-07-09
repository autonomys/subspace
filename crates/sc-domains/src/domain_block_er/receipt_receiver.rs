//! This module provides features for domains integration: snap sync synchronization primitives,
//! custom protocols for last confirmed block execution receipts, etc...

#![warn(missing_docs)]

use crate::domain_block_er::execution_receipt_protocol::{
    DomainBlockERRequest, DomainBlockERResponse, DomainBlockERResponseV0, generate_protocol_name,
};
use domain_runtime_primitives::Balance;
use futures::channel::oneshot;
use parity_scale_codec::{Decode, Encode};
use sc_network::{IfDisconnected, NetworkRequest, PeerId, RequestFailure};
use sc_network_sync::SyncingService;
use sp_blockchain::HeaderBackend;
use sp_core::{Hasher, KeccakHasher};
use sp_domains::DomainId;
use sp_domains::execution_receipt::ExecutionReceiptFor;
use sp_runtime::traits::{Block as BlockT, Header};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, trace};

const REQUEST_PAUSE: Duration = Duration::from_secs(15);
const ATTEMPTS_NUMBER: u32 = 20;
const PEERS_THRESHOLD: usize = 20;

/// Last confirmed domain block info error.
#[derive(Debug, thiserror::Error)]
pub enum DomainBlockERResponseError {
    /// Last confirmed domain block info request failed.
    #[error("Last confirmed domain block info request failed: {0}")]
    RequestFailed(#[from] RequestFailure),

    /// Last confirmed domain block info request canceled.
    #[error("Last confirmed domain block info request canceled")]
    RequestCanceled,

    /// "Last confirmed domain block info request failed: invalid protocol.
    #[error("Last confirmed domain block info request failed: invalid protocol")]
    InvalidProtocol,

    /// Failed to decode response.
    #[error("Failed to decode response: {0}")]
    DecodeFailed(parity_scale_codec::Error),
}

/// Provides execution receipts for domain block.
pub struct DomainBlockERReceiver<Block, CBlock, CClient, NR>
where
    Block: BlockT,
    CBlock: BlockT,
    NR: NetworkRequest,
    CClient: HeaderBackend<CBlock>,
{
    domain_id: DomainId,
    fork_id: Option<String>,
    consensus_client: Arc<CClient>,
    network_service: NR,
    sync_service: Arc<SyncingService<Block>>,
    _marker: PhantomData<CBlock>,
}

impl<Block, CBlock, CClient, NR> DomainBlockERReceiver<Block, CBlock, CClient, NR>
where
    CBlock: BlockT,
    Block: BlockT,
    NR: NetworkRequest,
    CClient: HeaderBackend<CBlock>,
{
    /// Constructor.
    pub fn new(
        domain_id: DomainId,
        fork_id: Option<String>,
        client: Arc<CClient>,
        network_service: NR,
        sync_service: Arc<SyncingService<Block>>,
    ) -> Self {
        Self {
            domain_id,
            fork_id,
            consensus_client: client,
            network_service,
            sync_service,
            _marker: PhantomData,
        }
    }

    /// Returns execution receipts for the last confirmed domain block.
    pub async fn get_last_confirmed_domain_block_receipt(
        &self,
    ) -> Option<ExecutionReceiptFor<Block::Header, CBlock, Balance>> {
        let info = self.consensus_client.info();
        let protocol_name = generate_protocol_name(info.genesis_hash, self.fork_id.as_deref());
        // Used to debug failures
        let mut peers_not_synced = 0;
        let mut peer_request_errors = 0;
        let mut peer_responses = 0;

        debug!(
            domain_id=%self.domain_id,
            %protocol_name,
            "Started obtaining last confirmed domain block ER..."
        );

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
                    %peers_not_synced,
                    %peer_request_errors,
                    %peer_responses,
                    "Domain block ER request. peer = {peer_id}, info = {:?}",
                    peer_info
                );

                if peers_hashes.contains_key(peer_id) {
                    trace!( %attempt, %peer_id, "Peer receipt has been already collected.");
                    continue 'peers;
                }

                if !peer_info.is_synced {
                    peers_not_synced += 1;
                    trace!(
                        %attempt,
                        %peer_id,
                        %peers_not_synced,
                        %peer_request_errors,
                        %peer_responses,
                        "Domain data request skipped (not synced).",
                    );
                    continue 'peers;
                }

                let request = DomainBlockERRequest::LastConfirmedER(self.domain_id);
                let response = send_request::<NR, CBlock, Block::Header>(
                    protocol_name.clone(),
                    *peer_id,
                    request,
                    &self.network_service,
                )
                .await;

                match response {
                    Ok(response) => {
                        let DomainBlockERResponse::LastConfirmedER(receipt) = response;
                        peer_responses += 1;
                        trace!(
                            %attempt,
                            %peers_not_synced,
                            %peer_request_errors,
                            %peer_responses,
                            "Response from a peer {peer_id}: {receipt:?}",
                        );

                        let receipt_hash = KeccakHasher::hash(&receipt.encode());
                        peers_hashes.insert(*peer_id, receipt_hash);
                        receipts.insert(receipt_hash, receipt);
                        receipts_hashes
                            .entry(receipt_hash)
                            .and_modify(|count: &mut u32| *count += 1)
                            .or_insert(1u32);
                    }
                    Err(error) => {
                        peer_request_errors += 1;
                        debug!(
                            %attempt,
                            %peers_not_synced,
                            %peer_request_errors,
                            %peer_responses,
                            "Domain block ER request failed. peer = {peer_id}: {error}",
                        );
                        continue 'peers;
                    }
                }
            }

            if peers_hashes.len() >= PEERS_THRESHOLD {
                break;
            }

            debug!(
                domain_id=%self.domain_id,
                %peers_not_synced,
                %peer_request_errors,
                %peer_responses,
                "No synced peers to handle the domain confirmed block info request. Pausing..."
            );
            sleep(REQUEST_PAUSE).await;
        }

        if peers_hashes.len() < PEERS_THRESHOLD {
            debug!(
                peers=%peers_hashes.len(),
                %PEERS_THRESHOLD,
                %peers_not_synced,
                %peer_request_errors,
                %peer_responses,
                "Couldn't pass peer threshold for receipts, trying snap sync anyway.",
            );
        }

        // Find the receipt with the maximum votes
        if let Some((max_voted_receipt_hash, _max_receipt_votes)) = receipts_hashes
            .into_iter()
            .max_by_key(|(_receipt_hash, receipt_votes)| *receipt_votes)
        {
            // We're about to drop receipts, so removing the receipt saves a clone.
            // This is always Some, because every receipt has a hash and a vote.
            return receipts.remove(&max_voted_receipt_hash);
        }

        error!(
            %peers_not_synced,
            %peer_request_errors,
            %peer_responses,
            "Couldn't find last confirmed domain block execution receipt: no receipts.",
        );
        None
    }
}

async fn send_request<NR: NetworkRequest, Block: BlockT, DomainHeader: Header>(
    protocol_name: String,
    peer_id: PeerId,
    request: DomainBlockERRequest,
    network_service: &NR,
) -> Result<DomainBlockERResponse<Block, DomainHeader>, DomainBlockERResponseError> {
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
        .map_err(|_| DomainBlockERResponseError::RequestCanceled)?;

    match result {
        Ok((data, response_protocol_name)) => {
            if response_protocol_name != protocol_name.into() {
                return Err(DomainBlockERResponseError::InvalidProtocol);
            }

            let response = match DomainBlockERResponse::decode(&mut data.as_slice()) {
                Ok(response) => Ok(response),
                Err(_) => DomainBlockERResponseV0::decode(&mut data.as_slice()).map(Into::into),
            }
            .map_err(DomainBlockERResponseError::DecodeFailed)?;

            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}
