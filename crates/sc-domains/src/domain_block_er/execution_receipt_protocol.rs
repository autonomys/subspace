// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

use domain_runtime_primitives::Balance;
use futures::channel::oneshot;
use futures::stream::StreamExt;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::BlockBackend;
use sc_network::request_responses::{IncomingRequest, OutgoingResponse};
use sc_network::{NetworkBackend, PeerId};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::execution_receipt::ExecutionReceiptFor;
use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0For;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{Block as BlockT, Header};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace};

/// Generates a `RequestResponseProtocolConfig` for the Execution receipt protocol.
pub fn generate_protocol_config<Hash: AsRef<[u8]>, B: BlockT, N: NetworkBackend<B, B::Hash>>(
    genesis_hash: Hash,
    fork_id: Option<&str>,
    inbound_queue: async_channel::Sender<IncomingRequest>,
) -> N::RequestResponseProtocolConfig {
    N::request_response_config(
        generate_protocol_name(genesis_hash, fork_id).into(),
        Vec::new(),
        1024 * 1024,
        16 * 1024 * 1024,
        Duration::from_secs(40),
        Some(inbound_queue),
    )
}

/// Generate the state protocol name from the genesis hash and fork id.
pub fn generate_protocol_name<Hash: AsRef<[u8]>>(
    genesis_hash: Hash,
    fork_id: Option<&str>,
) -> String {
    let genesis_hash = genesis_hash.as_ref();
    if let Some(fork_id) = fork_id {
        format!(
            "/{}/{}/last-confirmed-domain-block-receipt/1",
            array_bytes::bytes2hex("", genesis_hash),
            fork_id
        )
    } else {
        format!(
            "/{}/last-confirmed-domain-block-receipt/1",
            array_bytes::bytes2hex("", genesis_hash)
        )
    }
}

/// Domain block ER request.
#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub enum DomainBlockERRequest {
    /// Last Confirmed ER request for given Domain.
    LastConfirmedER(DomainId),
}

/// Response for Domain Block ER request.
#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub enum DomainBlockERResponse<CBlock: BlockT, DomainHeader: Header> {
    /// Response for last confirmed Domain block ER.
    LastConfirmedER(ExecutionReceiptFor<DomainHeader, CBlock, Balance>),
}

// TODO: remove once majority of the network is migrated.
/// V0 Response for Domain Block ER request.
#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub enum DomainBlockERResponseV0<CBlock: BlockT, DomainHeader: Header> {
    /// Response for last confirmed Domain block ER.
    LastConfirmedER(ExecutionReceiptV0For<DomainHeader, CBlock, Balance>),
}

impl<CBlock: BlockT, DomainHeader: Header> From<DomainBlockERResponseV0<CBlock, DomainHeader>>
    for DomainBlockERResponse<CBlock, DomainHeader>
{
    fn from(value: DomainBlockERResponseV0<CBlock, DomainHeader>) -> Self {
        let DomainBlockERResponseV0::LastConfirmedER(er) = value;
        DomainBlockERResponse::LastConfirmedER(
            ExecutionReceiptFor::<DomainHeader, CBlock, Balance>::V0(er),
        )
    }
}

/// Handler for incoming block requests from a remote peer.
pub struct DomainBlockERRequestHandler<CBlock, Block, CClient>
where
    CBlock: BlockT,
    Block: BlockT,
{
    consensus_client: Arc<CClient>,
    request_receiver: async_channel::Receiver<IncomingRequest>,
    _phantom: PhantomData<(CBlock, Block)>,
}

impl<CBlock, Block, CClient> DomainBlockERRequestHandler<CBlock, Block, CClient>
where
    CBlock: BlockT,
    Block: BlockT,
    CClient: ProvideRuntimeApi<CBlock>
        + BlockBackend<CBlock>
        + HeaderBackend<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
{
    /// Create a new [`DomainBlockERRequestHandler`].
    pub fn new<NB>(
        fork_id: Option<&str>,
        consensus_client: Arc<CClient>,
        num_peer_hint: usize,
    ) -> (Self, NB::RequestResponseProtocolConfig)
    where
        NB: NetworkBackend<Block, Block::Hash>,
    {
        // Reserve enough request slots for one request per peer when we are at the maximum
        // number of peers.
        let capacity = std::cmp::max(num_peer_hint, 1);
        let (tx, request_receiver) = async_channel::bounded(capacity);

        let protocol_config = generate_protocol_config::<_, Block, NB>(
            consensus_client
                .block_hash(0u32.into())
                .ok()
                .flatten()
                .expect("Genesis block exists; qed"),
            fork_id,
            tx,
        );

        (
            Self {
                request_receiver,
                consensus_client,
                _phantom: PhantomData,
            },
            protocol_config,
        )
    }

    /// Run [`DomainBlockERRequestHandler`].
    pub async fn run(mut self) {
        while let Some(request) = self.request_receiver.next().await {
            let IncomingRequest {
                peer,
                payload,
                pending_response,
            } = request;

            match self.handle_request(payload, pending_response, &peer) {
                Ok(()) => {
                    debug!("Handled domain block ER request from {}.", peer)
                }
                Err(e) => error!(
                    "Failed to handle domain block ER request from {}: {}",
                    peer, e,
                ),
            }
        }
    }

    fn handle_request(
        &self,
        payload: Vec<u8>,
        pending_response: oneshot::Sender<OutgoingResponse>,
        peer: &PeerId,
    ) -> Result<(), HandleRequestError> {
        let request = DomainBlockERRequest::decode(&mut payload.as_slice())?;

        trace!("Handle domain block ER request: {peer}, request: {request:?}",);

        let result = {
            let DomainBlockERRequest::LastConfirmedER(domain_id) = request;
            let response = DomainBlockERResponse::<CBlock, Block::Header>::LastConfirmedER(
                self.get_execution_receipts(domain_id)?,
            );
            Ok(response.encode())
        };

        pending_response
            .send(OutgoingResponse {
                result,
                reputation_changes: Vec::new(),
                sent_feedback: None,
            })
            .map_err(|_| HandleRequestError::SendResponse)
    }

    fn get_execution_receipts(
        &self,
        domain_id: DomainId,
    ) -> Result<ExecutionReceiptFor<Block::Header, CBlock, Balance>, HandleRequestError> {
        let best_consensus_hash = self.consensus_client.info().best_hash;

        let runtime_api = self.consensus_client.runtime_api();
        let domains_api_version = runtime_api
            .api_version::<dyn DomainsApi<CBlock, CBlock::Header>>(best_consensus_hash)?
            // It is safe to return a default version of 1, since there will always be version 1.
            .unwrap_or(1);

        // Get the last confirmed block receipt
        let last_confirmed_block_receipt = if domains_api_version >= 5 {
            self.consensus_client
                .runtime_api()
                .last_confirmed_domain_block_receipt(best_consensus_hash, domain_id)
        } else {
            #[allow(deprecated)]
            self.consensus_client
                .runtime_api()
                .last_confirmed_domain_block_receipt_before_version_5(
                    best_consensus_hash,
                    domain_id,
                )
                .map(|er| er.map(ExecutionReceiptFor::<Block::Header, CBlock, Balance>::V0))
        };

        let last_confirmed_block_receipt = match last_confirmed_block_receipt {
            Ok(Some(last_confirmed_block_receipt)) => last_confirmed_block_receipt,
            Ok(None) => {
                debug!(
                    %domain_id,
                    %best_consensus_hash,
                    "Last confirmed domain block ER acquisition failed: no data.",
                );

                return Err(HandleRequestError::AbsentLastConfirmedDomainBlockData);
            }
            Err(err) => {
                debug!(
                    %domain_id,
                    %best_consensus_hash,
                    ?err,
                    "Last confirmed domain block ER acquisition failed.",
                );

                return Err(HandleRequestError::LastConfirmedDomainDataAcquisitionFailed(err));
            }
        };

        debug!(
            ?last_confirmed_block_receipt,
            "Last confirmed domain block receipt."
        );

        Ok(last_confirmed_block_receipt)
    }
}

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    #[error(transparent)]
    Client(#[from] sp_blockchain::Error),

    #[error("Failed to send response.")]
    SendResponse,

    #[error("Failed to decode request: {0}.")]
    Decode(#[from] parity_scale_codec::Error),

    #[error("Last confirmed domain block acquisition failed: no data.")]
    AbsentLastConfirmedDomainBlockData,

    #[error("Last confirmed domain block acquisition failed: no data.")]
    LastConfirmedDomainDataAcquisitionFailed(#[from] sp_api::ApiError),
}
