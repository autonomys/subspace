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
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainsApi, ExecutionReceiptFor};
use sp_runtime::codec;
use sp_runtime::traits::{Block as BlockT, Header};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace};

/// Generates a `RequestResponseProtocolConfig` for the state request protocol, refusing incoming
/// requests.
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
            "/{}/{}/last-confirmed-block/1",
            array_bytes::bytes2hex("", genesis_hash),
            fork_id
        )
    } else {
        format!(
            "/{}/last-confirmed-block/1",
            array_bytes::bytes2hex("", genesis_hash)
        )
    }
}

/// Request last confirmed domain block data from a peer.
#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub struct LastConfirmedBlockRequest<Block: BlockT> {
    pub domain_id: DomainId,
    pub block_hash: Option<Block::Hash>,
}

#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub struct LastConfirmedBlockResponse<Block: BlockT, DomainHeader: Header> {
    pub last_confirmed_block_receipt: ExecutionReceiptFor<DomainHeader, Block, Balance>,
}

/// Handler for incoming block requests from a remote peer.
pub struct LastDomainBlockERRequestHandler<CBlock, Block, Client, DomainHeader>
where
    CBlock: BlockT,
    Block: BlockT,
{
    request_receiver: async_channel::Receiver<IncomingRequest>,

    _phantom: PhantomData<(CBlock, Block, DomainHeader)>,

    client: Arc<Client>,
}

impl<CBlock, Block, Client, DomainHeader>
    LastDomainBlockERRequestHandler<CBlock, Block, Client, DomainHeader>
where
    CBlock: BlockT,
    Block: BlockT,
    Client: ProvideRuntimeApi<CBlock>
        + BlockBackend<CBlock>
        + HeaderBackend<CBlock>
        + Send
        + Sync
        + 'static,
    Client::Api: DomainsApi<CBlock, DomainHeader>,
    DomainHeader: Header,
{
    /// Create a new [`LastDomainBlockERRequestHandler`].
    pub fn new<NB>(
        fork_id: Option<&str>,
        client: Arc<Client>,
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
            client
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
                client,
                _phantom: PhantomData,
            },
            protocol_config,
        )
    }

    /// Run [`LastDomainBlockERRequestHandler`].
    pub async fn run(mut self) {
        while let Some(request) = self.request_receiver.next().await {
            let IncomingRequest {
                peer,
                payload,
                pending_response,
            } = request;

            match self.handle_request(payload, pending_response, &peer) {
                Ok(()) => debug!("Handled domain block info request from {}.", peer),
                Err(e) => error!(
                    "Failed to handle domain block info request from {}: {}",
                    peer, e,
                ),
            }
        }
    }

    fn handle_request(
        &mut self,
        payload: Vec<u8>,
        pending_response: oneshot::Sender<OutgoingResponse>,
        peer: &PeerId,
    ) -> Result<(), HandleRequestError> {
        let request = LastConfirmedBlockRequest::<CBlock>::decode(&mut payload.as_slice())?;

        trace!("Handle last confirmed domain block info request: {peer}, request: {request:?}",);

        let result = {
            let target_block_hash = if let Some(block_hash) = request.block_hash {
                block_hash
            } else {
                let info = self.client.info();
                info.best_hash
            };

            let last_confirmed_block_receipt = self
                .client
                .runtime_api()
                .last_confirmed_domain_block_receipt(target_block_hash, request.domain_id);

            debug!(
                ?last_confirmed_block_receipt,
                "Last confirmed domain block receipt."
            );

            let response = match last_confirmed_block_receipt {
                Ok(Some(last_confirmed_block_receipt)) => {
                    LastConfirmedBlockResponse::<CBlock, DomainHeader> {
                        last_confirmed_block_receipt,
                    }
                }
                Ok(None) => {
                    debug!(
                        domain_id=%request.domain_id,
                        %target_block_hash,
                        "Last confirmed domain block acquisition failed: no data.",
                    );

                    return Err(HandleRequestError::AbsentLastConfirmedDomainBlockData);
                }
                Err(err) => {
                    debug!(
                        domain_id=%request.domain_id,
                        %target_block_hash,
                        ?err,
                        "Last confirmed domain block acquisition failed.",
                    );

                    return Err(HandleRequestError::LastConfirmedDomainDataAcquisitionFailed(err));
                }
            };

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
}

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    #[error(transparent)]
    Client(#[from] sp_blockchain::Error),

    #[error("Failed to send response.")]
    SendResponse,

    #[error("Failed to decode request: {0}.")]
    Decode(#[from] codec::Error),

    #[error("Last confirmed domain block acquisition failed: no data.")]
    AbsentLastConfirmedDomainBlockData,

    #[error("Last confirmed domain block acquisition failed: no data.")]
    LastConfirmedDomainDataAcquisitionFailed(#[from] sp_api::ApiError),
}
