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

use domain_client_operator::load_execution_receipt_by_domain_hash;
use domain_runtime_primitives::Balance;
use futures::channel::oneshot;
use futures::stream::StreamExt;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, BlockBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse};
use sc_network::{NetworkBackend, PeerId};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainsApi, ExecutionReceiptFor};
use sp_runtime::codec;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace};

const EXECUTION_RECEIPT_LIMIT: usize = 10;

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
pub struct LastConfirmedBlockRequest {
    pub domain_id: DomainId,
}

#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub struct LastConfirmedBlockResponse<Block: BlockT, DomainHeader: Header> {
    pub last_confirmed_block_receipts: Vec<ExecutionReceiptFor<DomainHeader, Block, Balance>>,
}

/// Handler for incoming block requests from a remote peer.
pub struct LastDomainBlockERRequestHandler<CBlock, Block, Client, CClient, DomainHeader>
where
    CBlock: BlockT,
    Block: BlockT,
{
    request_receiver: async_channel::Receiver<IncomingRequest>,

    _phantom: PhantomData<(CBlock, Block, DomainHeader)>,

    consensus_client: Arc<CClient>,
    domain_client: Arc<Client>,
}

impl<CBlock, Block, Client, CClient, DomainHeader>
    LastDomainBlockERRequestHandler<CBlock, Block, Client, CClient, DomainHeader>
where
    CBlock: BlockT,
    Block: BlockT<Header = DomainHeader>,
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    CClient: ProvideRuntimeApi<CBlock>
        + BlockBackend<CBlock>
        + HeaderBackend<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, DomainHeader>,
    DomainHeader: Header,
{
    /// Create a new [`LastDomainBlockERRequestHandler`].
    pub fn new<NB>(
        fork_id: Option<&str>,
        consensus_client: Arc<CClient>,
        domain_client: Arc<Client>,
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
                domain_client,
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
        let request = LastConfirmedBlockRequest::decode(&mut payload.as_slice())?;

        trace!("Handle last confirmed domain block info request: {peer}, request: {request:?}",);

        let result = {
            let receipts = self.get_execution_receipts(request.domain_id)?;

            let response = LastConfirmedBlockResponse::<CBlock, DomainHeader> {
                last_confirmed_block_receipts: receipts,
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

    fn get_execution_receipts(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<ExecutionReceiptFor<DomainHeader, CBlock, Balance>>, HandleRequestError> {
        let target_block_hash = self.consensus_client.info().best_hash;

        // Get the last confirmed block receipt
        let last_confirmed_block_receipt = self
            .consensus_client
            .runtime_api()
            .last_confirmed_domain_block_receipt(target_block_hash, domain_id);

        debug!(
            ?last_confirmed_block_receipt,
            "Last confirmed domain block receipt."
        );

        let last_confirmed_block_receipt = match last_confirmed_block_receipt {
            Ok(Some(last_confirmed_block_receipt)) => last_confirmed_block_receipt,
            Ok(None) => {
                debug!(
                    %domain_id,
                    %target_block_hash,
                    "Last confirmed domain block acquisition failed: no data.",
                );

                return Err(HandleRequestError::AbsentLastConfirmedDomainBlockData);
            }
            Err(err) => {
                debug!(
                    %domain_id,
                    %target_block_hash,
                    ?err,
                    "Last confirmed domain block acquisition failed.",
                );

                return Err(HandleRequestError::LastConfirmedDomainDataAcquisitionFailed(err));
            }
        };

        let mut previous_domain_block_number =
            Self::convert_block_number(last_confirmed_block_receipt.domain_block_number);
        let mut receipts = vec![last_confirmed_block_receipt];

        // Get previous execution receipts
        for iteration in 0..EXECUTION_RECEIPT_LIMIT {
            if previous_domain_block_number == 0u32 {
                debug!(
                    %iteration,
                    "Execution receipts handling: genesis block reached."
                );
                break;
            }

            let current_block_number = previous_domain_block_number - 1u32;

            let current_block_hash = match self.domain_client.hash(current_block_number.into()) {
                Ok(Some(hash)) => hash,
                Ok(None) => {
                    debug!(
                        %iteration,
                        %current_block_number,
                        "Execution receipts handling: can't get hash."
                    );
                    break;
                }
                Err(err) => {
                    debug!(
                        %iteration,
                        %current_block_number,
                        %err,
                        "Execution receipts handling: can't get hash."
                    );
                    break;
                }
            };

            let receipt = match load_execution_receipt_by_domain_hash::<Block, CBlock, Client>(
                self.domain_client.as_ref(),
                current_block_hash,
                current_block_number.into(),
            ) {
                Ok(receipt) => receipt,
                Err(err) => {
                    debug!(
                        %iteration,
                        %current_block_number,
                        ?current_block_hash,
                        %err,
                        "Execution receipts handling: can't load receipt."
                    );
                    break;
                }
            };

            receipts.push(receipt);

            previous_domain_block_number = current_block_number;

            trace!(%iteration, %current_block_number, "Execution receipt added.");
        }

        debug!(count=%receipts.len(), "Execution receipts added.");

        Ok(receipts)
    }

    fn convert_block_number(block_number: NumberFor<Block>) -> u32 {
        let block_number: u32 = match block_number.try_into() {
            Ok(block_number) => block_number,
            Err(_) => {
                panic!("Can't convert block number.")
            }
        };

        block_number
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
