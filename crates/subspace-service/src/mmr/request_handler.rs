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

use crate::mmr::get_offchain_key;
use futures::channel::oneshot;
use futures::stream::StreamExt;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{BlockBackend, ProofProvider};
use sc_network::config::ProtocolId;
use sc_network::request_responses::{IncomingRequest, OutgoingResponse};
use sc_network::{NetworkBackend, PeerId};
use schnellru::{ByLength, LruMap};
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::{DbExternalities, OffchainStorage, StorageKind};
use sp_runtime::codec;
use sp_runtime::traits::Block as BlockT;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace};

const MAX_NUMBER_OF_SAME_REQUESTS_PER_PEER: usize = 2;

/// Defines max items per request
pub const MAX_MMR_ITEMS: u32 = 20000;

mod rep {
    use sc_network::ReputationChange as Rep;

    /// Reputation change when a peer sent us the same request multiple times.
    pub const SAME_REQUEST: Rep = Rep::new(i32::MIN, "Same state request multiple times");
}

/// Generates a `RequestResponseProtocolConfig` for the state request protocol, refusing incoming
/// requests.
pub fn generate_protocol_config<Hash: AsRef<[u8]>, B: BlockT, N: NetworkBackend<B, B::Hash>>(
    _: &ProtocolId,
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
            "/{}/{}/mmr/1",
            array_bytes::bytes2hex("", genesis_hash),
            fork_id
        )
    } else {
        format!("/{}/mmr/1", array_bytes::bytes2hex("", genesis_hash))
    }
}

/// The key of [`BlockRequestHandler::seen_requests`].
#[derive(Eq, PartialEq, Clone, Hash)]
struct SeenRequestsKey {
    peer: PeerId,
    starting_position: u32,
}

/// Request MMR data from a peer.
#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub struct MmrRequest {
    /// Starting position for MMR node.
    pub starting_position: u32,
    /// Max returned nodes.
    pub limit: u32,
}

#[derive(Clone, PartialEq, Encode, Decode, Debug)]
pub struct MmrResponse {
    /// MMR-nodes related to node position
    pub mmr_data: BTreeMap<u32, Vec<u8>>,
}

/// The value of [`StateRequestHandler::seen_requests`].
enum SeenRequestsValue {
    /// First time we have seen the request.
    First,
    /// We have fulfilled the request `n` times.
    Fulfilled(usize),
}

/// Handler for incoming block requests from a remote peer.
pub struct MmrRequestHandler<Block: BlockT, OS> {
    request_receiver: async_channel::Receiver<IncomingRequest>,
    /// Maps from request to number of times we have seen this request.
    ///
    /// This is used to check if a peer is spamming us with the same request.
    seen_requests: LruMap<SeenRequestsKey, SeenRequestsValue>,

    offchain_db: OffchainDb<OS>,

    _phantom: PhantomData<Block>,
}

impl<Block, OS> MmrRequestHandler<Block, OS>
where
    Block: BlockT,

    OS: OffchainStorage,
{
    /// Create a new [`MmrRequestHandler`].
    pub fn new<NB, Client>(
        protocol_id: &ProtocolId,
        fork_id: Option<&str>,
        client: Arc<Client>,
        num_peer_hint: usize,
        offchain_storage: OS,
    ) -> (Self, NB::RequestResponseProtocolConfig)
    where
        NB: NetworkBackend<Block, Block::Hash>,
        Client: BlockBackend<Block> + ProofProvider<Block> + Send + Sync + 'static,
    {
        // Reserve enough request slots for one request per peer when we are at the maximum
        // number of peers.
        let capacity = std::cmp::max(num_peer_hint, 1);
        let (tx, request_receiver) = async_channel::bounded(capacity);

        let protocol_config = generate_protocol_config::<_, Block, NB>(
            protocol_id,
            client
                .block_hash(0u32.into())
                .ok()
                .flatten()
                .expect("Genesis block exists; qed"),
            fork_id,
            tx,
        );

        let capacity = ByLength::new(num_peer_hint.max(1) as u32 * 2);
        let seen_requests = LruMap::new(capacity);

        (
            Self {
                request_receiver,
                seen_requests,
                offchain_db: OffchainDb::new(offchain_storage),
                _phantom: PhantomData,
            },
            protocol_config,
        )
    }

    /// Run [`StateRequestHandler`].
    pub async fn run(mut self) {
        while let Some(request) = self.request_receiver.next().await {
            let IncomingRequest {
                peer,
                payload,
                pending_response,
            } = request;

            match self.handle_request(payload, pending_response, &peer) {
                Ok(()) => debug!("Handled MMR request from {}.", peer),
                Err(e) => error!("Failed to handle MMR request from {}: {}", peer, e,),
            }
        }
    }

    fn handle_request(
        &mut self,
        payload: Vec<u8>,
        pending_response: oneshot::Sender<OutgoingResponse>,
        peer: &PeerId,
    ) -> Result<(), HandleRequestError> {
        let request = MmrRequest::decode(&mut payload.as_slice())?;

        let key = SeenRequestsKey {
            peer: *peer,
            starting_position: request.starting_position,
        };

        let mut reputation_changes = Vec::new();

        match self.seen_requests.get(&key) {
            Some(SeenRequestsValue::First) => {}
            Some(SeenRequestsValue::Fulfilled(ref mut requests)) => {
                *requests = requests.saturating_add(1);

                if *requests > MAX_NUMBER_OF_SAME_REQUESTS_PER_PEER {
                    reputation_changes.push(rep::SAME_REQUEST);
                }
            }
            None => {
                self.seen_requests
                    .insert(key.clone(), SeenRequestsValue::First);
            }
        }

        trace!("Handle MMR request: {peer}, request: {request:?}",);

        let result = if request.limit > MAX_MMR_ITEMS {
            error!(
                "Invalid MMR request from peer={peer}: {:?}",
                HandleRequestError::MaxItemsLimitExceeded
            );

            Err(())
        } else {
            let mut mmr_data = BTreeMap::new();
            for block_number in
                request.starting_position..(request.starting_position + request.limit)
            {
                let canon_key = get_offchain_key(block_number.into());
                let storage_value = self
                    .offchain_db
                    .local_storage_get(StorageKind::PERSISTENT, &canon_key);

                if let Some(storage_value) = storage_value {
                    mmr_data.insert(block_number, storage_value);
                } else {
                    break; // No more storage values
                }
            }

            if let Some(value) = self.seen_requests.get(&key) {
                // If this is the first time we have processed this request, we need to change
                // it to `Fulfilled`.
                if let SeenRequestsValue::First = value {
                    *value = SeenRequestsValue::Fulfilled(1);
                }
            }

            let response = MmrResponse { mmr_data };

            Ok(response.encode())
        };

        pending_response
            .send(OutgoingResponse {
                result,
                reputation_changes,
                sent_feedback: None,
            })
            .map_err(|_| HandleRequestError::SendResponse)
    }
}

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    #[error("Invalid request: max MMR nodes limit exceeded.")]
    MaxItemsLimitExceeded,

    #[error(transparent)]
    Client(#[from] sp_blockchain::Error),

    #[error("Failed to send response.")]
    SendResponse,

    #[error("Failed to decode request: {0}.")]
    Decode(#[from] codec::Error),
}
