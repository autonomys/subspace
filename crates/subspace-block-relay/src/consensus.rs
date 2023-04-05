//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::{
    PoolBackend, ProtocolClient, ProtocolInitialRequest, ProtocolServer, RelayClient, RelayError,
    RelayServer, RelayServerMessage, LOG_TARGET,
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot;
use libp2p::PeerId;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse};
use sc_network_common::sync::message::{BlockRequest, FromBlock};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_transaction_pool_api::{TransactionPool, TxHash};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use tracing::warn;

/// The block Id for the backend APIs
type BlockIndex<Block> = <Block as BlockT>::Hash;

/// The transaction id for the backend APIs
type TxnIndex<Pool> = TxHash<Pool>;

#[derive(Encode, Decode)]
struct InitialRequest<Block: BlockT> {
    block_request: BlockRequest<Block>,
    protocol_request: ProtocolInitialRequest,
}

struct ConsensusRelayClient<Block: BlockT> {
    protocol: Arc<dyn ProtocolClient<BlockIndex<Block>>>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block: BlockT> RelayClient for ConsensusRelayClient<Block> {
    type Request = BlockRequest<Block>;

    fn download(&self, _who: PeerId, request: &Self::Request, _network: NetworkServiceHandle) {
        // Send initial message
        let _bytes = RelayServerMessage::<InitialRequest<Block>>::InitialRequest(InitialRequest {
            block_request: request.clone(),
            protocol_request: self.protocol.build_request(),
        })
        .encode();
        // let response = _network.send(bytes).await;
        // let transactions = self.protocol.resolve(response.protocol_data);

        unimplemented!()
    }
}

struct ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    client: Arc<Client>,
    protocol: Box<dyn ProtocolServer<BlockIndex<Block>> + Send>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block, Client> ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    async fn on_initial_request(
        &mut self,
        req: InitialRequest<Block>,
    ) -> Result<Vec<u8>, RelayError> {
        let block_hash = self.block_hash(&req.block_request.from)?;
        let _protocol_response = self
            .protocol
            .build_response(&block_hash, req.protocol_request);

        // Fill the rest of the block request
        // Call proto to fill the protocol entries
        // Encode and send
        Ok(vec![])
    }

    async fn on_protocol_request(&mut self, req: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        // Call proto to process the request
        // Encode and send
        Ok(vec![])
    }

    fn block_hash(
        &self,
        from: &FromBlock<<Block as BlockT>::Hash, NumberFor<Block>>,
    ) -> Result<BlockIndex<Block>, RelayError> {
        match from {
            FromBlock::Hash(h) => Ok(h.clone()),
            FromBlock::Number(n) => match self.client.block_hash(*n) {
                Ok(Some(hash)) => Ok(hash),
                Ok(None) => Err(RelayError::InvalidBlockHash(format!("{from:?}: None"))),
                Err(err) => Err(RelayError::InvalidBlockHash(format!("{from:?}: {err:?}"))),
            },
        }
    }

    fn send_response(
        &self,
        peer: sc_network::PeerId,
        result: Result<Vec<u8>, RelayError>,
        sender: oneshot::Sender<OutgoingResponse>,
    ) {
        let response = OutgoingResponse {
            result: Ok(result.encode()),
            reputation_changes: Vec::new(),
            sent_feedback: None,
        };
        if let Err(err) = sender.send(response) {
            warn!(
                target: LOG_TARGET,
                "consensus relay server: failed to send response to {peer}: {err:?}"
            );
        }
    }
}

#[async_trait]
impl<Block, Client> RelayServer for ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    async fn on_request(&mut self, request: IncomingRequest) {
        let IncomingRequest {
            peer,
            mut payload,
            pending_response,
        } = request;
        let msg: RelayServerMessage<InitialRequest<Block>> =
            match Decode::decode(&mut payload.as_ref()) {
                Ok(msg) => msg,
                Err(err) => {
                    self.send_response(
                        peer,
                        Err(RelayError::InvalidIncomingRequest(format!("{err:?}"))),
                        pending_response,
                    );
                    return;
                }
            };

        let ret = match msg {
            RelayServerMessage::InitialRequest(req) => self.on_initial_request(req).await,
            RelayServerMessage::ProtocolRequest(req) => self.on_protocol_request(req).await,
        };
        self.send_response(peer, ret, pending_response);
    }
}

struct ConsensusPoolBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool,
{
    client: Arc<Client>,
    transaction_pool: Arc<Pool>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block, Client, Pool> PoolBackend<BlockIndex<Block>, TxnIndex<Pool>>
    for ConsensusPoolBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool,
{
    fn download_unit_members(
        &self,
        id: &BlockIndex<Block>,
    ) -> Result<Vec<(TxnIndex<Pool>, Vec<u8>)>, String> {
        Ok(vec![])
    }

    fn protocol_unit(&self, id: &TxnIndex<Pool>) -> Option<Vec<u8>> {
        unimplemented!()
    }
}

fn build_consensus_relay<Block, Client, Pool>(
    client: Arc<Client>,
    pool: Arc<Pool>,
) -> (
    Arc<ConsensusRelayClient<Block>>,
    Box<ConsensusRelayServer<Block, Client>>,
)
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + 'static,
    Pool: TransactionPool + 'static,
{
    let backend: ConsensusPoolBackend<Block, Client, Pool> = ConsensusPoolBackend {
        client: client.clone(),
        transaction_pool: pool.clone(),
        _phantom_data: Default::default(),
    };
    let relay_client: ConsensusRelayClient<Block> = ConsensusRelayClient {
        protocol: Arc::new(CompactBlockClient {
            backend: Arc::new(backend),
        }),
        _phantom_data: Default::default(),
    };

    let relay_server: ConsensusRelayServer<Block, Client> = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer),
        _phantom_data: Default::default(),
    };

    (Arc::new(relay_client), Box::new(relay_server))
}
