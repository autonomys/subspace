//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::protocol::{
    ProtocolBackend, ProtocolClient, ProtocolRequest, ProtocolResponse, ProtocolServer,
};
use crate::{RelayClient, RelayError, RelayServer, LOG_TARGET};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot;
use libp2p::PeerId;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse};
use sc_network_common::sync::message::{BlockRequest, FromBlock};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use tracing::warn;

/// The block Id for the backend APIs
type BlockIndex<Block> = <Block as BlockT>::Hash;

/// The transaction Id for the backend APIs
type TxnIndex<Pool> = TxHash<Pool>;

/// The transaction
type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

/// Messages to server
#[derive(Encode, Decode)]
enum ServerMessage<Block: BlockT> {
    /// Initial request from the client. This has both the block request
    /// and the protocol specific part
    InitialRequest(BlockRequest<Block>, Option<ProtocolRequest>),

    /// Subsequent requests from the client during the resolve phase
    ProtocolRequest(ProtocolRequest),
}

/// Messages from server
#[derive(Encode, Decode)]
enum ClientMessage {
    /// Initial response from the server
    InitialResponse,

    /// Server response during the resolve phase
    ProtocolResponse(ProtocolResponse),
}

struct ConsensusRelayClient<Block: BlockT> {
    protocol: Arc<dyn ProtocolClient<BlockIndex<Block>, Extrinsic<Block>>>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block: BlockT> RelayClient for ConsensusRelayClient<Block> {
    type Request = BlockRequest<Block>;

    fn download(&self, _who: PeerId, request: &Self::Request, _network: NetworkServiceHandle) {
        // Send initial message
        let request =
            ServerMessage::<Block>::InitialRequest(request.clone(), self.protocol.build_request());
        let bytes = request.encode();

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
        block_request: BlockRequest<Block>,
        protocol_request: Option<ProtocolRequest>,
    ) -> Result<Vec<u8>, RelayError> {
        let block_hash = self.block_hash(&block_request.from)?;
        let _protocol_response = self
            .protocol
            .build_response(&block_hash, protocol_request)?;

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
                Ok(None) => Err(format!("Invalid block hash: {from:?}: None")),
                Err(err) => Err(format!("Invalid block hash: {from:?}: {err:?}")),
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
        let msg: ServerMessage<Block> = match Decode::decode(&mut payload.as_ref()) {
            Ok(msg) => msg,
            Err(err) => {
                self.send_response(
                    peer,
                    Err(format!("server: decode request: {err:?}")),
                    pending_response,
                );
                return;
            }
        };

        let ret = match msg {
            ServerMessage::InitialRequest(block_request, protocol_request) => {
                self.on_initial_request(block_request, protocol_request)
                    .await
            }
            ServerMessage::ProtocolRequest(req) => self.on_protocol_request(req).await,
        };
        self.send_response(peer, ret, pending_response);
    }
}

struct ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool,
{
    client: Arc<Client>,
    transaction_pool: Arc<Pool>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block, Client, Pool> ProtocolBackend<BlockIndex<Block>, TxnIndex<Pool>, Extrinsic<Block>>
    for ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool<Block = Block>,
{
    fn download_unit_members(
        &self,
        id: &BlockIndex<Block>,
    ) -> Result<Vec<(TxnIndex<Pool>, Vec<u8>)>, RelayError> {
        let extrinsics = self
            .client
            .block_body(*id)
            .map_err(|err| format!("download_unit_members:block_body: {id:?}, {err:?}"))?
            .unwrap_or_default();
        Ok(extrinsics
            .iter()
            .map(|extrinsic| (self.transaction_pool.hash_of(extrinsic), extrinsic.encode()))
            .collect())
    }

    fn protocol_unit(&self, id: &TxnIndex<Pool>) -> Result<Option<Extrinsic<Block>>, RelayError> {
        Ok(self
            .transaction_pool
            .ready_transaction(id)
            .map(|in_pool_transaction| in_pool_transaction.data().clone()))
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
    Pool: TransactionPool<Block = Block> + 'static,
{
    let backend = Arc::new(ConsensusBackend {
        client: client.clone(),
        transaction_pool: pool.clone(),
        _phantom_data: Default::default(),
    });
    let relay_client = ConsensusRelayClient {
        protocol: Arc::new(CompactBlockClient {
            backend: backend.clone(),
        }),
        _phantom_data: Default::default(),
    };

    let relay_server = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer { backend }),
        _phantom_data: Default::default(),
    };

    (Arc::new(relay_client), Box::new(relay_server))
}
