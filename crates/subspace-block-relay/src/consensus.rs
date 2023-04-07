//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::protocol::{
    ProtocolBackend, ProtocolClient, ProtocolRequest, ProtocolResponse, ProtocolServer,
};
use crate::utils::RequestResponseStub;
use crate::{RelayClient, RelayError, RelayServer, LOG_TARGET};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot;
use prost::Message;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IfDisconnected, IncomingRequest, OutgoingResponse};
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_common::sync::message::{BlockAttributes, BlockRequest, FromBlock};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_network_sync::{BlockDataSchema, BlockResponseSchema, DirectionSchema};
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::sync::Arc;
use tracing::warn;

/// The block Id for the backend APIs
type BlockIndex<Block> = <Block as BlockT>::Hash;

/// The transaction Id for the backend APIs
type TxnIndex<Pool> = TxHash<Pool>;

/// The transaction
type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

const SYNC_PROTOCOL: &str = "/subspace/consensus-block-relay/1";

/// Initial request to server
#[derive(Encode, Decode)]
struct InitialRequest<Block: BlockT> {
    block_request: BlockRequest<Block>,
    protocol_request: Option<Vec<u8>>,
}

/// Initial response from server
#[derive(Encode, Decode)]
struct InitialResponse {
    partial_block: PartialBlock,
    protocol_response: Vec<u8>,
}

/// Messages from client
#[derive(Encode, Decode)]
enum ClientMessage<Block: BlockT> {
    /// Initial request from the client. This has both the block request
    /// and the protocol specific part
    InitialRequest(BlockRequest<Block>, Option<ProtocolRequest>),

    /// Subsequent requests from the client during the resolve phase
    ProtocolRequest(ProtocolRequest),
}

/// Messages from server
#[derive(Encode, Decode)]
enum ServerMessage {
    /// Initial response: serialized BlockResponseSchema + protocol bytes
    InitialResponse(Vec<u8>, ProtocolResponse),

    /// Protocol bytes during the resolve phase
    ProtocolResponse(ProtocolResponse),
}

/// The partial block request from the server, it has all the fields
/// except the extrinsics. The extrinsics come from the protocol.
/// This is a subset of BlockResponseSchema
#[derive(Encode, Decode)]
struct PartialBlock {
    hash: Vec<u8>,
    hdr: Vec<u8>,
    justification: Vec<u8>,
    is_empty_justification: bool,
    justifications: Vec<u8>,
    indexed_body: Vec<Vec<u8>>,
}

struct ConsensusRelayClient<Block: BlockT> {
    protocol: Arc<dyn ProtocolClient<BlockIndex<Block>, Extrinsic<Block>>>,
    protocol_name: ProtocolName,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block: BlockT> ConsensusRelayClient<Block> {
    async fn send_request(
        &self,
        who: PeerId,
        request: Vec<u8>,
        network: NetworkServiceHandle,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
        let (tx, rx) = oneshot::channel();
        network.start_request(
            who,
            self.protocol_name.clone(),
            request,
            tx,
            IfDisconnected::ImmediateError,
        );
        rx.await
    }
}

#[async_trait]
impl<Block: BlockT> RelayClient for ConsensusRelayClient<Block> {
    type Request = BlockRequest<Block>;

    async fn download(
        &self,
        who: PeerId,
        request: &Self::Request,
        network: NetworkServiceHandle,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
        let stub = RequestResponseStub::new(self.protocol_name.clone(), who, network);

        // Perform the initial request/response
        let initial_request: InitialRequest<Block> = InitialRequest {
            block_request: request.clone(),
            protocol_request: self.protocol.build_request(),
        };
        let initial_response = match stub
            .request_response::<InitialRequest<Block>, InitialResponse>(initial_request)
            .await
        {
            Ok(response) => response,
            Err(err) => return err.into(),
        };

        // Resolve the protocol response to get the extrinsics
        let mut extrinsics = match self
            .protocol
            .resolve(initial_response.protocol_response, stub.clone())
            .await
        {
            Ok(extrinsics) => extrinsics,
            Err(err) => return err.into(),
        };

        // Assemble the final response
        let block_data = BlockDataSchema {
            hash: initial_response.partial_block.hash,
            header: initial_response.partial_block.hdr,
            body: extrinsics
                .iter_mut()
                .map(|extrinsic| extrinsic.encode())
                .collect(),
            receipt: Vec::new(),
            message_queue: Vec::new(),
            justification: initial_response.partial_block.justification,
            is_empty_justification: initial_response.partial_block.is_empty_justification,
            justifications: initial_response.partial_block.justifications,
            indexed_body: initial_response.partial_block.indexed_body,
        };
        let block_response = BlockResponseSchema {
            blocks: vec![block_data],
        };
        let mut data = Vec::with_capacity(block_response.encoded_len());

        if let Err(err) = block_response.encode(&mut data) {
            let relay_err: RelayError =
                format!("download: failed to encode response: {err:?}").into();
            relay_err.into()
        } else {
            Ok(Ok(data))
        }
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
        let partial_block = self
            .get_partial_block(&block_hash, &block_request)?
            .encode();
        let protocol_response = self
            .protocol
            .build_response(&block_hash, protocol_request)?;
        let initial_response = ServerMessage::InitialResponse(partial_block, protocol_response);
        Ok(initial_response.encode())
    }

    async fn on_protocol_request(&mut self, req: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        // Call proto to process the request
        // Encode and send
        Ok(vec![])
    }

    fn get_partial_block(
        &self,
        block_hash: &BlockIndex<Block>,
        block_request: &BlockRequest<Block>,
    ) -> Result<PartialBlock, RelayError> {
        let block_hdr = match self.client.header(*block_hash) {
            Ok(Some(hdr)) => hdr,
            Ok(None) => return Err(format!("partial block: missing hdr: {block_hash:?}").into()),
            Err(err) => {
                return Err(
                    format!("partial block: failed to get hdr: {block_hash:?}, {err:?}").into(),
                )
            }
        };

        // Header
        let hdr = if block_request.fields.contains(BlockAttributes::HEADER) {
            block_hdr.encode()
        } else {
            Vec::new()
        };

        // Justifications
        let justifications = if block_request
            .fields
            .contains(BlockAttributes::JUSTIFICATION)
        {
            self.client
                .justifications(*block_hash)
                .map_err(|err| {
                    format!("partial block: failed to get justification: {block_hash:?}, {err:?}")
                })?
                .map_or(Vec::new(), |v| v.encode())
        } else {
            Vec::new()
        };

        // Indexed body
        let indexed_body = if block_request.fields.contains(BlockAttributes::INDEXED_BODY) {
            self.client
                .block_indexed_body(*block_hash)
                .map_err(|err| {
                    format!("partial block: failed to get indexed body: {block_hash:?}, {err:?}")
                })?
                .unwrap_or(Vec::new())
        } else {
            Vec::new()
        };

        Ok(PartialBlock {
            hash: block_hdr.hash().encode(),
            hdr,
            justification: Vec::new(),
            is_empty_justification: false,
            justifications,
            indexed_body,
        })
    }

    fn block_hash(
        &self,
        from: &FromBlock<<Block as BlockT>::Hash, NumberFor<Block>>,
    ) -> Result<BlockIndex<Block>, RelayError> {
        match from {
            FromBlock::Hash(h) => Ok(h.clone()),
            FromBlock::Number(n) => match self.client.block_hash(*n) {
                Ok(Some(hash)) => Ok(hash),
                Ok(None) => Err(format!("Invalid block hash: {from:?}: None").into()),
                Err(err) => Err(format!("Invalid block hash: {from:?}: {err:?}").into()),
            },
        }
    }

    fn send_response(
        &self,
        peer: sc_network::PeerId,
        response: Vec<u8>,
        sender: oneshot::Sender<OutgoingResponse>,
    ) {
        let response = OutgoingResponse {
            result: Ok(Encode::encode(&response)),
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
        // Drop the request in case of errors and let the client time out.
        // This is the behavior of the current substrate block handler.
        let IncomingRequest {
            peer,
            mut payload,
            pending_response,
        } = request;
        let msg: ClientMessage<Block> = match Decode::decode(&mut payload.as_ref()) {
            Ok(msg) => msg,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "on request: decode request: {peer}: {err:?}"
                );
                return;
            }
        };

        let ret = match msg {
            ClientMessage::InitialRequest(block_request, protocol_request) => {
                self.on_initial_request(block_request, protocol_request)
                    .await
            }
            ClientMessage::ProtocolRequest(req) => self.on_protocol_request(req).await,
        };
        match ret {
            Ok(response) => {
                self.send_response(peer, response, pending_response);
            }
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "on request: processing request: {peer}:  {err:?}"
                );
            }
        }
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
        protocol_name: SYNC_PROTOCOL.into(),
        _phantom_data: Default::default(),
    };

    let relay_server = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer { backend }),
        _phantom_data: Default::default(),
    };

    (Arc::new(relay_client), Box::new(relay_server))
}
