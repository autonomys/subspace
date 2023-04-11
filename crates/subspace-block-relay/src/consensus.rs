//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::protocol::{ProtocolBackend, ProtocolClient, ProtocolServer};
use crate::utils::{RequestResponseStub, ServerMessage};
use crate::{RelayClient, RelayError, RelayServer, LOG_TARGET};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::{mpsc, oneshot};
use futures::stream::StreamExt;
use prost::Message;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use sc_network::types::ProtocolName;
use sc_network::{PeerId, RequestFailure};
use sc_network_common::sync::message::BlockAttributes;
use sc_network_sync::block_relay_protocol::{BlockDownloader, BlockRelayParams, BlockServer};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_network_sync::{BlockDataSchema, BlockRequestSchema, BlockResponseSchema, FromBlockSchema};
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Extrinsic as ExtrinsicT, Header};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, trace, warn};

/// The block Id for the backend APIs
type BlockHash<Block> = <Block as BlockT>::Hash;

/// The transaction
type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

const SYNC_PROTOCOL: &str = "/subspace/consensus-block-relay/1";

/// Initial request to server
#[derive(Encode, Decode)]
struct InitialRequest {
    /// Block request is the serialized BlockRequestSchema
    block_request: Vec<u8>,

    /// The opaque protocol specific part of the request
    protocol_request: Option<Vec<u8>>,
}

/// Initial response from server
#[derive(Encode, Decode)]
struct InitialResponse {
    /// The block except the extrinsics
    partial_block: PartialBlock,

    /// The opaque protocol specific part of the response
    protocol_response: Vec<u8>,
}

/// The partial block request from the server, it has all the fields
/// except the extrinsics. The extrinsics come from the protocol.
/// This is a subset of BlockResponseSchema, so that the fields can be
/// moved into the final output without extra copies.
#[derive(Encode, Decode)]
struct PartialBlock {
    hash: Vec<u8>,
    hdr: Vec<u8>,
    justification: Vec<u8>,
    is_empty_justification: bool,
    justifications: Vec<u8>,
    indexed_body: Vec<Vec<u8>>,
}

struct ConsensusRelayClient<Block: BlockT, Pool: TransactionPool> {
    protocol: Arc<dyn ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>>,
    protocol_name: ProtocolName,
    _phantom_data: std::marker::PhantomData<Block>,
}

#[async_trait]
impl<Block: BlockT, Pool: TransactionPool> RelayClient for ConsensusRelayClient<Block, Pool> {
    type Request = Vec<u8>;

    async fn download(
        &self,
        who: PeerId,
        request: Self::Request,
        network: NetworkServiceHandle,
    ) -> Result<Vec<u8>, RelayError> {
        let stub = RequestResponseStub::new(self.protocol_name.clone(), who, network);

        // Perform the initial request/response
        let initial_request = InitialRequest {
            block_request: request,
            protocol_request: self.protocol.build_initial_request(),
        };
        let initial_response = match stub
            .request_response::<InitialRequest, InitialResponse>(initial_request, false)
            .await
        {
            Ok(response) => response,
            Err(err) => return Err(err.into()),
        };

        // Resolve the protocol response to get the extrinsics
        let (block_hash, mut resolved) = self
            .protocol
            .resolve(initial_response.protocol_response, stub.clone())
            .await?;

        // Assemble the final response
        let block_data = BlockDataSchema {
            hash: initial_response.partial_block.hash,
            header: initial_response.partial_block.hdr,
            body: resolved
                .iter_mut()
                .map(|resolved| {
                    let encoded = resolved.protocol_unit.encode();
                    warn!(
                        target: LOG_TARGET,
                        "relay::download: {block_hash:?}/{:?}: locally_resolved = {}, \
                         signed = {:?}, size = {}",
                        resolved.protocol_unit_id,
                        resolved.locally_resolved,
                        resolved.protocol_unit.is_signed(),
                        encoded.len()
                    );
                    encoded
                })
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
            Err(format!("download: encode response: {err:?}").into())
        } else {
            Ok(data)
        }
    }
}

#[async_trait]
impl<Block: BlockT, Pool: TransactionPool> BlockDownloader for ConsensusRelayClient<Block, Pool> {
    async fn download_block(
        &self,
        who: PeerId,
        request: Vec<u8>,
        network: NetworkServiceHandle,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
        match self.download(who, request, network).await {
            Ok(val) => {
                trace!(
                    target: LOG_TARGET,
                    "relay::download_block: success: peer = {who:?}"
                );
                Ok(Ok(val))
            }
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "relay::download_block: peer = {who:?}, err = {err:?}"
                );
                err.into()
            }
        }
    }
}

struct ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    client: Arc<Client>,
    protocol: Box<dyn ProtocolServer<BlockHash<Block>> + Send>,
    request_receiver: mpsc::Receiver<IncomingRequest>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block, Client> ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    fn on_consensus_request(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        let req: InitialRequest = match Decode::decode(&mut msg.as_ref()) {
            Ok(initial_request) => initial_request,
            Err(err) => {
                return Err(RelayError::from(format!(
                    "on_consensus_request: decode request: {err:?}"
                )))
            }
        };
        let block_request = BlockRequestSchema::decode(&req.block_request[..])
            .map_err(|err| format!("on_consensus_request: decode schema: {err:?}"))?;
        let block_hash = self.block_hash(&block_request.from_block)?;
        let block_attributes = BlockAttributes::from_be_u32(block_request.fields)
            .map_err(|err| format!("on_consensus_request: block attributes: {err:?}"))?;

        let partial_block = self.get_partial_block(&block_hash, block_attributes)?;
        let protocol_response = self
            .protocol
            .build_initial_response(&block_hash, req.protocol_request)?;
        let initial_response = InitialResponse {
            partial_block,
            protocol_response,
        };
        Ok(initial_response.encode())
    }

    fn get_partial_block(
        &self,
        block_hash: &BlockHash<Block>,
        block_attributes: BlockAttributes,
    ) -> Result<PartialBlock, RelayError> {
        let block_hdr = match self.client.header(*block_hash) {
            Ok(Some(hdr)) => hdr,
            Ok(None) => {
                return Err(format!("get_partial_block: missing hdr: {block_hash:?}").into())
            }
            Err(err) => {
                return Err(format!("get_partial_block: get hdr: {block_hash:?}, {err:?}").into())
            }
        };

        // Header
        let hdr = if block_attributes.contains(BlockAttributes::HEADER) {
            block_hdr.encode()
        } else {
            Vec::new()
        };

        // Justifications
        let justifications = if block_attributes.contains(BlockAttributes::JUSTIFICATION) {
            self.client
                .justifications(*block_hash)
                .map_err(|err| {
                    format!("get_partial_block: justifications: {block_hash:?}, {err:?}")
                })?
                .map_or(Vec::new(), |v| v.encode())
        } else {
            Vec::new()
        };

        // Indexed body
        let indexed_body = if block_attributes.contains(BlockAttributes::INDEXED_BODY) {
            self.client
                .block_indexed_body(*block_hash)
                .map_err(|err| {
                    format!("get_partial_block: block_indexed_body: {block_hash:?}, {err:?}")
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

    fn block_hash(&self, from: &Option<FromBlockSchema>) -> Result<BlockHash<Block>, RelayError> {
        let block_id = match from {
            Some(ref from_block) => match from_block {
                FromBlockSchema::Hash(ref h) => {
                    let h = Decode::decode(&mut h.as_ref())
                        .map_err(|err| format!("block_hash: decode hash: {err:?}"))?;
                    BlockId::<Block>::Hash(h)
                }
                FromBlockSchema::Number(ref n) => {
                    let n = Decode::decode(&mut n.as_ref())
                        .map_err(|err| format!("block_hash decode number: {err:?}"))?;
                    BlockId::<Block>::Number(n)
                }
            },
            None => {
                return Err(RelayError::from(
                    "block_hash: missing FromBlock".to_string(),
                ))
            }
        };

        match self.client.block_hash_from_id(&block_id) {
            Ok(Some(hash)) => Ok(hash),
            Ok(None) => Err(format!("block_hash: {from:?}: None").into()),
            Err(err) => Err(format!("block_hash: {from:?}: {err:?}").into()),
        }
    }

    fn send_response(
        &self,
        peer: sc_network::PeerId,
        response: Vec<u8>,
        sender: oneshot::Sender<OutgoingResponse>,
    ) {
        let response = OutgoingResponse {
            result: Ok(response),
            reputation_changes: Vec::new(),
            sent_feedback: None,
        };
        if let Err(err) = sender.send(response) {
            warn!(
                target: LOG_TARGET,
                "relay::send_response: failed to send to {peer}: {err:?}"
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
            payload,
            pending_response,
        } = request;
        let server_msg: ServerMessage = match Decode::decode(&mut payload.as_ref()) {
            Ok(msg) => msg,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "relay::on_request: decode incoming: {peer}: {err:?}"
                );
                return;
            }
        };

        let ret = if !server_msg.is_protocol_message {
            self.on_consensus_request(server_msg.message)
        } else {
            self.protocol.on_request(server_msg.message)
        };
        match ret {
            Ok(response) => {
                self.send_response(peer, response, pending_response);
                trace!(
                    target: LOG_TARGET,
                    "relay::consensus server: request processed from: {peer}"
                );
            }
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "relay::consensus server: request processing error: {peer}:  {err:?}"
                );
            }
        }
    }
}

#[async_trait]
impl<Block, Client> BlockServer<Block> for ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    async fn run(&mut self) {
        info!(
            target: LOG_TARGET,
            "relay::consensus block server: starting"
        );
        while let Some(request) = self.request_receiver.next().await {
            self.on_request(request).await;
        }
    }
}

// TODO: listen to import notifications, cache transactions/blocks
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

impl<Block, Client, Pool> ProtocolBackend<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>
    for ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool<Block = Block>,
{
    fn download_unit_members(
        &self,
        block_hash: &BlockHash<Block>,
    ) -> Result<Vec<TxHash<Pool>>, RelayError> {
        let extrinsics = self
            .client
            .block_body(*block_hash)
            .map_err(|err| format!("download_unit_members:block_body: {block_hash:?}, {err:?}"))?
            .unwrap_or_default();
        Ok(extrinsics
            .iter()
            .map(|extrinsic| self.transaction_pool.hash_of(extrinsic))
            .collect())
    }

    fn protocol_unit(
        &self,
        block_hash: &BlockHash<Block>,
        tx_hash: &TxHash<Pool>,
        client: bool,
    ) -> Result<Option<Extrinsic<Block>>, RelayError> {
        // First look up the block extrinsics
        if let Ok(Some(extrinsics)) = self.client.block_body(*block_hash) {
            if !extrinsics.is_empty() {
                let len = extrinsics.len();
                for extrinsic in extrinsics {
                    if self.transaction_pool.hash_of(&extrinsic) == *tx_hash {
                        return Ok(Some(extrinsic));
                    }
                }
                warn!(
                    target: LOG_TARGET,
                    "relay::protocol_unit: {client}, {tx_hash:?} not found in {block_hash:?}/{len}",
                );
            }
        }

        // Failed to find the transaction among the block extrinsics, look up the
        // transaction pool.
        Ok(self
            .transaction_pool
            .ready_transaction(tx_hash)
            .map(|in_pool_transaction| in_pool_transaction.data().clone()))
    }
}

pub fn build_consensus_relay<Block, Client, Pool>(
    client: Arc<Client>,
    pool: Arc<Pool>,
    num_peer_hint: usize,
) -> BlockRelayParams<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + 'static,
    Pool: TransactionPool<Block = Block> + 'static,
{
    let (tx, request_receiver) = mpsc::channel(num_peer_hint);

    let backend = Arc::new(ConsensusBackend {
        client: client.clone(),
        transaction_pool: pool,
        _phantom_data: Default::default(),
    });
    let relay_client: ConsensusRelayClient<Block, Pool> = ConsensusRelayClient {
        protocol: Arc::new(CompactBlockClient {
            backend: backend.clone(),
        }),
        protocol_name: SYNC_PROTOCOL.into(),
        _phantom_data: Default::default(),
    };

    let relay_server = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer { backend }),
        request_receiver,
        _phantom_data: Default::default(),
    };

    let mut protocol_config = ProtocolConfig {
        name: SYNC_PROTOCOL.into(),
        fallback_names: Vec::new(),
        max_request_size: 1024 * 1024,
        max_response_size: 16 * 1024 * 1024,
        request_timeout: Duration::from_secs(20),
        inbound_queue: None,
    };
    protocol_config.inbound_queue = Some(tx);

    BlockRelayParams {
        server: Box::new(relay_server),
        downloader: Arc::new(relay_client),
        request_response_config: protocol_config,
    }
}
