//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::utils::{NetworkPeerHandle, NetworkWrapper, RequestResponseErr};
use crate::{
    DownloadResult, ProtocolBackend, ProtocolClient, ProtocolServer, RelayError, LOG_TARGET,
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::{mpsc, oneshot};
use futures::stream::StreamExt;
use lru::LruCache;
use parking_lot::Mutex;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_common::sync::message::{BlockAttributes, BlockData, BlockRequest, FromBlock};
use sc_network_sync::block_relay_protocol::{
    BlockDownloader, BlockRelayParams, BlockResponseError, BlockServer,
};
use sc_service::SpawnTaskHandle;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header};
use sp_runtime::Justifications;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

type BlockHash<Block> = <Block as BlockT>::Hash;
type BlockHeader<Block> = <Block as BlockT>::Header;
type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

const SYNC_PROTOCOL: &str = "/subspace/consensus-block-relay/1";

// TODO: size these properly, or move to config
const NUM_PEER_HINT: NonZeroUsize = NonZeroUsize::new(100).expect("Not zero; qed");
const TRANSACTION_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(512).expect("Not zero; qed");

/// Initial request to the server
/// We currently ignore the direction field and return a single block,
/// revisit if needed
#[derive(Encode, Decode)]
struct InitialRequest<Block: BlockT, ProtocolRequest> {
    /// Starting block
    from_block: BlockId<Block>,

    /// Requested block components
    block_attributes: BlockAttributes,

    /// The protocol specific part of the request
    protocol_request: ProtocolRequest,
}

/// Initial response from server
#[derive(Encode, Decode)]
struct InitialResponse<Block: BlockT, ProtocolResponse> {
    ///  Hash of the block being downloaded
    block_hash: BlockHash<Block>,

    /// The partial block, without the extrinsics
    partial_block: PartialBlock<Block>,

    /// The opaque protocol specific part of the response.
    /// This is optional because BlockAttributes::BODY may not be set in
    /// the BlockRequest, in which case we don't need to fetch the
    /// extrinsics
    protocol_response: Option<ProtocolResponse>,
}

/// The partial block response from the server. It has all the fields
/// except the extrinsics. The extrinsics are handled by the protocol
#[derive(Encode, Decode)]
struct PartialBlock<Block: BlockT> {
    hash: BlockHash<Block>,
    header: Option<BlockHeader<Block>>,
    indexed_body: Option<Vec<Vec<u8>>>,
    justifications: Option<Justifications>,
}

/// The message to the server
#[derive(Encode, Decode)]
enum ServerMessage<Block: BlockT, ProtocolRequest> {
    /// Initial message, to be handled both by the client
    /// and the protocol
    InitialRequest(InitialRequest<Block, ProtocolRequest>),

    /// Message to be handled by the protocol
    ProtocolRequest(ProtocolRequest),
}

impl<Block: BlockT, ProtocolRequest> From<InitialRequest<Block, ProtocolRequest>>
    for ServerMessage<Block, ProtocolRequest>
{
    fn from(
        inner: InitialRequest<Block, ProtocolRequest>,
    ) -> ServerMessage<Block, ProtocolRequest> {
        ServerMessage::InitialRequest(inner)
    }
}

impl<Block: BlockT, ProtocolRequest> From<ProtocolRequest>
    for ServerMessage<Block, ProtocolRequest>
{
    fn from(inner: ProtocolRequest) -> ServerMessage<Block, ProtocolRequest> {
        ServerMessage::ProtocolRequest(inner)
    }
}

/// The client side of the consensus block relay
struct ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool,
    ProtoClient: ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
{
    network: Arc<NetworkWrapper>,
    protocol_name: ProtocolName,
    protocol_client: Arc<ProtoClient>,
    _phantom_data: std::marker::PhantomData<(Block, Pool)>,
}

impl<Block, Pool, ProtoClient> ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool,
    ProtoClient: ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
{
    /// Downloads the requested block from the peer using the relay protocol
    async fn download(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<DownloadResult<BlockHash<Block>, BlockData<Block>>, RelayError> {
        let start_ts = Instant::now();
        let network_peer_handle: NetworkPeerHandle<ServerMessage<Block, ProtoClient::Request>> =
            self.network
                .network_peer_handle(self.protocol_name.clone(), who)?;

        // Perform the initial request/response
        let initial_request = InitialRequest {
            from_block: match request.from {
                FromBlock::Hash(h) => BlockId::<Block>::Hash(h),
                FromBlock::Number(n) => BlockId::<Block>::Number(n),
            },
            block_attributes: request.fields,
            protocol_request: self.protocol_client.build_initial_request(),
        };
        let initial_response = network_peer_handle
            .request::<_, InitialResponse<Block, ProtoClient::Response>>(initial_request)
            .await?;

        // Resolve the protocol response to get the extrinsics
        let (body, local_miss) = if let Some(protocol_response) = initial_response.protocol_response
        {
            let (body, local_miss) = self
                .resolve_extrinsics(protocol_response, &network_peer_handle)
                .await?;
            (Some(body), local_miss)
        } else {
            (None, 0)
        };

        // Assemble the final response
        let block_data = BlockData::<Block> {
            hash: initial_response.partial_block.hash,
            header: initial_response.partial_block.header,
            body,
            indexed_body: initial_response.partial_block.indexed_body,
            receipt: None,
            message_queue: None,
            justification: None,
            justifications: initial_response.partial_block.justifications,
        };

        Ok(DownloadResult {
            download_unit_id: initial_response.block_hash,
            downloaded: block_data,
            latency: start_ts.elapsed(),
            local_miss,
        })
    }

    /// Resolves the extrinsics from the initial response
    async fn resolve_extrinsics(
        &self,
        protocol_response: ProtoClient::Response,
        network_peer_handle: &NetworkPeerHandle<ServerMessage<Block, ProtoClient::Request>>,
    ) -> Result<(Vec<Extrinsic<Block>>, usize), RelayError> {
        let (block_hash, resolved) = self
            .protocol_client
            .resolve_initial_response(protocol_response, network_peer_handle)
            .await?;
        let mut local_miss = 0;
        let extrinsics = resolved
            .into_iter()
            .map(|entry| {
                let encoded = entry.protocol_unit.encode();
                if !entry.locally_resolved {
                    trace!(
                        target: LOG_TARGET,
                        "relay::download: local miss: {block_hash:?}/{:?}, \
                             size = {}",
                        entry.protocol_unit_id,
                        encoded.len()
                    );
                    local_miss += encoded.len();
                }
                entry.protocol_unit
            })
            .collect();
        Ok((extrinsics, local_miss))
    }
}

#[async_trait]
impl<Block, Pool, ProtoClient> BlockDownloader<Block>
    for ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool,
    ProtoClient: ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
{
    async fn download_block(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
        let ret = self.download(who, request).await;
        match ret {
            Ok(result) => {
                let downloaded = result.downloaded.encode();
                trace!(
                    target: LOG_TARGET,
                    "relay::download_block: {:?} => {},{},{:?}",
                    result.download_unit_id,
                    downloaded.len(),
                    result.local_miss,
                    result.latency
                );
                Ok(Ok(downloaded))
            }
            Err(error) => {
                warn!(
                    target: LOG_TARGET,
                    "relay::download_block: peer = {who:?}, err = {error:?}"
                );
                match error {
                    RelayError::RequestResponse(error) => match error {
                        RequestResponseErr::DecodeFailed { .. } => {
                            Ok(Err(RequestFailure::Network(OutboundFailure::Timeout)))
                        }
                        RequestResponseErr::RequestFailure(err) => Ok(Err(err)),
                        RequestResponseErr::NetworkUninitialized => {
                            // TODO: This is the best error found that kind of matches
                            Ok(Err(RequestFailure::NotConnected))
                        }
                        RequestResponseErr::Canceled => Err(oneshot::Canceled),
                    },
                    _ => {
                        // Why timeout???
                        Ok(Err(RequestFailure::Network(OutboundFailure::Timeout)))
                    }
                }
            }
        }
    }

    fn block_response_into_blocks(
        &self,
        _request: &BlockRequest<Block>,
        response: Vec<u8>,
    ) -> Result<Vec<BlockData<Block>>, BlockResponseError> {
        match Decode::decode(&mut response.as_ref()) {
            Ok(block_data) => Ok(vec![block_data]),
            Err(err) => Err(BlockResponseError::DecodeFailed(format!(
                "Failed to decode consensus response: {err:?}"
            ))),
        }
    }
}

/// The server side of the consensus block relay
struct ConsensusRelayServer<
    Block: BlockT,
    Client,
    ProtoServer: ProtocolServer<BlockHash<Block>> + Send,
> {
    client: Arc<Client>,
    protocol: Box<ProtoServer>,
    request_receiver: mpsc::Receiver<IncomingRequest>,
    _block: std::marker::PhantomData<Block>,
}

impl<Block, Client, ProtoServer> ConsensusRelayServer<Block, Client, ProtoServer>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    ProtoServer: ProtocolServer<BlockHash<Block>> + Send,
{
    /// Handles the received request from the client side
    async fn on_request(&mut self, request: IncomingRequest) {
        // Drop the request in case of errors and let the client time out.
        // This is the behavior of the current substrate block handler.
        let IncomingRequest {
            peer,
            payload,
            pending_response,
        } = request;
        let server_msg: ServerMessage<Block, ProtoServer::Request> =
            match Decode::decode(&mut payload.as_ref()) {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(
                        target: LOG_TARGET,
                        "relay::on_request: decode incoming: {peer}: {err:?}"
                    );
                    return;
                }
            };

        let ret = match server_msg {
            ServerMessage::InitialRequest(req) => self.on_initial_request(req),
            ServerMessage::ProtocolRequest(req) => self.on_protocol_request(req),
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

    /// Handles the initial request from the client
    fn on_initial_request(
        &mut self,
        initial_request: InitialRequest<Block, ProtoServer::Request>,
    ) -> Result<Vec<u8>, RelayError> {
        let block_hash = self.block_hash(&initial_request.from_block)?;
        let block_attributes = initial_request.block_attributes;

        // Build the generic and the protocol specific parts of the response
        let partial_block = self.get_partial_block(&block_hash, block_attributes)?;
        let protocol_response = if block_attributes.contains(BlockAttributes::BODY) {
            Some(
                self.protocol
                    .build_initial_response(&block_hash, initial_request.protocol_request)?,
            )
        } else {
            None
        };

        let initial_response: InitialResponse<Block, ProtoServer::Response> = InitialResponse {
            block_hash,
            partial_block,
            protocol_response,
        };
        Ok(initial_response.encode())
    }

    /// Handles the protocol request from the client
    fn on_protocol_request(
        &mut self,
        request: ProtoServer::Request,
    ) -> Result<Vec<u8>, RelayError> {
        let response = self.protocol.on_request(request)?;
        Ok(response.encode())
    }

    /// Builds the partial block response
    fn get_partial_block(
        &self,
        block_hash: &BlockHash<Block>,
        block_attributes: BlockAttributes,
    ) -> Result<PartialBlock<Block>, RelayError> {
        let block_header = match self.client.header(*block_hash) {
            Ok(Some(header)) => header,
            Ok(None) => {
                return Err(RelayError::BlockHeader(format!(
                    "Missing header: {block_hash:?}"
                )))
            }
            Err(err) => return Err(RelayError::BlockHeader(format!("{block_hash:?}, {err:?}"))),
        };
        let hash = block_header.hash();

        let header = if block_attributes.contains(BlockAttributes::HEADER) {
            Some(block_header)
        } else {
            None
        };

        let indexed_body = if block_attributes.contains(BlockAttributes::INDEXED_BODY) {
            self.client
                .block_indexed_body(*block_hash)
                .map_err(|err| RelayError::BlockIndexedBody(format!("{block_hash:?}, {err:?}")))?
        } else {
            None
        };

        let justifications = if block_attributes.contains(BlockAttributes::JUSTIFICATION) {
            self.client.justifications(*block_hash).map_err(|err| {
                RelayError::BlockJustifications(format!("{block_hash:?}, {err:?}"))
            })?
        } else {
            None
        };

        Ok(PartialBlock {
            hash,
            header,
            indexed_body,
            justifications,
        })
    }

    /// Converts the BlockId to block hash
    fn block_hash(&self, block_id: &BlockId<Block>) -> Result<BlockHash<Block>, RelayError> {
        match self.client.block_hash_from_id(block_id) {
            Ok(Some(hash)) => Ok(hash),
            Ok(None) => Err(RelayError::BlockHash(format!("Missing: {block_id:?}"))),
            Err(err) => Err(RelayError::BlockHash(format!("{block_id:?}, {err:?}"))),
        }
    }

    /// Builds/sends the response back to the client
    fn send_response(
        &self,
        peer: PeerId,
        response: Vec<u8>,
        sender: oneshot::Sender<OutgoingResponse>,
    ) {
        let response = OutgoingResponse {
            result: Ok(response),
            reputation_changes: Vec::new(),
            sent_feedback: None,
        };
        if sender.send(response).is_err() {
            warn!(
                target: LOG_TARGET,
                "relay::send_response: failed to send to {peer}"
            );
        }
    }
}

#[async_trait]
impl<Block, Client, ProtoServer> BlockServer<Block>
    for ConsensusRelayServer<Block, Client, ProtoServer>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    ProtoServer: ProtocolServer<BlockHash<Block>> + Send,
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

/// The backend interface for the consensus block relay
struct ConsensusBackend<Block: BlockT, Client, Pool: TransactionPool> {
    client: Arc<Client>,
    transaction_pool: Arc<Pool>,
    transaction_cache: Arc<Mutex<LruCache<TxHash<Pool>, Extrinsic<Block>>>>,
}

impl<Block, Client, Pool> ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    fn new(
        client: Arc<Client>,
        transaction_pool: Arc<Pool>,
        spawn_handle: SpawnTaskHandle,
    ) -> Self {
        let transaction_cache = Arc::new(Mutex::new(LruCache::new(TRANSACTION_CACHE_SIZE)));
        spawn_handle.spawn_blocking("block-relay-transaction-import", None, {
            let transaction_pool = transaction_pool.clone();
            let transaction_cache = transaction_cache.clone();
            Box::pin(async move {
                while let Some(hash) = transaction_pool.import_notification_stream().next().await {
                    if let Some(transaction) = transaction_pool.ready_transaction(&hash) {
                        transaction_cache
                            .lock()
                            .put(hash.clone(), transaction.data().clone());
                        trace!(
                            target: LOG_TARGET,
                            "relay::backend: received import notification: {hash:?}"
                        );
                    }
                }
            })
        });

        Self {
            client,
            transaction_pool,
            transaction_cache,
        }
    }

    /// Adds the entry to the cache
    fn update_cache(&self, tx_hash: &TxHash<Pool>, extrinsic: &Extrinsic<Block>) {
        self.transaction_cache
            .lock()
            .put(tx_hash.clone(), extrinsic.clone());
        trace!(
            target: LOG_TARGET,
            "relay::backend: updated cache: {tx_hash:?}"
        );
    }
}

impl<Block, Client, Pool> ProtocolBackend<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>
    for ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    fn download_unit_members(
        &self,
        block_hash: &BlockHash<Block>,
    ) -> Result<Vec<(TxHash<Pool>, Extrinsic<Block>)>, RelayError> {
        let extrinsics = self
            .client
            .block_body(*block_hash)
            .map_err(|err| RelayError::BlockBody(format!("{block_hash:?}, {err:?}")))?
            .unwrap_or_default();
        Ok(extrinsics
            .into_iter()
            .map(|extrinsic| (self.transaction_pool.hash_of(&extrinsic), extrinsic))
            .collect())
    }

    fn protocol_unit(
        &self,
        block_hash: &BlockHash<Block>,
        tx_hash: &TxHash<Pool>,
    ) -> Result<Option<Extrinsic<Block>>, RelayError> {
        // First look up the cache
        if let Some(extrinsic) = self.transaction_cache.lock().get(tx_hash) {
            return Ok(Some(extrinsic.clone()));
        }

        // Next look up the block extrinsics
        if let Ok(Some(extrinsics)) = self.client.block_body(*block_hash) {
            if !extrinsics.is_empty() {
                let len = extrinsics.len();
                for extrinsic in extrinsics {
                    if self.transaction_pool.hash_of(&extrinsic) == *tx_hash {
                        // TODO: avoid adding inherents to the cache
                        self.update_cache(tx_hash, &extrinsic);
                        return Ok(Some(extrinsic));
                    }
                }
                trace!(
                    target: LOG_TARGET,
                    "relay::protocol_unit: {tx_hash:?} not found in {block_hash:?}/{len}",
                );
            }
        }

        // Failed to find the transaction among the block extrinsics, look up the
        // transaction pool
        if let Some(in_pool_transaction) = self.transaction_pool.ready_transaction(tx_hash) {
            let extrinsic = in_pool_transaction.data().clone();
            self.update_cache(tx_hash, &extrinsic);
            return Ok(Some(extrinsic));
        }

        Ok(None)
    }
}

pub fn build_consensus_relay<Block, Client, Pool>(
    network: Arc<NetworkWrapper>,
    client: Arc<Client>,
    pool: Arc<Pool>,
    spawn_handle: SpawnTaskHandle,
) -> BlockRelayParams<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + 'static,
    Pool: TransactionPool<Block = Block> + 'static,
{
    let (tx, request_receiver) = mpsc::channel(NUM_PEER_HINT.get());

    let backend = Arc::new(ConsensusBackend::new(client.clone(), pool, spawn_handle));
    let relay_client: ConsensusRelayClient<Block, Pool, _> = ConsensusRelayClient {
        network,
        protocol_name: SYNC_PROTOCOL.into(),
        protocol_client: Arc::new(CompactBlockClient {
            backend: backend.clone(),
        }),
        _phantom_data: Default::default(),
    };

    let relay_server = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer { backend }),
        request_receiver,
        _block: Default::default(),
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
