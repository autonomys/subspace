//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::utils::{NetworkPeerHandle, NetworkWrapper, RequestResponseErr};
use crate::{
    ProtocolBackend, ProtocolClient, ProtocolServer, ProtocolUnitInfo, RelayError, LOG_TARGET,
};
use async_trait::async_trait;
use codec::{Compact, CompactLen, Decode, Encode};
use futures::channel::oneshot;
use futures::stream::StreamExt;
use lru::LruCache;
use parking_lot::Mutex;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_common::sync::message::{
    BlockAttributes, BlockData, BlockRequest, Direction, FromBlock,
};
use sc_network_sync::block_relay_protocol::{
    BlockDownloader, BlockRelayParams, BlockResponseError, BlockServer,
};
use sc_service::SpawnTaskHandle;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_api::ProvideRuntimeApi;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor, One, Zero};
use sp_runtime::Justifications;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

type BlockHash<Block> = <Block as BlockT>::Hash;
type BlockHeader<Block> = <Block as BlockT>::Header;
type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

const SYNC_PROTOCOL: &str = "/subspace/consensus-block-relay/1";

// TODO: size these properly, or move to config
const NUM_PEER_HINT: NonZeroUsize = NonZeroUsize::new(100).expect("Not zero; qed");
const TRANSACTION_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(512).expect("Not zero; qed");

/// These are the same limits used by substrate block handler.
/// Maximum response size (bytes).
const MAX_RESPONSE_SIZE: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("Not zero; qed");
/// Maximum blocks in the response.
const MAX_RESPONSE_BLOCKS: NonZeroU32 = NonZeroU32::new(128).expect("Not zero; qed");

/// If the encoded size of the extrinsic is less than the threshold,
/// return the full extrinsic along with the tx hash.
const TX_SIZE_THRESHOLD: NonZeroUsize = NonZeroUsize::new(32).expect("Not zero; qed");

/// Initial request for a single block.
#[derive(Encode, Decode)]
struct InitialRequest<Block: BlockT, ProtocolRequest> {
    /// Starting block
    from_block: BlockId<Block>,

    /// Requested block components
    block_attributes: BlockAttributes,

    /// The protocol specific part of the request
    protocol_request: ProtocolRequest,
}

/// Initial response for a single block.
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

/// Request to download multiple/complete blocks, for scenarios like the
/// sync phase. This does not involve the protocol optimizations, as the
/// requesting node is just coming up and may not have the transactions
/// in its pool. So it does not make sense to send response with tx hash,
/// and the full blocks are sent back. This behaves like the default
/// substrate block downloader.
#[derive(Encode, Decode)]
struct FullDownloadRequest<Block: BlockT>(BlockRequest<Block>);

/// Response to the full download request.
#[derive(Encode, Decode)]
struct FullDownloadResponse<Block: BlockT>(Vec<BlockData<Block>>);

/// The partial block response from the server. It has all the fields
/// except the extrinsics(and some other meta info). The extrinsics
/// are handled by the protocol.
#[derive(Encode, Decode)]
struct PartialBlock<Block: BlockT> {
    parent_hash: BlockHash<Block>,
    block_number: NumberFor<Block>,
    block_header_hash: BlockHash<Block>,
    header: Option<BlockHeader<Block>>,
    indexed_body: Option<Vec<Vec<u8>>>,
    justifications: Option<Justifications>,
}

impl<Block: BlockT> PartialBlock<Block> {
    /// Builds the full block data.
    fn block_data(self, body: Option<Vec<Extrinsic<Block>>>) -> BlockData<Block> {
        BlockData::<Block> {
            hash: self.block_header_hash,
            header: self.header,
            body,
            indexed_body: self.indexed_body,
            receipt: None,
            message_queue: None,
            justification: None,
            justifications: self.justifications,
        }
    }
}

/// The message to the server
#[allow(clippy::enum_variant_names)]
#[derive(Encode, Decode)]
enum ServerMessage<Block: BlockT, ProtocolRequest> {
    /// Initial message, to be handled both by the client
    /// and the protocol
    InitialRequest(InitialRequest<Block, ProtocolRequest>),

    /// Message to be handled by the protocol
    ProtocolRequest(ProtocolRequest),

    /// Full download request.
    FullDownloadRequest(FullDownloadRequest<Block>),
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
    /// Downloads the requested block from the peer using the relay protocol.
    async fn download(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<Vec<BlockData<Block>>, RelayError> {
        let start_ts = Instant::now();
        let network_peer_handle = self
            .network
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
            .request::<_, InitialResponse<Block, ProtoClient::Response>>(
                ServerMessage::InitialRequest(initial_request),
            )
            .await?;

        // Resolve the protocol response to get the extrinsics
        let (body, local_miss) = if let Some(protocol_response) = initial_response.protocol_response
        {
            let (body, local_miss) = self
                .resolve_extrinsics::<ServerMessage<Block, ProtoClient::Request>>(
                    protocol_response,
                    &network_peer_handle,
                )
                .await?;
            (Some(body), local_miss)
        } else {
            (None, 0)
        };

        // Assemble the final response
        let downloaded = vec![initial_response.partial_block.block_data(body)];
        debug!(
            target: LOG_TARGET,
            block_hash = ?initial_response.block_hash,
            download_bytes = %downloaded.encoded_size(),
            %local_miss,
            duration = ?start_ts.elapsed(),
            "block_download",
        );
        Ok(downloaded)
    }

    /// Downloads the requested blocks from the peer, without using the relay protocol.
    async fn full_download(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<Vec<BlockData<Block>>, RelayError> {
        let start_ts = Instant::now();
        let network_peer_handle = self
            .network
            .network_peer_handle(self.protocol_name.clone(), who)?;

        let server_request: ServerMessage<Block, ProtoClient::Request> =
            ServerMessage::FullDownloadRequest(FullDownloadRequest(request.clone()));
        let full_response = network_peer_handle
            .request::<_, FullDownloadResponse<Block>>(server_request)
            .await?;
        let downloaded = full_response.0;

        debug!(
            target: LOG_TARGET,
            ?request,
            download_blocks =  %downloaded.len(),
            download_bytes = %downloaded.encoded_size(),
            duration = ?start_ts.elapsed(),
            "full_download",
        );
        Ok(downloaded)
    }

    /// Resolves the extrinsics from the initial response
    async fn resolve_extrinsics<Request>(
        &self,
        protocol_response: ProtoClient::Response,
        network_peer_handle: &NetworkPeerHandle,
    ) -> Result<(Vec<Extrinsic<Block>>, usize), RelayError>
    where
        Request: From<ProtoClient::Request> + Encode + Send + Sync,
    {
        let (block_hash, resolved) = self
            .protocol_client
            .resolve_initial_response::<Request>(protocol_response, network_peer_handle)
            .await?;
        let mut local_miss = 0;
        let extrinsics = resolved
            .into_iter()
            .map(|entry| {
                let encoded = entry.protocol_unit.encode();
                if !entry.locally_resolved {
                    trace!(
                        target: LOG_TARGET,
                        ?block_hash,
                        tx_hash = ?entry.protocol_unit_id,
                        tx_size = %encoded.len(),
                        "resolve_extrinsics: local miss"
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
        let full_download = request.max.map_or(false, |max_blocks| max_blocks > 1);
        let ret = if full_download {
            self.full_download(who, request.clone()).await
        } else {
            self.download(who, request.clone()).await
        };
        match ret {
            Ok(blocks) => Ok(Ok(blocks.encode())),
            Err(error) => {
                debug!(
                    target: LOG_TARGET,
                    peer=?who,
                    ?request,
                    ?error,
                    "download_block failed"
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
        Decode::decode(&mut response.as_ref()).map_err(|err| {
            BlockResponseError::DecodeFailed(format!(
                "Failed to decode consensus response: {err:?}"
            ))
        })
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
    request_receiver: async_channel::Receiver<IncomingRequest>,
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
                        ?peer,
                        ?err,
                        "Decode failed"
                    );
                    return;
                }
            };

        let ret = match server_msg {
            ServerMessage::InitialRequest(req) => self.on_initial_request(req),
            ServerMessage::ProtocolRequest(req) => self.on_protocol_request(req),
            ServerMessage::FullDownloadRequest(req) => self.on_full_download_request(req),
        };

        match ret {
            Ok(response) => {
                self.send_response(peer, response, pending_response);
                trace!(
                    target: LOG_TARGET,
                    ?peer,
                    "server: request processed from"
                );
            }
            Err(error) => {
                debug!(
                    target: LOG_TARGET,
                    ?peer,
                    ?error,
                    "Server error"
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

    /// Handles the full download request from the client
    fn on_full_download_request(
        &mut self,
        full_download_request: FullDownloadRequest<Block>,
    ) -> Result<Vec<u8>, RelayError> {
        let block_request = full_download_request.0;
        let mut blocks = Vec::new();
        let mut block_id = match block_request.from {
            FromBlock::Hash(h) => BlockId::<Block>::Hash(h),
            FromBlock::Number(n) => BlockId::<Block>::Number(n),
        };

        // This is a compact length encoding of max number of blocks to be sent in response
        let mut total_size = Compact::compact_len(&MAX_RESPONSE_BLOCKS.get());
        let max_blocks = block_request.max.map_or(MAX_RESPONSE_BLOCKS.into(), |val| {
            std::cmp::min(val, MAX_RESPONSE_BLOCKS.into())
        });
        while blocks.len() < max_blocks as usize {
            let block_hash = self.block_hash(&block_id)?;
            let partial_block = self.get_partial_block(&block_hash, block_request.fields)?;
            let body = if block_request.fields.contains(BlockAttributes::BODY) {
                Some(block_transactions(&block_hash, self.client.as_ref())?)
            } else {
                None
            };
            let block_number = partial_block.block_number;
            let parent_hash = partial_block.parent_hash;
            let block_data = partial_block.block_data(body);

            // Enforce the max limit on response size.
            let bytes = block_data.encoded_size();
            if !blocks.is_empty() && (total_size + bytes) > MAX_RESPONSE_SIZE.into() {
                break;
            }
            total_size += bytes;
            blocks.push(block_data);

            block_id = match block_request.direction {
                Direction::Ascending => BlockId::Number(block_number + One::one()),
                Direction::Descending => {
                    if block_number.is_zero() {
                        break;
                    }
                    BlockId::Hash(parent_hash)
                }
            };
        }

        Ok(blocks.encode())
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
        let parent_hash = *block_header.parent_hash();
        let block_number = *block_header.number();
        let block_header_hash = block_header.hash();

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
            parent_hash,
            block_number,
            block_header_hash,
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
                ?peer,
                "Failed to send response"
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
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
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
    }
}

impl<Block, Client, Pool> ProtocolBackend<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>
    for ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    fn download_unit_members(
        &self,
        block_hash: &BlockHash<Block>,
    ) -> Result<Vec<ProtocolUnitInfo<TxHash<Pool>, Extrinsic<Block>>>, RelayError> {
        let txns = block_transactions(block_hash, self.client.as_ref())?;
        Ok(txns
            .into_iter()
            .map(|extrinsic| {
                let send_tx = extrinsic.encoded_size() <= TX_SIZE_THRESHOLD.get()
                    || self
                        .client
                        .runtime_api()
                        .is_inherent(*block_hash, &extrinsic)
                        .unwrap_or(false);
                ProtocolUnitInfo {
                    id: self.transaction_pool.hash_of(&extrinsic),
                    unit: if send_tx { Some(extrinsic) } else { None },
                }
            })
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
                    ?tx_hash,
                    ?block_hash,
                    %len,
                    "protocol_unit",
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

/// Retrieves the block transactions/tx hash from the backend.
fn block_transactions<Block, Client>(
    block_hash: &BlockHash<Block>,
    client: &Client,
) -> Result<Vec<Extrinsic<Block>>, RelayError>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    let maybe_extrinsics = client
        .block_body(*block_hash)
        .map_err(|err| RelayError::BlockBody(format!("{block_hash:?}, {err:?}")))?;
    maybe_extrinsics.ok_or(RelayError::BlockExtrinsicsNotFound(format!(
        "{block_hash:?}"
    )))
}

/// Sets up the relay components.
pub fn build_consensus_relay<Block, Client, Pool>(
    network: Arc<NetworkWrapper>,
    client: Arc<Client>,
    pool: Arc<Pool>,
    spawn_handle: SpawnTaskHandle,
) -> BlockRelayParams<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    let (tx, request_receiver) = async_channel::bounded(NUM_PEER_HINT.get());

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
