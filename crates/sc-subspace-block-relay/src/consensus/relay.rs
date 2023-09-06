//! Consensus block relay implementation.

use crate::consensus::types::{
    BlockHash, BlockResponse, Extrinsic, FullDownloadRequest, FullDownloadResponse, InitialRequest,
    InitialResponse, MessageBody, MessagePrefix, PartialBlock, ServerMessage, ServerMessageDecoder,
};
use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::protocol::{
    ClientBackend, ProtocolClient, ProtocolServer, ProtocolUnitInfo, ServerBackend,
};
use crate::types::{RelayError, RelayVersion, RequestResponseErr, VersionEncodable};
use crate::utils::{NetworkPeerHandle, NetworkWrapper};
use crate::LOG_TARGET;
use async_trait::async_trait;
use codec::{Compact, CompactLen, Decode, Encode, Input};
use futures::channel::oneshot;
use futures::stream::StreamExt;
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
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_api::ProvideRuntimeApi;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, One, Zero};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

const SYNC_PROTOCOL: &str = "/subspace/consensus-block-relay/1";

// TODO: size these properly, or move to config
const NUM_PEER_HINT: NonZeroUsize = NonZeroUsize::new(100).expect("Not zero; qed");

/// These are the same limits used by substrate block handler.
/// Maximum response size (bytes).
const MAX_RESPONSE_SIZE: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("Not zero; qed");
/// Maximum blocks in the response.
const MAX_RESPONSE_BLOCKS: NonZeroU32 = NonZeroU32::new(128).expect("Not zero; qed");

/// If the encoded size of the extrinsic is less than the threshold,
/// return the full extrinsic along with the tx hash.
const TX_SIZE_THRESHOLD: NonZeroUsize = NonZeroUsize::new(32).expect("Not zero; qed");

/// The client side of the consensus block relay
struct ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool,
    ProtoClient: ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
{
    network: Arc<NetworkWrapper>,
    protocol_name: ProtocolName,
    protocol_version: RelayVersion,
    protocol: Arc<ProtoClient>,
    backend: Arc<ConsensusClientBackend<Pool>>,
    _phantom_data: std::marker::PhantomData<(Block, Pool)>,
}

impl<Block, Pool, ProtoClient> ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool<Block = Block> + 'static,
    ProtoClient: ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
{
    /// Creates the consensus relay client.
    fn new(
        network: Arc<NetworkWrapper>,
        protocol_name: ProtocolName,
        protocol: Arc<ProtoClient>,
        backend: Arc<ConsensusClientBackend<Pool>>,
    ) -> Self {
        Self {
            network,
            protocol_name,
            protocol_version: protocol.version(),
            protocol,
            backend,
            _phantom_data: Default::default(),
        }
    }

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
            protocol_request: self.protocol.build_initial_request(self.backend.as_ref()),
        };
        let initial_response = network_peer_handle
            .request::<_, InitialResponse<Block, ProtoClient::Response>>(
                ServerMessage::InitialRequest(initial_request),
                self.protocol_version,
            )
            .await?;

        let (block_data, local_miss) = match initial_response.response {
            BlockResponse::Partial(partial_block, protocol_response) => {
                // Resolve the protocol response to get the extrinsics.
                let (body, miss) = self
                    .resolve_extrinsics::<ServerMessage<Block, ProtoClient::Request>>(
                        protocol_response,
                        &network_peer_handle,
                    )
                    .await?;
                (partial_block.block_data(body), miss)
            }
            BlockResponse::Complete(block_data) => {
                debug!(
                    target: LOG_TARGET,
                    version = ?self.protocol_version,
                    block_hash = ?initial_response.block_hash,
                    "download: received full block",
                );
                (block_data, 0)
            }
        };

        // Assemble the final response
        let downloaded = vec![block_data];
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
            .request::<_, FullDownloadResponse<Block>>(server_request, self.protocol_version)
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
        protocol_response: Option<ProtoClient::Response>,
        network_peer_handle: &NetworkPeerHandle,
    ) -> Result<(Option<Vec<Extrinsic<Block>>>, usize), RelayError>
    where
        Request: From<ProtoClient::Request> + VersionEncodable + Send + Sync,
    {
        let protocol_response = if let Some(protocol_response) = protocol_response {
            protocol_response
        } else {
            return Ok((None, 0));
        };

        let (block_hash, resolved) = self
            .protocol
            .resolve_initial_response::<Request>(
                protocol_response,
                network_peer_handle,
                self.backend.as_ref(),
            )
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
        Ok((Some(extrinsics), local_miss))
    }
}

#[async_trait]
impl<Block, Pool, ProtoClient> BlockDownloader<Block>
    for ConsensusRelayClient<Block, Pool, ProtoClient>
where
    Block: BlockT,
    Pool: TransactionPool<Block = Block> + 'static,
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
struct ConsensusRelayServer<Block: BlockT, Client, Pool, ProtoServer> {
    client: Arc<Client>,
    protocol_version: RelayVersion,
    protocol: Box<ProtoServer>,
    request_receiver: async_channel::Receiver<IncomingRequest>,
    backend: Arc<ConsensusServerBackend<Client, Pool>>,
    _block: std::marker::PhantomData<Block>,
}

impl<Block, Client, Pool, ProtoServer> ConsensusRelayServer<Block, Client, Pool, ProtoServer>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
    ProtoServer: ProtocolServer<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>> + Send,
{
    /// Creates the consensus relay server.
    fn new(
        client: Arc<Client>,
        protocol: Box<ProtoServer>,
        request_receiver: async_channel::Receiver<IncomingRequest>,
        backend: Arc<ConsensusServerBackend<Client, Pool>>,
    ) -> Self {
        Self {
            client,
            protocol_version: protocol.version(),
            protocol,
            request_receiver,
            backend,
            _block: Default::default(),
        }
    }

    /// Handles the received request from the client side
    async fn on_request(&mut self, request: IncomingRequest) {
        // Drop the request in case of errors and let the client time out.
        // This is the behavior of the current substrate block handler.
        let IncomingRequest {
            peer,
            payload,
            pending_response,
        } = request;
        let mut decoder = ServerMessageDecoder::new(payload.as_slice());
        let prefix: MessagePrefix<Block> = match decoder.prefix() {
            Ok(prefix) => prefix,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    ?peer,
                    ?err,
                    "Prefix decode failed"
                );
                return;
            }
        };

        let ret = match prefix {
            MessagePrefix::InitialRequest(version, from_block, block_attributes) => {
                self.on_initial_request(version, from_block, block_attributes, &mut decoder)
            }
            MessagePrefix::ProtocolRequest(version) => {
                self.on_protocol_request(version, &mut decoder)
            }
            MessagePrefix::FullDownloadRequest(req) => self.on_full_download_request(req),
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
    fn on_initial_request<I: Input>(
        &mut self,
        version: RelayVersion,
        from_block: BlockId<Block>,
        block_attributes: BlockAttributes,
        decoder: &mut ServerMessageDecoder<I>,
    ) -> Result<Vec<u8>, RelayError> {
        let block_hash = self.block_hash(&from_block)?;
        if version != self.protocol_version {
            debug!(
                target: LOG_TARGET,
                client_version = ?version,
                server_version = ?self.protocol_version,
                ?block_hash,
                "initial request: version mismatch, sending full block",
            );
            return self.handle_version_mismatch(&block_hash, block_attributes);
        }

        // Same version, decode the body.
        let body = decoder.body::<ProtoServer::Request>()?;
        let protocol_request = if let MessageBody::InitialRequest(req) = body {
            req
        } else {
            return Err(RelayError::UnexpectedProtocolRequest);
        };

        // Build the generic and the protocol specific parts of the response
        let partial_block = self.get_partial_block(&block_hash, block_attributes)?;
        let protocol_response = if block_attributes.contains(BlockAttributes::BODY) {
            Some(self.protocol.build_initial_response(
                &block_hash,
                protocol_request,
                self.backend.as_ref(),
            )?)
        } else {
            None
        };

        let initial_response: InitialResponse<Block, ProtoServer::Response> = InitialResponse {
            block_hash,
            response: BlockResponse::Partial(partial_block, protocol_response),
        };
        Ok(initial_response.encode())
    }

    /// Handles the protocol request from the client
    fn on_protocol_request<I: Input>(
        &mut self,
        version: RelayVersion,
        decoder: &mut ServerMessageDecoder<I>,
    ) -> Result<Vec<u8>, RelayError> {
        if version != self.protocol_version {
            return Err(RelayError::UnsupportedVersion {
                expected: self.protocol_version,
                actual: version,
            });
        }

        // Same version, decode the body.
        let body = decoder.body::<ProtoServer::Request>()?;
        let request = if let MessageBody::ProtocolRequest(req) = body {
            req
        } else {
            return Err(RelayError::UnexpectedProtocolRequest);
        };

        let response = self.protocol.on_request(request, self.backend.as_ref())?;
        Ok(response.encode())
    }

    /// Handles the full download request from the client
    fn on_full_download_request(
        &mut self,
        block_request: BlockRequest<Block>,
    ) -> Result<Vec<u8>, RelayError> {
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

    /// Handles version mismatch detected when the initial request
    /// was received.
    fn handle_version_mismatch(
        &self,
        block_hash: &BlockHash<Block>,
        block_attributes: BlockAttributes,
    ) -> Result<Vec<u8>, RelayError> {
        // Return full block on version mismatch.
        let partial_block = self.get_partial_block(block_hash, block_attributes)?;
        let body = if block_attributes.contains(BlockAttributes::BODY) {
            Some(block_transactions(block_hash, self.client.as_ref())?)
        } else {
            None
        };
        let initial_response: InitialResponse<Block, ProtoServer::Response> = InitialResponse {
            block_hash: *block_hash,
            response: BlockResponse::Complete(partial_block.block_data(body)),
        };
        Ok(initial_response.encode())
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
impl<Block, Client, Pool, ProtoServer> BlockServer<Block>
    for ConsensusRelayServer<Block, Client, Pool, ProtoServer>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
    ProtoServer: ProtocolServer<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>> + Send,
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

/// The client backend.
struct ConsensusClientBackend<Pool> {
    transaction_pool: Arc<Pool>,
}

impl<Block, Pool> ClientBackend<TxHash<Pool>, Extrinsic<Block>> for ConsensusClientBackend<Pool>
where
    Block: BlockT,
    Pool: TransactionPool<Block = Block> + 'static,
{
    fn protocol_unit(&self, tx_hash: &TxHash<Pool>) -> Option<Extrinsic<Block>> {
        // Look up the transaction pool.
        self.transaction_pool
            .ready_transaction(tx_hash)
            .map(|in_pool_tx| in_pool_tx.data().clone())
    }
}

/// The server backend.
struct ConsensusServerBackend<Client, Pool> {
    client: Arc<Client>,
    transaction_pool: Arc<Pool>,
}

impl<Block, Client, Pool> ServerBackend<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>
    for ConsensusServerBackend<Client, Pool>
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
    ) -> Option<Extrinsic<Block>> {
        // Look up the block extrinsics.
        match block_transactions(block_hash, self.client.as_ref()) {
            Ok(extrinsics) => {
                for extrinsic in extrinsics {
                    if self.transaction_pool.hash_of(&extrinsic) == *tx_hash {
                        return Some(extrinsic);
                    }
                }
            }
            Err(err) => {
                debug!(
                    target: LOG_TARGET,
                    ?block_hash,
                    ?tx_hash,
                    ?err,
                    "consensus server protocol_unit: "
                );
            }
        }

        // Next look up the transaction pool.
        self.transaction_pool
            .ready_transaction(tx_hash)
            .map(|in_pool_tx| in_pool_tx.data().clone())
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
) -> BlockRelayParams<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    let (tx, request_receiver) = async_channel::bounded(NUM_PEER_HINT.get());

    let backend = Arc::new(ConsensusClientBackend {
        transaction_pool: pool.clone(),
    });
    let relay_client: ConsensusRelayClient<Block, Pool, _> = ConsensusRelayClient::new(
        network,
        SYNC_PROTOCOL.into(),
        Arc::new(CompactBlockClient::new()),
        backend,
    );

    let backend = Arc::new(ConsensusServerBackend {
        client: client.clone(),
        transaction_pool: pool.clone(),
    });
    let relay_server = ConsensusRelayServer::new(
        client,
        Box::new(CompactBlockServer::new()),
        request_receiver,
        backend,
    );

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
