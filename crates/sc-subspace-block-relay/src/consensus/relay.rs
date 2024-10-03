//! Consensus block relay implementation.

use crate::consensus::types::{
    BlockHash, ConsensusClientMetrics, ConsensusRequest, ConsensusServerMetrics, Extrinsic,
    FullDownloadRequest, FullDownloadResponse, InitialRequest, InitialResponse, PartialBlock,
    ProtocolInitialRequest, ProtocolInitialResponse, ProtocolMessage,
};
use crate::protocol::compact_block::{
    CompactBlockClient, CompactBlockHandshake, CompactBlockServer,
};
use crate::protocol::{ClientBackend, ProtocolUnitInfo, ServerBackend};
use crate::types::{RelayError, RequestResponseErr};
use crate::utils::{NetworkPeerHandle, NetworkWrapper};
use crate::LOG_TARGET;
use async_trait::async_trait;
use codec::{Compact, CompactLen, Decode, Encode};
use futures::channel::oneshot;
use futures::stream::StreamExt;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_network::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use sc_network::types::ProtocolName;
use sc_network::{NetworkWorker, OutboundFailure, PeerId, RequestFailure};
use sc_network_common::sync::message::{
    BlockAttributes, BlockData, BlockRequest, Direction, FromBlock,
};
use sc_network_sync::block_relay_protocol::{
    BlockDownloader, BlockRelayParams, BlockResponseError, BlockServer,
};
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TxHash};
use sp_api::ProvideRuntimeApi;
use sp_consensus_subspace::SubspaceApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, One, Zero};
use std::fmt;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::PublicKey;
use substrate_prometheus_endpoint::{PrometheusError, Registry};
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
struct ConsensusRelayClient<Block, Pool>
where
    Block: BlockT,
    Pool: TransactionPool,
{
    network: Arc<NetworkWrapper>,
    protocol_name: ProtocolName,
    compact_block: CompactBlockClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
    backend: Arc<ConsensusClientBackend<Pool>>,
    metrics: ConsensusClientMetrics,
    _phantom_data: std::marker::PhantomData<(Block, Pool)>,
}

impl<Block, Pool> fmt::Debug for ConsensusRelayClient<Block, Pool>
where
    Block: BlockT,
    Pool: TransactionPool,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusRelayClient")
            .field("protocol_name", &self.protocol_name)
            .finish_non_exhaustive()
    }
}

impl<Block, Pool> ConsensusRelayClient<Block, Pool>
where
    Block: BlockT,
    Pool: TransactionPool<Block = Block> + 'static,
{
    /// Creates the consensus relay client.
    fn new(
        network: Arc<NetworkWrapper>,
        protocol_name: ProtocolName,
        compact_block: CompactBlockClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
        backend: Arc<ConsensusClientBackend<Pool>>,
        metrics: ConsensusClientMetrics,
    ) -> Self {
        Self {
            network,
            protocol_name,
            compact_block,
            backend,
            metrics,
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
            protocol_request: ProtocolInitialRequest::from(
                self.compact_block
                    .build_initial_request(self.backend.as_ref()),
            ),
        };
        let initial_response = network_peer_handle
            .request::<_, InitialResponse<Block, TxHash<Pool>>>(ConsensusRequest::<
                Block,
                TxHash<Pool>,
            >::from(initial_request))
            .await?;

        // Resolve the protocol response to get the extrinsics
        let (body, local_miss) = if let Some(protocol_response) = initial_response.protocol_response
        {
            let (body, local_miss) = self
                .resolve_extrinsics::<ConsensusRequest<Block, TxHash<Pool>>>(
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

        let server_request =
            ConsensusRequest::<Block, TxHash<Pool>>::from(FullDownloadRequest(request.clone()));
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
        protocol_response: ProtocolInitialResponse<Block, TxHash<Pool>>,
        network_peer_handle: &NetworkPeerHandle,
    ) -> Result<(Vec<Extrinsic<Block>>, usize), RelayError>
    where
        Request: From<CompactBlockHandshake<BlockHash<Block>, TxHash<Pool>>> + Encode + Send + Sync,
    {
        let ProtocolInitialResponse::CompactBlock(compact_response) = protocol_response;
        let (block_hash, resolved) = self
            .compact_block
            .resolve_initial_response::<Request>(
                compact_response,
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
                    self.metrics.tx_pool_miss.inc();
                    local_miss += encoded.len();
                }
                entry.protocol_unit
            })
            .collect();
        Ok((extrinsics, local_miss))
    }
}

#[async_trait]
impl<Block, Pool> BlockDownloader<Block> for ConsensusRelayClient<Block, Pool>
where
    Block: BlockT,
    Pool: TransactionPool<Block = Block> + 'static,
{
    fn protocol_name(&self) -> &ProtocolName {
        &self.protocol_name
    }

    async fn download_blocks(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<Result<(Vec<u8>, ProtocolName), RequestFailure>, oneshot::Canceled> {
        let full_download = request.max.map_or(false, |max_blocks| max_blocks > 1);
        let ret = if full_download {
            self.full_download(who, request.clone()).await
        } else {
            self.download(who, request.clone()).await
        };
        match ret {
            Ok(blocks) => {
                self.metrics.on_download::<Block>(&blocks);
                Ok(Ok((blocks.encode(), self.protocol_name.clone())))
            }
            Err(error) => {
                debug!(
                    target: LOG_TARGET,
                    peer=?who,
                    ?request,
                    ?error,
                    "download_block failed"
                );
                self.metrics.on_download_fail(&error);
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
struct ConsensusRelayServer<Block: BlockT, Client, Pool: TransactionPool> {
    client: Arc<Client>,
    compact_block: CompactBlockServer<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
    request_receiver: async_channel::Receiver<IncomingRequest>,
    backend: Arc<ConsensusServerBackend<Client, Pool>>,
    metrics: ConsensusServerMetrics,
    _block: std::marker::PhantomData<Block>,
}

impl<Block, Client, Pool> ConsensusRelayServer<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, PublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    /// Creates the consensus relay server.
    fn new(
        client: Arc<Client>,
        compact_block: CompactBlockServer<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>,
        request_receiver: async_channel::Receiver<IncomingRequest>,
        backend: Arc<ConsensusServerBackend<Client, Pool>>,
        metrics: ConsensusServerMetrics,
    ) -> Self {
        Self {
            client,
            compact_block,
            request_receiver,
            backend,
            metrics,
            _block: Default::default(),
        }
    }

    /// Handles the received request from the client side
    async fn process_incoming_request(&mut self, request: IncomingRequest) {
        // Drop the request in case of errors and let the client time out.
        // This is the behavior of the current substrate block handler.
        let IncomingRequest {
            peer,
            payload,
            pending_response,
        } = request;
        let req: ConsensusRequest<Block, TxHash<Pool>> = match Decode::decode(&mut payload.as_ref())
        {
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

        let ret = match req {
            ConsensusRequest::BlockDownloadV0(req) => {
                self.on_initial_request(req).map(|rsp| rsp.encode())
            }
            ConsensusRequest::ProtocolMessageV0(msg) => self.on_protocol_message(msg),
            ConsensusRequest::FullBlockDownloadV0(req) => {
                self.on_full_download_request(req).map(|rsp| rsp.encode())
            }
        };

        match ret {
            Ok(response) => {
                self.metrics.on_request();
                self.send_response(peer, response, pending_response);
                trace!(
                    target: LOG_TARGET,
                    ?peer,
                    "server: request processed from"
                );
            }
            Err(error) => {
                self.metrics.on_failed_request(&error);
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
        initial_request: InitialRequest<Block>,
    ) -> Result<InitialResponse<Block, TxHash<Pool>>, RelayError> {
        let block_hash = self.block_hash(&initial_request.from_block)?;
        let block_attributes = initial_request.block_attributes;

        // Build the generic and the protocol specific parts of the response
        let partial_block = self.get_partial_block(&block_hash, block_attributes)?;
        let ProtocolInitialRequest::CompactBlock(compact_request) =
            initial_request.protocol_request;
        let protocol_response = if block_attributes.contains(BlockAttributes::BODY) {
            let compact_response = self.compact_block.build_initial_response(
                &block_hash,
                compact_request,
                self.backend.as_ref(),
            )?;
            Some(ProtocolInitialResponse::from(compact_response))
        } else {
            None
        };

        Ok(InitialResponse {
            block_hash,
            partial_block,
            protocol_response,
        })
    }

    /// Handles the protocol message from the client
    fn on_protocol_message(
        &mut self,
        msg: ProtocolMessage<Block, TxHash<Pool>>,
    ) -> Result<Vec<u8>, RelayError> {
        let response = match msg {
            ProtocolMessage::CompactBlock(msg) => self
                .compact_block
                .on_protocol_message(msg, self.backend.as_ref())?
                .encode(),
        };
        Ok(response)
    }

    /// Handles the full download request from the client
    fn on_full_download_request(
        &mut self,
        full_download_request: FullDownloadRequest<Block>,
    ) -> Result<FullDownloadResponse<Block>, RelayError> {
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

        Ok(FullDownloadResponse(blocks))
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
impl<Block, Client, Pool> BlockServer<Block> for ConsensusRelayServer<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, PublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    async fn run(&mut self) {
        info!(
            target: LOG_TARGET,
            "relay::consensus block server: starting"
        );
        while let Some(request) = self.request_receiver.next().await {
            self.process_incoming_request(request).await;
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
    Client::Api: SubspaceApi<Block, PublicKey>,
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

#[derive(Debug, thiserror::Error)]
pub enum BlockRelayConfigurationError {
    #[error(transparent)]
    PrometheusError(#[from] PrometheusError),
}

/// Sets up the relay components.
pub fn build_consensus_relay<Block, Client, Pool>(
    network: Arc<NetworkWrapper>,
    client: Arc<Client>,
    pool: Arc<Pool>,
    registry: Option<&Registry>,
) -> Result<
    BlockRelayParams<Block, NetworkWorker<Block, <Block as BlockT>::Hash>>,
    BlockRelayConfigurationError,
>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: SubspaceApi<Block, PublicKey>,
    Pool: TransactionPool<Block = Block> + 'static,
{
    let (tx, request_receiver) = async_channel::bounded(NUM_PEER_HINT.get());

    let backend = Arc::new(ConsensusClientBackend {
        transaction_pool: pool.clone(),
    });
    let metrics = ConsensusClientMetrics::new(registry)
        .map_err(BlockRelayConfigurationError::PrometheusError)?;
    let relay_client: ConsensusRelayClient<Block, Pool> = ConsensusRelayClient::new(
        network,
        SYNC_PROTOCOL.into(),
        CompactBlockClient::new(),
        backend,
        metrics,
    );

    let backend = Arc::new(ConsensusServerBackend {
        client: client.clone(),
        transaction_pool: pool.clone(),
    });
    let metrics = ConsensusServerMetrics::new(registry)
        .map_err(BlockRelayConfigurationError::PrometheusError)?;
    let relay_server = ConsensusRelayServer::new(
        client,
        CompactBlockServer::new(),
        request_receiver,
        backend,
        metrics,
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

    Ok(BlockRelayParams {
        server: Box::new(relay_server),
        downloader: Arc::new(relay_client),
        request_response_config: protocol_config,
    })
}
