//! Relay implementation for consensus blocks.

use crate::protocol::compact_block::{CompactBlockClient, CompactBlockServer};
use crate::utils::{decode_response, NetworkStubImpl, NetworkWrapper, ServerMessage};
use crate::{
    DownloadResult, NetworkStub, ProtocolBackend, ProtocolClient, ProtocolServer, RelayError,
    LOG_TARGET,
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
use sc_network::{PeerId, RequestFailure};
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
struct InitialRequest<Block: BlockT> {
    /// Starting block
    from_block: BlockId<Block>,

    /// Requested block components
    block_attributes: u32,

    /// The opaque protocol specific part of the request
    protocol_request: Option<Vec<u8>>,
}

/// Initial response from server
#[derive(Encode, Decode)]
struct InitialResponse<Block: BlockT> {
    ///  Hash of the block being downloaded
    block_hash: BlockHash<Block>,

    /// The partial block, without the extrinsics
    partial_block: PartialBlock<Block>,

    /// The opaque protocol specific part of the response
    protocol_response: Option<Vec<u8>>,
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

/// The client side of the consensus block relay
struct ConsensusRelayClient<Block: BlockT, Pool: TransactionPool> {
    network: Arc<NetworkWrapper<Block>>,
    protocol_name: ProtocolName,
    protocol_client: Arc<dyn ProtocolClient<BlockHash<Block>, TxHash<Pool>, Extrinsic<Block>>>,
}

impl<Block: BlockT, Pool: TransactionPool> ConsensusRelayClient<Block, Pool> {
    /// Downloads the requested block from the peer using the relay protocol
    async fn download(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<DownloadResult<BlockHash<Block>>, RelayError> {
        let start_ts = Instant::now();
        let network = match self.network.get() {
            Some(network) => network,
            None => {
                return Err(RelayError::Internal(
                    "relay::download: network not initialized".to_string(),
                ));
            }
        };
        let stub = Arc::new(NetworkStubImpl::new(
            self.protocol_name.clone(),
            who,
            network,
        ));

        // Perform the initial request/response
        let initial_request = InitialRequest {
            from_block: match request.from {
                FromBlock::Hash(h) => BlockId::<Block>::Hash(h),
                FromBlock::Number(n) => BlockId::<Block>::Number(n),
            },
            block_attributes: request.fields.to_be_u32(),
            protocol_request: self.protocol_client.build_initial_request(),
        };
        let initial_response: InitialResponse<Block> =
            match decode_response(stub.request_response(initial_request.encode(), false).await) {
                Ok(response) => response,
                Err(err) => return Err(err.into()),
            };

        // Resolve the protocol response to get the extrinsics
        let (body, local_miss) = if let Some(protocol_response) = initial_response.protocol_response
        {
            let (body, local_miss) = self
                .resolve_extrinsics(protocol_response, stub.clone())
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
            download_unit: block_data.encode(),
            latency: start_ts.elapsed(),
            local_miss,
        })
    }

    /// Resolves the extrinsics from the initial response
    async fn resolve_extrinsics(
        &self,
        protocol_response: Vec<u8>,
        stub: Arc<dyn NetworkStub>,
    ) -> Result<(Vec<Extrinsic<Block>>, usize), RelayError> {
        let (block_hash, resolved) = self
            .protocol_client
            .resolve(protocol_response, stub)
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
impl<Block: BlockT, Pool: TransactionPool> BlockDownloader<Block>
    for ConsensusRelayClient<Block, Pool>
{
    async fn download_block(
        &self,
        who: PeerId,
        request: BlockRequest<Block>,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
        let ret = self.download(who, request).await;
        match ret {
            Ok(result) => {
                trace!(
                    target: LOG_TARGET,
                    "relay::download_block: {:?} => {},{},{:?}",
                    result.download_unit_id,
                    result.download_unit.len(),
                    result.local_miss,
                    result.latency
                );
                Ok(Ok(result.download_unit))
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
struct ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    client: Arc<Client>,
    protocol: Box<dyn ProtocolServer<BlockHash<Block>> + Send>,
    request_receiver: mpsc::Receiver<IncomingRequest>,
}

impl<Block, Client> ConsensusRelayServer<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
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
            self.on_initial_request(server_msg.message)
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

    /// Handles the initial request from the client
    fn on_initial_request(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        let initial_request: InitialRequest<Block> = match Decode::decode(&mut msg.as_ref()) {
            Ok(initial_request) => initial_request,
            Err(err) => {
                return Err(RelayError::from(format!(
                    "on_initial_request: decode initial request: {err:?}"
                )))
            }
        };
        let block_hash = self.block_hash(&initial_request.from_block)?;
        let block_attributes = BlockAttributes::from_be_u32(initial_request.block_attributes)
            .map_err(|err| format!("on_initial_request: block attributes: {err:?}"))?;

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

        let initial_response: InitialResponse<Block> = InitialResponse {
            block_hash,
            partial_block,
            protocol_response,
        };
        Ok(initial_response.encode())
    }

    /// Builds the partial block response
    fn get_partial_block(
        &self,
        block_hash: &BlockHash<Block>,
        block_attributes: BlockAttributes,
    ) -> Result<PartialBlock<Block>, RelayError> {
        let block_hdr = match self.client.header(*block_hash) {
            Ok(Some(hdr)) => hdr,
            Ok(None) => {
                return Err(format!("get_partial_block: missing hdr: {block_hash:?}").into())
            }
            Err(err) => {
                return Err(format!("get_partial_block: get hdr: {block_hash:?}, {err:?}").into())
            }
        };
        let hash = block_hdr.hash();

        let header = if block_attributes.contains(BlockAttributes::HEADER) {
            Some(block_hdr)
        } else {
            None
        };

        let indexed_body = if block_attributes.contains(BlockAttributes::INDEXED_BODY) {
            self.client.block_indexed_body(*block_hash).map_err(|err| {
                format!("get_partial_block: block_indexed_body: {block_hash:?}, {err:?}")
            })?
        } else {
            None
        };

        let justifications = if block_attributes.contains(BlockAttributes::JUSTIFICATION) {
            self.client.justifications(*block_hash).map_err(|err| {
                format!("get_partial_block: justifications: {block_hash:?}, {err:?}")
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
            Ok(None) => Err(format!("block_hash: {block_id:?}: None").into()),
            Err(err) => Err(format!("block_hash: {block_id:?}: {err:?}").into()),
        }
    }

    /// Builds/sends the response back to the client
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

/// The backend interface for the consensus block relay
struct ConsensusBackend<Block, Client, Pool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
    Pool: TransactionPool,
{
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
        let transaction_pool_cl = transaction_pool.clone();
        let transaction_cache_cl = transaction_cache.clone();
        spawn_handle.spawn_blocking("block-relay-transaction-import", None, {
            Box::pin(async move {
                while let Some(hash) = transaction_pool_cl
                    .import_notification_stream()
                    .next()
                    .await
                {
                    if let Some(transaction) = transaction_pool_cl.ready_transaction(&hash) {
                        transaction_cache_cl
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
            .map_err(|err| format!("download_unit_members:block_body: {block_hash:?}, {err:?}"))?
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
    network: Arc<NetworkWrapper<Block>>,
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
    let relay_client: ConsensusRelayClient<Block, Pool> = ConsensusRelayClient {
        network,
        protocol_name: SYNC_PROTOCOL.into(),
        protocol_client: Arc::new(CompactBlockClient {
            backend: backend.clone(),
        }),
    };

    let relay_server = ConsensusRelayServer {
        client,
        protocol: Box::new(CompactBlockServer { backend }),
        request_receiver,
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
