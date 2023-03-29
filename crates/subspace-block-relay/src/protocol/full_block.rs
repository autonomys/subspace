//! Implementation of the full block protocol.

use crate::protocol::{BlockInfo, BlockRelayProtocol, GossipNetworkService, ProtocolResponse};
use crate::LOG_TARGET;
use async_trait::async_trait;
use futures::channel::mpsc::{self, Receiver};
use futures::channel::oneshot;
use futures::future::pending;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::IncomingBlock;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network::{IfDisconnected, NetworkRequest, PeerId};
use sc_network_common::config::NonDefaultSetConfig;
use sc_network_gossip::{
    GossipEngine, MessageIntent, TopicNotification, ValidationResult, Validator, ValidatorContext,
};
use sc_service::config::{IncomingRequest, OutgoingResponse, RequestResponseConfig};
use sc_service::Configuration;
use sp_consensus::BlockOrigin;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::HashSet;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

const ANNOUNCE_PROTOCOL: &str = "/subspace/full-block-relay-announces/1";
const SYNC_PROTOCOL: &str = "/subspace/full-block-relay-sync/1";

/// TODO: tentative size, to be tuned based on testing.
const INBOUND_QUEUE_SIZE: usize = 1024;

type ProtocolResponseFuture<Block> =
    dyn Future<Output = ProtocolResponse<BlockRequest<Block>>> + Send;

/// The gossiped block announcement.
#[derive(Clone, Encode, Decode)]
struct BlockAnnouncement<Block: BlockT>(BlockInfo<Block>);

impl<Block: BlockT> From<&ImportedBlockNotification<Block>> for BlockAnnouncement<Block> {
    fn from(import_notification: &ImportedBlockNotification<Block>) -> Self {
        Self(import_notification.into())
    }
}

impl<Block: BlockT> fmt::Display for BlockAnnouncement<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockAnnouncement::{}", self.0)
    }
}

/// The block download request.
#[derive(Clone, Encode, Decode)]
struct BlockRequest<Block: BlockT>(BlockInfo<Block>);

impl<Block: BlockT> From<&BlockAnnouncement<Block>> for BlockRequest<Block> {
    fn from(announcement: &BlockAnnouncement<Block>) -> Self {
        Self(announcement.0.clone())
    }
}

impl<Block: BlockT> fmt::Display for BlockRequest<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockRequest::{}", self.0)
    }
}

/// The block download response.
#[derive(Debug, Encode, Decode)]
struct BlockResponse<Block: BlockT>(SignedBlock<Block>);

impl<Block: BlockT> fmt::Display for BlockResponse<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockResponse[hash = {}, size_hint = {}]",
            self.0.block.hash(),
            self.0.block.size_hint()
        )
    }
}

pub struct FullBlockRelay<Block: BlockT, Client> {
    /// Network handle.
    network: Arc<GossipNetworkService<Block>>,

    /// Block backend.
    client: Arc<Client>,

    /// The import queue for the downloaded blocks.
    import_queue: Box<dyn ImportQueueService<Block>>,

    /// Announcement gossip engine.
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,

    /// Announcement gossip validator.
    _validator: Arc<FullBlockRelayValidator>,

    /// Announcements in the process of being sent.
    pending_announcements: Arc<Mutex<HashSet<Vec<u8>>>>,

    /// Block downloads in progress.
    pending_downloads: HashSet<BlockInfo<Block>>,

    /// Requests waiting for responses from peers.
    pending_responses: FuturesUnordered<Pin<Box<ProtocolResponseFuture<Block>>>>,
}

impl<Block, Client> FullBlockRelay<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
{
    pub(crate) fn new(
        network: Arc<GossipNetworkService<Block>>,
        client: Arc<Client>,
        import_queue: Box<dyn ImportQueueService<Block>>,
    ) -> (Self, Arc<Mutex<GossipEngine<Block>>>) {
        let pending_announcements = Arc::new(Mutex::new(HashSet::new()));
        let validator = Arc::new(FullBlockRelayValidator {
            pending_announcements: pending_announcements.clone(),
        });
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network.clone(),
            ANNOUNCE_PROTOCOL,
            validator.clone(),
            None,
        )));

        let protocol = Self {
            network,
            client,
            import_queue,
            gossip_engine: gossip_engine.clone(),
            _validator: validator,
            pending_announcements,
            pending_downloads: HashSet::new(),
            pending_responses: Default::default(),
        };
        // FuturesUnordered has the issue where polling of an empty collection returns
        // Poll::Ready(None). This causes a busy loop from the runner, and doesn't let anything else
        // run. To avoid this, initialize the collection with a future that never completes.
        protocol
            .pending_responses
            .push(Box::pin(pending::<ProtocolResponse<BlockRequest<Block>>>()));
        (protocol, gossip_engine)
    }

    /// Initiates the block download request.
    fn start_block_download(&mut self, sender: PeerId, announcement: &BlockAnnouncement<Block>) {
        if self.pending_downloads.contains(&announcement.0) {
            return;
        }
        self.pending_downloads.insert(announcement.0.clone());

        let block_request: BlockRequest<Block> = announcement.into();
        let (tx, rx) = oneshot::channel();
        let request_ts = Instant::now();
        self.network.start_request(
            sender,
            SYNC_PROTOCOL.into(),
            block_request.encode(),
            tx,
            IfDisconnected::ImmediateError,
        );
        self.pending_responses.push(Box::pin(async move {
            ProtocolResponse {
                peer_id: sender,
                request_id: block_request,
                response: rx.await.ok(),
                request_ts,
            }
        }));
    }

    /// Processes the block download response.
    async fn on_block_download_response(
        &mut self,
        sender: PeerId,
        request: BlockRequest<Block>,
        bytes: Vec<u8>,
        elapsed: Duration,
    ) {
        if !self.pending_downloads.remove(&request.0) {
            warn!(
                target: LOG_TARGET,
                "On response: unknown request: {sender}, {request}, {}",
                bytes.len()
            );
            return;
        }

        let response_len = bytes.len();
        let block_response = match BlockResponse::<Block>::decode(&mut bytes.as_slice()) {
            Ok(block_response) => block_response,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "On response: failed to decode response: {sender}, {request}, {}, {err}",
                    response_len,
                );
                return;
            }
        };

        // Import the downloaded block.
        let response_str = format!("{block_response}");
        self.import_block(sender, block_response.0).await;
        trace!(
            target: LOG_TARGET,
            "On response:: {request}, {response_str}. Block downloaded/imported, \
             {response_len} bytes in {elapsed:?}",
        );
    }

    /// Imports the block.
    async fn import_block(&mut self, sender: PeerId, block: SignedBlock<Block>) {
        let (header, extrinsics) = block.block.deconstruct();
        let hash = header.hash();
        self.import_queue.import_blocks(
            BlockOrigin::ConsensusBroadcast,
            vec![IncomingBlock::<Block> {
                hash,
                header: Some(header),
                body: Some(extrinsics),
                indexed_body: None,
                justifications: block.justifications,
                origin: Some(sender),
                allow_missing_state: false,
                import_existing: false,
                state: None,
                skip_execution: false,
            }],
        );
    }

    /// Sends the response to the block download request.
    async fn send_download_response(
        &mut self,
        incoming: IncomingRequest,
        request: BlockRequest<Block>,
        response: BlockResponse<Block>,
    ) {
        let encoded = response.encode();
        let encoded_len = encoded.len();
        let outgoing = OutgoingResponse {
            result: Ok(encoded),
            reputation_changes: vec![],
            sent_feedback: None,
        };

        if let Err(err) = incoming.pending_response.send(outgoing) {
            warn!(
                target: LOG_TARGET,
                "Send response: Failed to send: {request}, {response}, {encoded_len} bytes, {err:?}",
            );
        } else {
            trace!(
                target: LOG_TARGET,
                "Send response: {request}, {response}, {encoded_len} bytes",
            );
        }
    }

    /// Retrieves the requested block from the backend.
    fn get_backend_block(
        &mut self,
        block_hash: Block::Hash,
    ) -> Result<Option<SignedBlock<Block>>, String> {
        self.client
            .block(block_hash)
            .map_err(|err| format!("Backend block lookup failed: {block_hash}, {err}",))
    }
}

#[async_trait]
impl<Block, Client> BlockRelayProtocol<Block> for FullBlockRelay<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
{
    fn block_announcement_topic(&self) -> Block::Hash {
        topic::<Block>()
    }

    async fn on_block_import(&mut self, notification: ImportedBlockNotification<Block>) {
        // Announce the imported block.
        let announcement: BlockAnnouncement<Block> = (&notification).into();
        let encoded = announcement.encode();
        let should_announce = self.pending_announcements.lock().insert(encoded.clone());
        if should_announce {
            self.gossip_engine
                .lock()
                .gossip_message(topic::<Block>(), encoded, false);
        }
        trace!(
            target: LOG_TARGET,
            "On block import: {notification:?}, {announcement}, announced = {should_announce}",
        );
    }

    async fn on_block_announcement(&mut self, message: TopicNotification) {
        let sender = match message.sender {
            Some(sender) => sender,
            None => return,
        };

        let announcement = match BlockAnnouncement::<Block>::decode(&mut &message.message[..]) {
            Ok(announcement) => announcement,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "On block announcement: failed to decode {message:?}, {err:?}"
                );
                return;
            }
        };

        // Skip the announcement if we already have the block.
        if let Ok(Some(_)) = self.get_backend_block(announcement.0.block_hash) {
            info!(
                target: LOG_TARGET,
                "On block announcement: {announcement}, existing block announced, skipping",
            );
            return;
        }

        // Initiate the block download.
        self.start_block_download(sender, &announcement);
        trace!(
            target: LOG_TARGET,
            "On block announcement: {sender}, {announcement}. Block download initiated",
        );
    }

    async fn on_protocol_message(&mut self, incoming: IncomingRequest) {
        let block_request = match BlockRequest::<Block>::decode(&mut &incoming.payload[..]) {
            Ok(block_request) => block_request,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "On message: Failed to decode: {incoming:?}, {err:?}"
                );
                return;
            }
        };

        let ret = self.get_backend_block(block_request.0.block_hash);
        if let Ok(Some(signed_block)) = ret {
            let block_response = BlockResponse(signed_block);
            self.send_download_response(incoming, block_request, block_response)
                .await;
        } else {
            warn!(
                target: LOG_TARGET,
                "On message: backend fetch failed, {block_request}, {ret:?}"
            );
        }
    }

    async fn poll(&mut self) {
        let protocol_response = match self.pending_responses.next().await {
            Some(protocol_response) => protocol_response,
            None => return,
        };

        if let Some(Ok(response)) = protocol_response.response {
            self.on_block_download_response(
                protocol_response.peer_id,
                protocol_response.request_id,
                response,
                protocol_response.request_ts.elapsed(),
            )
            .await;
        } else {
            warn!(
                target: LOG_TARGET,
                "Poll: download request failed: {:?}, {}, {:?}",
                protocol_response.peer_id,
                protocol_response.request_id,
                protocol_response.response
            );
        }
    }
}

struct FullBlockRelayValidator {
    pending_announcements: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl<Block: BlockT> Validator<Block> for FullBlockRelayValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        // TODO: substrate requires decoding twice, once during validate and again
        // during the processing.
        if let Err(err) = BlockAnnouncement::<Block>::decode(&mut data) {
            warn!(
                target: LOG_TARGET,
                "Validate announcement: {sender}, decode failed: {err:?}"
            );
            ValidationResult::Discard
        } else {
            ValidationResult::ProcessAndKeep(topic::<Block>())
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_, data| !self.pending_announcements.lock().contains(data))
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_, _, _, data| {
            let mut pending_announcements = self.pending_announcements.lock();
            pending_announcements.remove(data)
        })
    }
}

/// Block relay message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(ANNOUNCE_PROTOCOL.as_bytes())
}

/// Initializes the full block relay specific config.
pub(crate) fn init_full_block_config(config: &mut Configuration) -> Receiver<IncomingRequest> {
    let mut cfg = NonDefaultSetConfig::new(ANNOUNCE_PROTOCOL.into(), 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    config.network.extra_sets.push(cfg);

    let (request_sender, request_receiver) = mpsc::channel(INBOUND_QUEUE_SIZE);
    config
        .network
        .request_response_protocols
        .push(RequestResponseConfig {
            name: SYNC_PROTOCOL.into(),
            fallback_names: Vec::new(),
            max_request_size: 1024 * 1024,
            max_response_size: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(60),
            inbound_queue: Some(request_sender),
        });
    request_receiver
}
