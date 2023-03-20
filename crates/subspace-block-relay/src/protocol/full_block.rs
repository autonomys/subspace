//! Implementation of the full block protocol.

use crate::protocol::{BlockRelayProtocol, GossipNetworkService};
use crate::LOG_TARGET;
use async_trait::async_trait;
use futures::channel::mpsc::{self, Receiver};
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
use sp_runtime::generic::{BlockId, SignedBlock};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, trace, warn};

const ANNOUNCE_PROTOCOL: &str = "/subspace/full-block-relay-announces/1";
const SYNC_PROTOCOL: &str = "/subspace/full-block-relay-sync/1";

/// TODO: tentative size, to be tuned based on testing.
const INBOUND_QUEUE_SIZE: usize = 1024;

/// The gossiped block announcement.
#[derive(Debug, Clone, Encode, Decode)]
struct BlockAnnouncement<Block: BlockT>(NumberFor<Block>);

impl<Block: BlockT> From<&ImportedBlockNotification<Block>> for BlockAnnouncement<Block> {
    fn from(import_notification: &ImportedBlockNotification<Block>) -> Self {
        Self(import_notification.block_number)
    }
}

impl<Block: BlockT> fmt::Display for BlockAnnouncement<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockAnnouncement[block = {}]", self.0)
    }
}

/// The block download request.
#[derive(Debug, Encode, Decode)]
struct BlockRequest<Block: BlockT>(NumberFor<Block>);

impl<Block: BlockT> From<&BlockAnnouncement<Block>> for BlockRequest<Block> {
    fn from(announcement: &BlockAnnouncement<Block>) -> Self {
        Self(announcement.0)
    }
}

impl<Block: BlockT> fmt::Display for BlockRequest<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockRequest[block = {}]", self.0)
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
    import_queue: Mutex<Box<dyn ImportQueueService<Block>>>,

    /// Announcement gossip engine.
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,

    /// Announcement gossip validator.
    _validator: Arc<FullBlockRelayValidator>,

    /// Announcements in the process of being sent.
    pending_announcements: Arc<Mutex<HashSet<Vec<u8>>>>,

    /// Block downloads in progress.
    pending_downloads: Mutex<HashMap<NumberFor<Block>, BlockDownloadState>>,
}

#[derive(Debug)]
pub struct BlockDownloadState;

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
            import_queue: Mutex::new(import_queue),
            gossip_engine: gossip_engine.clone(),
            _validator: validator,
            pending_announcements,
            pending_downloads: Mutex::new(HashMap::new()),
        };
        (protocol, gossip_engine)
    }

    /// Downloads the announced block.
    async fn download_block(
        &self,
        sender: PeerId,
        announcement: &BlockAnnouncement<Block>,
    ) -> Result<Option<BlockResponse<Block>>, String> {
        {
            let mut pending_downloads = self.pending_downloads.lock();
            if pending_downloads.contains_key(&announcement.0) {
                return Ok(None);
            }
            pending_downloads.insert(announcement.0, BlockDownloadState);
        }

        let block_request = BlockRequest::<Block>(announcement.0);
        let ret = self
            .network
            .request(
                sender,
                SYNC_PROTOCOL.into(),
                block_request.encode(),
                IfDisconnected::ImmediateError,
            )
            .await;
        self.pending_downloads.lock().remove(&announcement.0);

        let bytes = match ret {
            Ok(bytes) => bytes,
            Err(err) => {
                return Err(format!(
                    "[{}, send request failed, err = {:?}]",
                    block_request, err
                ));
            }
        };

        BlockResponse::<Block>::decode(&mut bytes.as_slice())
            .map(|block| Some(block))
            .map_err(|err| {
                format!(
                    "[{}, failed to decoded block response, len = {}, err = {:?}]",
                    block_request,
                    bytes.len(),
                    err
                )
            })
    }

    /// Imports the block.
    async fn import_block(&self, block: SignedBlock<Block>) {
        let (header, extrinsics) = block.block.deconstruct();
        let hash = header.hash();
        self.import_queue.lock().import_blocks(
            BlockOrigin::ConsensusBroadcast,
            vec![IncomingBlock::<Block> {
                hash,
                header: Some(header),
                body: Some(extrinsics),
                indexed_body: None,
                justifications: block.justifications,
                origin: None,
                allow_missing_state: false,
                import_existing: false,
                state: None,
                skip_execution: false,
            }],
        );
    }

    /// Sends the response to the block download request.
    async fn send_download_response(
        &self,
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
                "FullBlockRelay::send_download_response(): {}, {}, response len = {}, err = {:?}",
                request,
                response,
                encoded_len,
                err
            );
        } else {
            warn!(
                target: LOG_TARGET,
                "FullBlockRelay::send_download_response(): {}, {}, sent response, len = {}",
                request,
                response,
                encoded_len,
            );
        }
    }

    /// Retrieves the requested block from the backend.
    fn get_backend_block(
        &self,
        block_number: NumberFor<Block>,
    ) -> Result<Option<SignedBlock<Block>>, String> {
        let block_id = BlockId::<Block>::Number(block_number);
        let block_hash = match self.client.block_hash_from_id(&block_id) {
            Ok(Some(block_hash)) => block_hash,
            Ok(None) => {
                return Err(format!(
                    "FullBlockRelay::get_block(): hash lookup failed: {:?}",
                    block_id
                ))
            }
            Err(err) => {
                return Err(format!(
                    "FullBlockRelay::get_block(): hash conversion failed: {:?}, {:?}",
                    block_id, err
                ))
            }
        };

        self.client.block(block_hash).map_err(|err| {
            format!(
                "FullBlockRelay::get_block(): block lookup failed: {:?}, {:?}",
                block_id, err
            )
        })
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

    async fn on_block_import(&self, notification: ImportedBlockNotification<Block>) {
        // Announce the imported block.
        let announcement: BlockAnnouncement<Block> = (&notification).into();
        let encoded = announcement.encode();
        self.pending_announcements.lock().insert(encoded.clone());
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded, false);
        info!(
            target: LOG_TARGET,
            "FullBlockRelay::on_block_import(): notification = {:?}, sent {}",
            notification,
            announcement
        );
    }

    async fn on_block_announcement(&self, message: TopicNotification) {
        let sender = match message.sender {
            Some(sender) => sender,
            None => return,
        };

        let announcement = match BlockAnnouncement::<Block>::decode(&mut &message.message[..]) {
            Ok(announcement) => announcement,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "FullBlockRelay::on_block_announcement(): failed to decode {:?}, err = {:?}",
                    message,
                    err
                );
                return;
            }
        };

        // Skip the announcement if we already have the block.
        if let Ok(Some(_)) = self.get_backend_block(announcement.0) {
            info!(
                target: LOG_TARGET,
                "FullBlockRelay::on_block_announcement(): {}, skipping", announcement,
            );
            return;
        }

        // Download/import the block
        let block_response = match self.download_block(sender, &announcement).await {
            Ok(Some(block_response)) => block_response,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "FullBlockRelay::on_block_announcement(): {}, download failed, err = {:?}",
                    announcement,
                    err
                );
                return;
            }
            _ => return,
        };

        // Import the downloaded block
        info!(
            target: LOG_TARGET,
            "FullBlockRelay::on_block_announcement(): {}, {}, block downloaded/imported",
            announcement,
            block_response
        );
        self.import_block(block_response.0).await;
    }

    async fn on_protocol_message(&self, incoming: IncomingRequest) {
        let block_request = match BlockRequest::<Block>::decode(&mut &incoming.payload[..]) {
            Ok(block_request) => block_request,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "FullBlockRelay::on_protocol_message(): failed to decode {:?}, err = {:?}",
                    incoming,
                    err
                );
                return;
            }
        };

        let ret = self.get_backend_block(block_request.0);
        if let Ok(Some(signed_block)) = ret {
            let block_response = BlockResponse(signed_block);
            self.send_download_response(incoming, block_request, block_response)
                .await;
        } else {
            warn!(
                target: LOG_TARGET,
                "FullBlockRelay::on_protocol_message(): {}, backend fetch failed, ret = {:?}",
                block_request,
                ret
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
                "FullBlockRelayValidator::validate(): peer = {:?}, decode failed: {:?}",
                sender,
                err
            );
            ValidationResult::Discard
        } else {
            ValidationResult::ProcessAndKeep(topic::<Block>())
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |topic, data| {
            trace!(
                target: LOG_TARGET,
                "FullBlockRelayValidator::message_expired(): topic = {:?}, data = {:?}",
                topic,
                data
            );
            !self.pending_announcements.lock().contains(data)
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |peer, intent, topic, data| {
            let i = match intent {
                MessageIntent::Broadcast => "Broadcast",
                MessageIntent::ForcedBroadcast => "ForcedBroadcast",
                MessageIntent::PeriodicRebroadcast => "PeriodicRebroadcast",
            };
            trace!(
                target: LOG_TARGET,
                "FullBlockRelayValidator::message_allowed(): topic = {:?}, data = {:?}, \
                peer = {:?}, intent = {:?}",
                topic,
                data,
                peer,
                i
            );

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
