//! Implementation of the full block protocol.

use crate::protocol::{BlockRelayProtocol, GossipNetworkService};
use crate::LOG_TARGET;
use async_trait::async_trait;
use futures::channel::mpsc::{self, Receiver};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network::{IfDisconnected, NetworkRequest, PeerId};
use sc_network_common::config::NonDefaultSetConfig;
use sc_network_gossip::{
    GossipEngine, MessageIntent, TopicNotification, ValidationResult, Validator, ValidatorContext,
};
use sc_service::config::{IncomingRequest, OutgoingResponse, RequestResponseConfig};
use sc_service::Configuration;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, trace, warn};

const ANNOUNCE_PROTOCOL: &str = "/subspace/full-block-relay-announces/1";
const SYNC_PROTOCOL: &str = "/subspace/full-block-relay-sync/1";

/// TODO: tentative size, to be tuned based on testing.
const INBOUND_QUEUE_SIZE: usize = 1024;

/// The gossip message.
#[derive(Debug, Encode, Decode)]
pub struct BlockAnnouncement<Block: BlockT>(NumberFor<Block>);

pub struct FullBlockRelay<Block: BlockT> {
    /// Network handle.
    network: Arc<GossipNetworkService<Block>>,

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

impl<Block: BlockT> FullBlockRelay<Block> {
    pub(crate) fn new(
        network: Arc<GossipNetworkService<Block>>,
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
            gossip_engine: gossip_engine.clone(),
            _validator: validator,
            pending_announcements,
            pending_downloads: Mutex::new(HashMap::new()),
        };
        (protocol, gossip_engine)
    }

    /// Sends the block download request for the announcement.
    async fn send_download_request(&self, sender: PeerId, announcement: BlockAnnouncement<Block>) {
        {
            let mut pending_downloads = self.pending_downloads.lock();
            if pending_downloads.contains_key(&announcement.0) {
                return;
            }
            pending_downloads.insert(announcement.0, BlockDownloadState);
        }

        match self
            .network
            .request(
                sender,
                SYNC_PROTOCOL.into(),
                announcement.encode(),
                IfDisconnected::ImmediateError,
            )
            .await
        {
            Ok(bytes) => {
                info!(
                    target: LOG_TARGET,
                    "FullBlockRelay::send_download_request(): announcement = {:?}, received {} bytes",
                    announcement, bytes.len()
                );
            }
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "FullBlockRelay::send_download_request(): announcement = {:?}, request failed: {:?}",
                    announcement, err
                );
            }
        }
        self.pending_downloads.lock().remove(&announcement.0);
    }
}

#[async_trait]
impl<Block: BlockT> BlockRelayProtocol<Block> for FullBlockRelay<Block> {
    fn block_announcement_topic(&self) -> Block::Hash {
        topic::<Block>()
    }

    async fn on_block_import(&self, notification: ImportedBlockNotification<Block>) {
        // Announce the imported block.
        let announcement = BlockAnnouncement::<Block>(notification.block_number);
        let encoded = announcement.encode();
        self.pending_announcements.lock().insert(encoded.clone());
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded, false);
        info!(
            target: LOG_TARGET,
            "FullBlockRelay::on_block_import(): sent announcement for {:?}", notification
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

        info!(
            target: LOG_TARGET,
            "FullBlockRelay::on_block_announcement(): sender = {:?}, announcement = {:?}",
            sender,
            announcement,
        );

        self.send_download_request(sender, announcement).await;
    }

    async fn on_protocol_message(&self, request: IncomingRequest) {
        info!(
            target: LOG_TARGET,
            "FullBlockRelay::on_protocol_message(): {:?}", request
        );

        let announcement = match BlockAnnouncement::<Block>::decode(&mut &request.payload[..]) {
            Ok(announcement) => announcement,
            Err(err) => {
                warn!(
                    target: LOG_TARGET,
                    "FullBlockRelay::on_protocol_message(): failed to decode {:?}, err = {:?}",
                    request,
                    err
                );
                return;
            }
        };

        let response = OutgoingResponse {
            result: Ok(announcement.encode()),
            reputation_changes: vec![],
            sent_feedback: None,
        };
        if let Err(err) = request.pending_response.send(response) {
            warn!(
                target: LOG_TARGET,
                "FullBlockRelay::on_protocol_message(): failed to send response: err = {:?}", err
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
