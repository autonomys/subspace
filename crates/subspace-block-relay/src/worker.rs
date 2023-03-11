//! Block relay worker.

use futures::channel::mpsc::{self, Receiver};
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network::PeerId;
use sc_network_common::config::NonDefaultSetConfig;
use sc_network_gossip::{
    GossipEngine, MessageIntent, TopicNotification, ValidationResult, Validator, ValidatorContext,
};
use sc_service::config::{IncomingRequest, RequestResponseConfig};
use sc_service::Configuration;
use sc_utils::mpsc::TracingUnboundedReceiver;
//use sp_api::NumberFor;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, trace, warn};

const LOG_TARGET: &str = "block_relay_worker";
const PROTOCOL_NAME: &str = "/subspace/block-relay";

/// TODO: tentative size, to be tuned based on testing.
const INBOUND_QUEUE_SIZE: usize = 1024;

/// The gossip message.
#[derive(Debug, Encode, Decode)]
pub struct BlockAnnouncement<Block: BlockT>(NumberFor<Block>);

/// Thw gossip worker processes these events:
/// 1. Block imported: announce to peers
/// 2. Incoming Block announcement from peers: process, start the download handshake if needed
/// 3. Incoming handshake requests from peers: process, send response if needed
/// 4. Manage the outstanding handshake requests
pub struct BlockRelayWorker<Block: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    _validator: Arc<BlockRelayValidator>,
    pending_announcements: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl<Block: BlockT> BlockRelayWorker<Block> {
    pub fn new<Network>(network: Network) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
    {
        let pending_announcements = Arc::new(Mutex::new(HashSet::new()));
        let validator = Arc::new(BlockRelayValidator {
            pending_announcements: pending_announcements.clone(),
        });
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            PROTOCOL_NAME,
            validator.clone(),
            None,
        )));

        Self {
            gossip_engine,
            _validator: validator,
            pending_announcements,
        }
    }

    /// Starts the worker.
    pub async fn run(
        self,
        mut import_stream: TracingUnboundedReceiver<ImportedBlockNotification<Block>>,
        mut req_receiver: Receiver<IncomingRequest>,
    ) {
        info!(target: LOG_TARGET, "BlockRelayWorker: started");
        let mut gossip_messages =
            Box::pin(self.gossip_engine.lock().messages_for(topic::<Block>()));

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                import_notification = import_stream.next().fuse() => {
                    if let Some(import_notification) = import_notification {
                        self.on_block_import(import_notification);
                    }
                }
                gossip_message = gossip_messages.next().fuse() => {
                    if let Some(msg) = gossip_message {
                        self.on_block_announcement(msg);
                    }
                },
                rr_req = req_receiver.next().fuse() => {
                    info!(target: LOG_TARGET, "BlockRelayWorker(): RR_request: {:?}", rr_req);
                }

                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "BlockRelayWorker(): gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Handles the block import notifications.
    fn on_block_import(&self, notification: ImportedBlockNotification<Block>) {
        // Announce the block.
        let announcement = BlockAnnouncement::<Block>(notification.block_number);
        let encoded = announcement.encode();
        self.pending_announcements.lock().insert(encoded.clone());
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded, false);
        info!(
            target: LOG_TARGET,
            "BlockRelayWorker::on_block_import(): sent announcement for {:?}", notification
        );
    }

    /// Handles the incoming announcements.
    fn on_block_announcement(&self, message: TopicNotification) {
        let sender = match message.sender {
            Some(sender) => sender,
            None => return,
        };

        let announcement =
            match BlockAnnouncement::<Block>::decode(&mut &message.message[..]) {
                Ok(announcement) => announcement,
                Err(err) => {
                    warn!(
                    target: LOG_TARGET,
                    "BlockRelayWorker::on_block_announcement(): failed to decode {:?}, err = {:?}",
                    message, err);
                    return;
                }
            };

        info!(
            target: LOG_TARGET,
            "BlockRelayWorker::on_block_announcement(): sender = {:?}, announcement = {:?}",
            sender,
            announcement,
        );
    }
}

struct BlockRelayValidator {
    pending_announcements: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl<Block: BlockT> Validator<Block> for BlockRelayValidator {
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
                "BlockRelayValidator::validate(): peer = {:?}, decode failed: {:?}", sender, err
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
                "BlockRelayGossipWorker::message_expired(): topic = {:?}, data = {:?}",
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
                "BlockRelayGossipWorker::message_allowed(): topic = {:?}, data = {:?}, \
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
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(PROTOCOL_NAME.as_bytes())
}

/// Sets up the required config for the block relay.
pub fn init_block_relay_config(config: &mut Configuration) -> Receiver<IncomingRequest> {
    let mut cfg = NonDefaultSetConfig::new(PROTOCOL_NAME.into(), 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    config.network.extra_sets.push(cfg);

    let (request_sender, request_receiver) = mpsc::channel(INBOUND_QUEUE_SIZE);
    config
        .network
        .request_response_protocols
        .push(RequestResponseConfig {
            name: PROTOCOL_NAME.into(),
            fallback_names: Vec::new(),
            max_request_size: 1024 * 1024,
            max_response_size: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(15),
            inbound_queue: Some(request_sender),
        });
    request_receiver
}
