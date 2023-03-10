//! Block relay worker.

use futures::channel::mpsc::{self, Receiver};
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, ValidationResult, Validator, ValidatorContext,
};
use sc_service::config::{IncomingRequest, RequestResponseConfig};
use sc_service::Configuration;
use sc_utils::mpsc::TracingUnboundedReceiver;
//use sp_api::NumberFor;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, error};

const LOG_TARGET: &str = "block_relay_worker";
const PROTOCOL_NAME: &str = "/subspace/block-relay";

/// TODO: tentative size, to be tuned based on testing.
const INBOUND_QUEUE_SIZE: usize = 1024;

/// The messages exchanged by the workers.
#[derive(Debug, Encode, Decode)]
pub struct BlockRelayMessage;
/*
{
    pub block_number: NumberFor<Block>,
}

 */

/// Thw gossip worker processes these events:
/// 1. Block imported: announce to peers
/// 2. Incoming Block announcement from peers: process, start the download handshake if needed
/// 3. Incoming handshake requests from peers: process, send response if needed
/// 4. Manage the outstanding handshake requests
pub struct BlockRelayGossipWorker<Block: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    _validator: Arc<BlockRelayGossipValidator>,
}

impl<Block: BlockT> BlockRelayGossipWorker<Block> {
    pub fn new<Network>(network: Network) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
    {
        let _validator = Arc::new(BlockRelayGossipValidator);
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            PROTOCOL_NAME,
            _validator.clone(),
            None,
        )));

        Self {
            gossip_engine,
            _validator,
        }
    }

    /// Starts the worker.
    pub async fn run(
        self,
        mut req_receiver: Receiver<IncomingRequest>,
        mut import_stream: TracingUnboundedReceiver<ImportedBlockNotification<Block>>,
    ) {
        info!(target: LOG_TARGET, "xxx: Block relay worker started");
        let mut gossip_messages = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    BlockRelayMessage::decode(&mut &notification.message[..]).ok()
                }),
        );

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                gossip_message = gossip_messages.next().fuse() => {
                    if let Some(msg) = gossip_message {
                        info!(target: LOG_TARGET, "xxx: Gossip message: {:?}", msg);
                        //self.handle_gossip_message(msg);
                    }
                },
                import_notification = import_stream.next().fuse() => {
                    info!(target: LOG_TARGET, "xxx: Import notification: {:?}", import_notification);
                }
                rr_req = req_receiver.next().fuse() => {
                    info!(target: LOG_TARGET, "xxx: RR_request: {:?}", rr_req);
                }

                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "Block relay: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Handles the incoming gossip messages
    fn _handle_gossip_message(&mut self, _msg: BlockRelayMessage) {}
}

struct BlockRelayGossipValidator;

impl<Block: BlockT> Validator<Block> for BlockRelayGossipValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut _data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        ValidationResult::ProcessAndKeep(topic::<Block>())
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_, _| false)
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_, _, _, _| true)
    }
}

/// Block relay message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"block-relay-messages")
}

pub fn setup_block_relay_rr_handlers(config: &mut Configuration) -> Receiver<IncomingRequest> {
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
