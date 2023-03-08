//! Block relay worker.

use futures::{FutureExt, Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, ValidationResult, Validator, ValidatorContext,
};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::sync::Arc;
use tracing::error;

const LOG_TARGET: &str = "block_relay_worker";
const PROTOCOL_NAME: &str = "/subspace/block-relay";

/// The messages exchanged by the workers.
#[derive(Debug, Encode, Decode)]
pub struct BlockRelayMessage;

/// Thw gossip worker processes these events:
/// 1. Block imported: announce to peers
/// 2. Incoming Block announcement from peers: process, start the download handshake if needed
/// 3. Incoming handshake requests from peers: process, send response if needed
/// 4. Manage the outstanding handshake requests
pub struct BlockRelayGossipWorker<Block: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    validator: Arc<BlockRelayGossipValidator>,
}

impl<Block: BlockT> BlockRelayGossipWorker<Block> {
    pub fn new<Network>(network: Network) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
    {
        let validator = Arc::new(BlockRelayGossipValidator);
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            PROTOCOL_NAME,
            validator.clone(),
            None,
        )));

        Self {
            gossip_engine,
            validator,
        }
    }

    /// Starts the worker.
    pub async fn run<MsgStream>(mut self, mut msg_stream: MsgStream)
    where
        MsgStream: Stream<Item = BlockRelayMessage> + Unpin + futures::stream::FusedStream,
    {
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
                        self.handle_gossip_message(msg);
                    }
                },

                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "Block relay: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Handles the incoming gossip messages
    fn handle_gossip_message(&mut self, msg: BlockRelayMessage) {}
}

struct BlockRelayGossipValidator;

impl<Block: BlockT> Validator<Block> for BlockRelayGossipValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut _data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        unimplemented!()
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        unimplemented!()
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        unimplemented!()
    }
}

/// Block relay message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"block-relay-messages")
}
