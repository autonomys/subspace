use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::config::NonDefaultSetConfig;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Syncing as GossipSyncing, ValidationResult, Validator,
    ValidatorContext,
};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_core::twox_256;
use sp_messenger::messages::ChainId;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

const LOG_TARGET: &str = "cross_chain_gossip_worker";
const PROTOCOL_NAME: &str = "/subspace/cross-chain-messages";

/// Unbounded sender to send encoded ext to listeners.
pub type ChainTxPoolSink = TracingUnboundedSender<Vec<u8>>;
type MessageHash = [u8; 32];

/// A cross chain message with encoded data.
#[derive(Debug, Encode, Decode)]
pub struct Message {
    pub chain_id: ChainId,
    pub encoded_data: Vec<u8>,
}

/// Gossip worker builder
pub struct GossipWorkerBuilder {
    gossip_msg_stream: TracingUnboundedReceiver<Message>,
    gossip_msg_sink: TracingUnboundedSender<Message>,
    chain_tx_pool_sinks: BTreeMap<ChainId, ChainTxPoolSink>,
}

impl GossipWorkerBuilder {
    /// Construct a gossip worker builder
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (gossip_msg_sink, gossip_msg_stream) =
            tracing_unbounded("cross_chain_gossip_messages", 100);
        Self {
            gossip_msg_stream,
            gossip_msg_sink,
            chain_tx_pool_sinks: BTreeMap::new(),
        }
    }

    /// Collect the chain tx pool sink that will be used by the gossip message worker later.
    pub fn push_chain_tx_pool_sink(&mut self, chain_id: ChainId, tx_pool_sink: ChainTxPoolSink) {
        self.chain_tx_pool_sinks.insert(chain_id, tx_pool_sink);
    }

    /// Get the gossip message sink
    pub fn gossip_msg_sink(&self) -> TracingUnboundedSender<Message> {
        self.gossip_msg_sink.clone()
    }

    /// Build gossip worker
    pub fn build<Block, Network, GossipSync>(
        self,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> GossipWorker<Block>
    where
        Block: BlockT,
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let Self {
            gossip_msg_stream,
            chain_tx_pool_sinks,
            ..
        } = self;

        let gossip_validator = Arc::new(GossipValidator::default());
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            PROTOCOL_NAME,
            gossip_validator.clone(),
            None,
        )));

        GossipWorker {
            gossip_engine,
            gossip_validator,
            gossip_msg_stream,
            chain_tx_pool_sinks,
        }
    }
}

/// Gossip worker to gossip incoming and outgoing messages to other peers.
/// Also, streams the decoded extrinsics to destination chain tx pool if available.
pub struct GossipWorker<Block: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    gossip_validator: Arc<GossipValidator>,
    gossip_msg_stream: TracingUnboundedReceiver<Message>,
    chain_tx_pool_sinks: BTreeMap<ChainId, ChainTxPoolSink>,
}

/// Returns the network configuration for cross chain message gossip.
pub fn cdm_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(PROTOCOL_NAME.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

/// Cross chain message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"cross-chain-messages")
}

impl<Block: BlockT> GossipWorker<Block> {
    /// Starts the Gossip message worker.
    pub async fn run(mut self) {
        let mut incoming_cross_chain_messages = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    Message::decode(&mut &notification.message[..]).ok()
                }),
        );

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                cross_chain_message = incoming_cross_chain_messages.next().fuse() => {
                    if let Some(msg) = cross_chain_message {
                        tracing::debug!(target: LOG_TARGET, "Incoming cross chain message for chain: {:?}", msg.chain_id);
                        self.handle_cross_chain_message(msg);
                    }
                },

                cross_chain_message = self.gossip_msg_stream.next().fuse() => {
                    if let Some(msg) = cross_chain_message {
                        tracing::debug!(target: LOG_TARGET, "Incoming cross chain message for chain: {:?}", msg.chain_id);
                        self.handle_cross_chain_message(msg);
                    }
                }

                _ = gossip_engine.fuse() => {
                    tracing::error!(target: LOG_TARGET, "Gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    fn handle_cross_chain_message(&mut self, msg: Message) {
        // mark and rebroadcast message
        let encoded_msg = msg.encode();
        self.gossip_validator.note_broadcast(&encoded_msg);
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_msg, false);

        let Message {
            chain_id,
            encoded_data,
        } = msg;
        let sink = match self.chain_tx_pool_sinks.get(&chain_id) {
            Some(sink) => sink,
            None => return,
        };

        // send the message to the open and ready channel
        if !sink.is_closed() && sink.unbounded_send(encoded_data).is_ok() {
            return;
        }

        // sink is either closed or failed to send unbounded message
        // consider it closed and remove the sink.
        tracing::error!(
            target: LOG_TARGET,
            "Failed to send incoming chain message: {:?}",
            chain_id
        );
        self.chain_tx_pool_sinks.remove(&chain_id);
    }
}

/// Gossip validator to retain or clean up Gossiped messages.
#[derive(Debug, Default)]
struct GossipValidator {
    should_broadcast: RwLock<HashSet<MessageHash>>,
}

impl GossipValidator {
    fn note_broadcast(&self, msg: &[u8]) {
        let msg_hash = twox_256(msg);
        let mut msg_set = self.should_broadcast.write();
        msg_set.insert(msg_hash);
    }

    fn should_broadcast(&self, msg: &[u8]) -> bool {
        let msg_hash = twox_256(msg);
        let msg_set = self.should_broadcast.read();
        msg_set.contains(&msg_hash)
    }

    fn note_broadcasted(&self, msg: &[u8]) {
        let msg_hash = twox_256(msg);
        let mut msg_set = self.should_broadcast.write();
        msg_set.remove(&msg_hash);
    }
}

impl<Block: BlockT> Validator<Block> for GossipValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match Message::decode(&mut data) {
            Ok(_) => ValidationResult::ProcessAndKeep(topic::<Block>()),
            Err(_) => ValidationResult::Discard,
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| !self.should_broadcast(data))
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, data| {
            let should_broadcast = self.should_broadcast(data);
            if should_broadcast {
                self.note_broadcasted(data)
            }

            should_broadcast
        })
    }
}
