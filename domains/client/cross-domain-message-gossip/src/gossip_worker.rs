use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::config::NonDefaultSetConfig;
use sc_network::{NetworkPeers, NotificationService, PeerId};
use sc_network_gossip::{
    GossipEngine, MessageIntent, Syncing as GossipSyncing, ValidationResult, Validator,
    ValidatorContext,
};
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender, tracing_unbounded};
use sp_api::StorageProof;
use sp_consensus::SyncOracle;
use sp_core::twox_256;
use sp_messenger::messages::{ChainId, ChannelId};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, HashingFor};
use std::collections::{BTreeMap, HashSet};
use std::future::poll_fn;
use std::pin::pin;
use std::sync::Arc;
use subspace_runtime_primitives::BlockNumber;

const PROTOCOL_NAME: &str = "/subspace/cross-chain-messages";

/// Encoded message with sender info if available.
pub struct ChainMsg {
    pub maybe_peer: Option<PeerId>,
    pub data: MessageData,
}

/// Unbounded sender to send encoded message to listeners.
pub type ChainSink = TracingUnboundedSender<ChainMsg>;
type MessageHash = [u8; 32];

/// Channel update message.
#[derive(Debug, Encode, Decode)]
pub struct ChannelUpdate {
    /// Message is coming from src_chain.
    pub src_chain_id: ChainId,
    /// Channel id.
    pub channel_id: ChannelId,
    /// Block number at which storage proof was generated.
    pub block_number: BlockNumber,
    /// Storage proof of the channel on src_chain.
    pub storage_proof: StorageProof,
}

/// A type of cross chain message
#[derive(Debug, Encode, Decode)]
pub enum MessageData {
    /// Encoded XDM message
    Xdm(Vec<u8>),
    /// Encoded channel update message.
    ChannelUpdate(ChannelUpdate),
}

/// A cross chain message with encoded data.
#[derive(Debug, Encode, Decode)]
pub struct Message {
    pub chain_id: ChainId,
    pub data: MessageData,
}

/// Gossip worker builder
pub struct GossipWorkerBuilder {
    gossip_msg_stream: TracingUnboundedReceiver<Message>,
    gossip_msg_sink: TracingUnboundedSender<Message>,
    chain_sinks: BTreeMap<ChainId, ChainSink>,
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
            chain_sinks: BTreeMap::new(),
        }
    }

    /// Collect the chain sink that will be used by the gossip message worker later.
    pub fn push_chain_sink(&mut self, chain_id: ChainId, sink: ChainSink) {
        self.chain_sinks.insert(chain_id, sink);
    }

    // Remove the chain sink
    pub fn remove_chain_sink(&mut self, chain_id: &ChainId) -> Option<ChainSink> {
        self.chain_sinks.remove(chain_id)
    }

    /// Get the gossip message sink
    pub fn gossip_msg_sink(&self) -> TracingUnboundedSender<Message> {
        self.gossip_msg_sink.clone()
    }

    /// Build gossip worker
    pub fn build<Block, Network, GossipSync>(
        self,
        network: Network,
        notification_service: Box<dyn NotificationService>,
        sync: Arc<GossipSync>,
    ) -> GossipWorker<Block, Network, GossipSync>
    where
        Block: BlockT,
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + SyncOracle + Send + 'static,
    {
        let Self {
            gossip_msg_stream,
            chain_sinks,
            ..
        } = self;

        let gossip_validator = Arc::new(GossipValidator::new(network.clone()));
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync.clone(),
            notification_service,
            PROTOCOL_NAME,
            gossip_validator.clone(),
            None,
        )));

        GossipWorker {
            gossip_engine,
            gossip_validator,
            gossip_msg_stream,
            chain_sinks,
            sync_oracle: sync,
        }
    }
}

/// Gossip worker to gossip incoming and outgoing messages to other peers.
/// Also, streams the decoded extrinsics to destination chain tx pool if available.
pub struct GossipWorker<Block: BlockT, Network, SO> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    gossip_validator: Arc<GossipValidator<Network>>,
    gossip_msg_stream: TracingUnboundedReceiver<Message>,
    chain_sinks: BTreeMap<ChainId, ChainSink>,
    sync_oracle: Arc<SO>,
}

/// Returns the network configuration for cross chain message gossip.
pub fn xdm_gossip_peers_set_config() -> (NonDefaultSetConfig, Box<dyn NotificationService>) {
    let (mut cfg, notification_service) = NonDefaultSetConfig::new(
        PROTOCOL_NAME.into(),
        Vec::new(),
        5 * 1024 * 1024,
        None,
        Default::default(),
    );
    cfg.allow_non_reserved(25, 25);
    (cfg, notification_service)
}

/// Cross chain message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    HashingFor::<Block>::hash(b"cross-chain-messages")
}

impl<Block: BlockT, Network, SO: SyncOracle> GossipWorker<Block, Network, SO> {
    /// Starts the Gossip message worker.
    pub async fn run(mut self) {
        let incoming_cross_chain_messages = pin!(
            self.gossip_engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    Message::decode(&mut &notification.message[..])
                        .ok()
                        .map(|msg| (notification.sender, msg))
                })
        );
        let mut incoming_cross_chain_messages = incoming_cross_chain_messages.fuse();

        loop {
            let engine = self.gossip_engine.clone();
            let mut gossip_engine = poll_fn(|cx| engine.lock().poll_unpin(cx)).fuse();

            futures::select! {
                cross_chain_message = incoming_cross_chain_messages.next() => {
                    if let Some((maybe_peer, msg)) = cross_chain_message {
                        tracing::debug!("Incoming cross chain message for chain from Network: {:?}", msg.chain_id);
                        self.handle_cross_chain_message(msg, maybe_peer);
                    }
                },

                msg = self.gossip_msg_stream.select_next_some() => {
                    tracing::debug!("Incoming cross chain message for chain from Relayer: {:?}", msg.chain_id);
                    self.handle_cross_chain_message(msg, None);
                }

                _ = gossip_engine => {
                    tracing::error!("Gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    fn handle_cross_chain_message(&mut self, msg: Message, maybe_peer: Option<PeerId>) {
        // mark and rebroadcast message
        let encoded_msg = msg.encode();
        self.gossip_validator.note_broadcast(&encoded_msg);
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_msg, false);

        // Skip sending the message since the node unable to verify the message before synced
        if self.sync_oracle.is_major_syncing() {
            return;
        }

        let Message { chain_id, data } = msg;
        let sink = match self.chain_sinks.get(&chain_id) {
            Some(sink) => sink,
            None => return,
        };

        // send the message to the open and ready channel
        if !sink.is_closed() && sink.unbounded_send(ChainMsg { data, maybe_peer }).is_ok() {
            return;
        }

        // sink is either closed or failed to send unbounded message
        // consider it closed and remove the sink.
        tracing::error!("Failed to send incoming chain message: {:?}", chain_id);
        self.chain_sinks.remove(&chain_id);
    }
}

/// Gossip validator to retain or clean up Gossiped messages.
#[derive(Debug)]
struct GossipValidator<Network> {
    network: Network,
    should_broadcast: RwLock<HashSet<MessageHash>>,
}

impl<Network> GossipValidator<Network> {
    fn new(network: Network) -> Self {
        Self {
            network,
            should_broadcast: Default::default(),
        }
    }

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

impl<Block, Network> Validator<Block> for GossipValidator<Network>
where
    Block: BlockT,
    Network: NetworkPeers + Send + Sync + 'static,
{
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match Message::decode(&mut data) {
            Ok(_) => ValidationResult::ProcessAndKeep(topic::<Block>()),
            Err(_) => {
                self.network.report_peer(*sender, rep::GOSSIP_NOT_DECODABLE);
                ValidationResult::Discard
            }
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

pub(crate) mod rep {
    use sc_network::ReputationChange;

    /// Reputation change when a peer sends us a gossip message that can't be decoded.
    pub(crate) const GOSSIP_NOT_DECODABLE: ReputationChange =
        ReputationChange::new_fatal("Cross chain message: not decodable");

    /// Reputation change when a peer sends us a non XDM message
    pub(crate) const NOT_XDM: ReputationChange =
        ReputationChange::new_fatal("Cross chain message: not XDM");
}
