use futures::{Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, ValidationResult, Validator, ValidatorContext,
};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_core::twox_256;
use sp_domains::DomainId;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

const LOG_TARGET: &str = "cross_domain_gossip_worker";
const PROTOCOL_NAME: &str = "/subspace/cross-domain-messages";

/// Unbounded sender to send encoded ext to listeners.
pub type DomainTxPoolSink = TracingUnboundedSender<Vec<u8>>;
type MessageHash = [u8; 32];

/// A cross domain message with encoded data.
#[derive(Debug, Encode, Decode)]
pub struct Message {
    pub domain_id: DomainId,
    pub encoded_data: Vec<u8>,
}

/// Gossip worker to gossip incoming and outgoing messages to other peers.
/// Also, streams the decoded extrinsics to destination domain tx pool if available.
pub struct GossipWorker<Block: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    gossip_validator: Arc<GossipValidator>,
    domain_tx_pool_sinks: BTreeMap<DomainId, DomainTxPoolSink>,
}

/// Cross domain message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"cross-domain-messages")
}

impl<Block: BlockT> GossipWorker<Block> {
    pub fn new<Network>(
        network: Network,
        domain_tx_pool_sinks: BTreeMap<DomainId, DomainTxPoolSink>,
    ) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
    {
        let gossip_validator = Arc::new(GossipValidator::default());
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            PROTOCOL_NAME,
            gossip_validator.clone(),
            None,
        )));
        GossipWorker {
            gossip_engine,
            gossip_validator,
            domain_tx_pool_sinks,
        }
    }

    /// Starts the Gossip message worker.
    pub async fn run<GossipMessageStream>(mut self, mut gossip_msg_stream: GossipMessageStream)
    where
        GossipMessageStream: Stream<Item = Message> + Unpin + futures::stream::FusedStream,
    {
        let mut incoming_cross_domain_messages = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    Message::decode(&mut &notification.message[..]).ok()
                }),
        );

        loop {
            futures::select! {
                cross_domain_message = incoming_cross_domain_messages.next() => {
                    if let Some(msg) = cross_domain_message {
                        tracing::debug!(target: LOG_TARGET, "Incoming cross domain message for domain: {:?}", msg.domain_id);
                        self.handle_cross_domain_message(msg);
                    }
                },

                cross_domain_message = gossip_msg_stream.next() => {
                    if let Some(msg) = cross_domain_message {
                        tracing::debug!(target: LOG_TARGET, "Submitted cross domain message for domain: {:?}", msg.domain_id);
                        self.handle_cross_domain_message(msg);
                    }
                }
            }
        }
    }

    fn handle_cross_domain_message(&mut self, msg: Message) {
        // mark and rebroadcast message
        let encoded_msg = msg.encode();
        self.gossip_validator.note_broadcast(&encoded_msg);
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_msg, false);

        let Message {
            domain_id,
            encoded_data,
        } = msg;
        let sink = match self.domain_tx_pool_sinks.get(&domain_id) {
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
            "Failed to send incoming domain message: {:?}",
            domain_id
        );
        self.domain_tx_pool_sinks.remove(&domain_id);
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
