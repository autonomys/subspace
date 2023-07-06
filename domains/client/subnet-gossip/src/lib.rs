//! This crate is intended to provide the feature of gossiping bundles over the domain subnet.
//! However, it's unused at present as it's not yet fully implemented.
//!
//! We may enable this feature in the future:
//! 1. Implement the [`GossipMessageHandler`] somewhere.
//! 2. Run the gossip worker using `start_gossip_worker` when building the service.

mod worker;

use self::worker::GossipWorker;
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::config::NonDefaultSetConfig;
use sc_network::PeerId;
use sc_network_common::role::ObservedRole;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Network as GossipNetwork, Syncing as GossipSyncing,
    ValidationResult, Validator, ValidatorContext,
};
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_core::hashing::twox_64;
use sp_domains::Bundle;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor};
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LOG_TARGET: &str = "gossip::operator";

const DOMAIN_SUBNET_PROTOCOL_NAME: &str = "/subspace/operator/1";

type BundleFor<Block, CBlock> = Bundle<
    <Block as BlockT>::Extrinsic,
    NumberFor<CBlock>,
    <CBlock as BlockT>::Hash,
    NumberFor<Block>,
    <Block as BlockT>::Hash,
>;

// TODO: proper timeout
/// Timeout for rebroadcasting messages.
/// The default value used in network-gossip is 1100ms.
const REBROADCAST_AFTER: Duration = Duration::from_secs(6);

type MessageHash = [u8; 8];

/// Returns the configuration value to use in
/// [`sc_network::config::FullNetworkConfiguration::add_notification_protocol`].
pub fn domain_subnet_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(DOMAIN_SUBNET_PROTOCOL_NAME.into(), 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

/// Gossip engine messages topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"operator")
}

/// Operator gossip message type.
///
/// This is the root type that gets encoded and sent on the network.
#[derive(Debug, Encode, Decode)]
pub enum GossipMessage<CBlock: BlockT, Block: BlockT> {
    Bundle(BundleFor<Block, CBlock>),
}

impl<CBlock: BlockT, Block: BlockT> From<BundleFor<Block, CBlock>>
    for GossipMessage<CBlock, Block>
{
    #[inline]
    fn from(bundle: BundleFor<Block, CBlock>) -> Self {
        Self::Bundle(bundle)
    }
}

/// What to do with the successfully verified gossip message.
#[derive(Debug)]
pub enum Action {
    /// The message does not have to be re-gossiped.
    Empty,
    /// Gossip the bundle message to other peers.
    RebroadcastBundle,
    /// Gossip the execution exceipt message to other peers.
    RebroadcastExecutionReceipt,
}

impl Action {
    fn rebroadcast_bundle(&self) -> bool {
        matches!(self, Self::RebroadcastBundle)
    }
}

/// Handler for the messages received from the domain subnet.
pub trait GossipMessageHandler<CBlock, Block>
where
    CBlock: BlockT,
    Block: BlockT,
{
    /// Error type.
    type Error: Debug;

    /// Validates and applies when a transaction bundle was received.
    fn on_bundle(&self, bundle: &BundleFor<Block, CBlock>) -> Result<Action, Self::Error>;
}

/// Validator for the gossip messages.
pub struct GossipValidator<CBlock, Block, Operator>
where
    CBlock: BlockT,
    Block: BlockT,
    Operator: GossipMessageHandler<CBlock, Block>,
{
    topic: Block::Hash,
    executor: Operator,
    next_rebroadcast: Mutex<Instant>,
    known_rebroadcasted: RwLock<HashSet<MessageHash>>,
    _phantom_data: PhantomData<CBlock>,
}

impl<CBlock, Block, Operator> GossipValidator<CBlock, Block, Operator>
where
    CBlock: BlockT,
    Block: BlockT,
    Operator: GossipMessageHandler<CBlock, Block>,
{
    pub fn new(executor: Operator) -> Self {
        Self {
            topic: topic::<Block>(),
            executor,
            next_rebroadcast: Mutex::new(Instant::now() + REBROADCAST_AFTER),
            known_rebroadcasted: RwLock::new(HashSet::new()),
            _phantom_data: PhantomData,
        }
    }

    pub(crate) fn note_rebroadcasted(&self, encoded_message: &[u8]) {
        let mut known_rebroadcasted = self.known_rebroadcasted.write();
        known_rebroadcasted.insert(twox_64(encoded_message));
    }

    fn validate_message(&self, msg: GossipMessage<CBlock, Block>) -> ValidationResult<Block::Hash> {
        match msg {
            GossipMessage::Bundle(bundle) => {
                let outcome = self.executor.on_bundle(&bundle);
                match outcome {
                    Ok(action) if action.rebroadcast_bundle() => {
                        ValidationResult::ProcessAndKeep(self.topic)
                    }
                    Err(err) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?err,
                            "Invalid GossipMessage::Bundle discarded"
                        );
                        ValidationResult::Discard
                    }
                    _ => ValidationResult::ProcessAndDiscard(self.topic),
                }
            }
        }
    }
}

impl<CBlock, Block, Operator> Validator<Block> for GossipValidator<CBlock, Block, Operator>
where
    CBlock: BlockT,
    Block: BlockT,
    Operator: GossipMessageHandler<CBlock, Block> + Send + Sync,
{
    fn new_peer(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _who: &PeerId,
        _role: ObservedRole,
    ) {
    }

    fn peer_disconnected(&self, _context: &mut dyn ValidatorContext<Block>, _who: &PeerId) {}

    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match GossipMessage::<CBlock, Block>::decode(&mut data) {
            Ok(msg) => {
                tracing::debug!(target: LOG_TARGET, ?msg, "Validating incoming message");
                self.validate_message(msg)
            }
            Err(err) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?err,
                    ?data,
                    "Message discarded due to the decoding error"
                );
                ValidationResult::Discard
            }
        }
    }

    /// Produce a closure for validating messages on a given topic.
    ///
    /// The gossip engine will periodically prune old or no longer relevant messages using
    /// `message_expired`.
    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, mut data| {
            let msg_hash = twox_64(data);
            // TODO: can be expired due to the message itself might be too old?
            let _msg = match GossipMessage::<CBlock, Block>::decode(&mut data) {
                Ok(msg) => msg,
                Err(_) => return true,
            };
            let expired = {
                let known_rebroadcasted = self.known_rebroadcasted.read();
                known_rebroadcasted.contains(&msg_hash)
            };
            if expired {
                let mut known_rebroadcasted = self.known_rebroadcasted.write();
                known_rebroadcasted.remove(&msg_hash);
            }
            expired
        })
    }

    /// Produce a closure for filtering egress messages.
    ///
    /// Called before actually sending a message to a peer.
    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        let do_rebroadcast = {
            let now = Instant::now();
            let mut next_rebroadcast = self.next_rebroadcast.lock();
            if now >= *next_rebroadcast {
                *next_rebroadcast = now + REBROADCAST_AFTER;
                true
            } else {
                false
            }
        };

        Box::new(move |_who, intent, _topic, mut data| {
            if let MessageIntent::PeriodicRebroadcast = intent {
                return do_rebroadcast;
            }

            GossipMessage::<CBlock, Block>::decode(&mut data).is_ok()
        })
    }
}

type BundleReceiver<Block, CBlock> = TracingUnboundedReceiver<BundleFor<Block, CBlock>>;

/// Parameters to run the executor gossip service.
pub struct ExecutorGossipParams<CBlock: BlockT, Block: BlockT, Network, GossipSync, Operator> {
    /// Substrate network service.
    pub network: Network,
    /// Syncing service an event stream for peers.
    pub sync: Arc<GossipSync>,
    /// Operator instance.
    pub operator: Operator,
    /// Stream of transaction bundle produced locally.
    pub bundle_receiver: BundleReceiver<Block, CBlock>,
}

/// Starts the executor gossip worker.
pub async fn start_gossip_worker<CBlock, Block, Network, GossipSync, Operator>(
    gossip_params: ExecutorGossipParams<CBlock, Block, Network, GossipSync, Operator>,
) where
    CBlock: BlockT,
    Block: BlockT,
    Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
    Operator: GossipMessageHandler<CBlock, Block> + Send + Sync + 'static,
    GossipSync: GossipSyncing<Block> + 'static,
{
    let ExecutorGossipParams {
        network,
        sync,
        operator,
        bundle_receiver,
    } = gossip_params;

    let gossip_validator = Arc::new(GossipValidator::new(operator));
    let gossip_engine = GossipEngine::new(
        network,
        sync,
        DOMAIN_SUBNET_PROTOCOL_NAME,
        gossip_validator.clone(),
        None,
    );

    let gossip_worker = GossipWorker::new(
        gossip_validator,
        Arc::new(Mutex::new(gossip_engine)),
        bundle_receiver,
    );

    gossip_worker.run().await
}
