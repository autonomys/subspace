//! PoT gossip functionality.

use crate::state_manager::PotProtocolState;
use futures::{FutureExt, StreamExt};
use parity_scale_codec::Decode;
use parking_lot::{Mutex, RwLock};
use sc_network::config::NonDefaultSetConfig;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Syncing as GossipSyncing, ValidationResult, Validator,
    ValidatorContext,
};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::HashSet;
use std::sync::Arc;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::PotProof;

pub(crate) const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time";

type MessageHash = [u8; 32];

/// PoT gossip components.
#[derive(Clone)]
pub(crate) struct PotGossip<Block: BlockT> {
    engine: Arc<Mutex<GossipEngine<Block>>>,
    validator: Arc<PotGossipValidator>,
}

impl<Block: BlockT> PotGossip<Block> {
    /// Creates the gossip components.
    pub(crate) fn new<Network, GossipSync>(
        network: Network,
        sync: Arc<GossipSync>,
        pot_state: Arc<dyn PotProtocolState>,
    ) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let validator = Arc::new(PotGossipValidator::new(pot_state));
        let engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            GOSSIP_PROTOCOL,
            validator.clone(),
            None,
        )));
        Self { engine, validator }
    }

    /// Gossips the message to the network.
    pub(crate) fn gossip_message(&self, message: Vec<u8>) {
        self.validator.on_broadcast(&message);
        self.engine
            .lock()
            .gossip_message(topic::<Block>(), message, false);
    }

    /// Runs the loop to process incoming messages.
    /// Returns when the gossip engine terminates.
    pub(crate) async fn process_incoming_messages<'a>(
        &self,
        process_fn: Arc<dyn Fn(PeerId, PotProof) + Send + Sync + 'a>,
    ) {
        let message_receiver = self.engine.lock().messages_for(topic::<Block>());
        let mut incoming_messages = Box::pin(message_receiver.filter_map(
            // Filter out messages without sender or fail to decode.
            // TODO: penalize nodes that send garbled messages.
            |notification| async move {
                let mut ret = None;
                if let Some(sender) = notification.sender {
                    if let Ok(msg) = PotProof::decode(&mut &notification.message[..]) {
                        ret = Some((sender, msg))
                    }
                }
                ret
            },
        ));

        loop {
            futures::select! {
                gossiped = incoming_messages.next().fuse() => {
                    if let Some((sender, proof)) = gossiped {
                        (process_fn)(sender, proof);
                    }
                },
                 _ = self.wait_for_termination().fuse() => {
                    return;
                }
            }
        }
    }

    /// Waits for gossip engine to terminate.
    async fn wait_for_termination(&self) {
        let poll_fn = futures::future::poll_fn(|cx| self.engine.lock().poll_unpin(cx));
        poll_fn.await;
    }
}

/// Validator for gossiped messages
struct PotGossipValidator {
    pot_state: Arc<dyn PotProtocolState>,
    pending: RwLock<HashSet<MessageHash>>,
}

impl PotGossipValidator {
    /// Creates the validator.
    fn new(pot_state: Arc<dyn PotProtocolState>) -> Self {
        Self {
            pot_state,
            pending: RwLock::new(HashSet::new()),
        }
    }

    /// Called when the message is broadcast.
    fn on_broadcast(&self, msg: &[u8]) {
        let hash = blake2b_256_hash(msg);
        let mut pending = self.pending.write();
        pending.insert(hash);
    }
}

impl<Block: BlockT> Validator<Block> for PotGossipValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match PotProof::decode(&mut data) {
            Ok(proof) => {
                if self.pot_state.is_candidate(*sender, &proof).is_ok() {
                    ValidationResult::ProcessAndKeep(topic::<Block>())
                } else {
                    ValidationResult::Discard
                }
            }
            Err(_) => ValidationResult::Discard,
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let hash = blake2b_256_hash(data);
            let pending = self.pending.read();
            !pending.contains(&hash)
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, data| {
            let hash = blake2b_256_hash(data);
            let mut pending = self.pending.write();
            if pending.contains(&hash) {
                pending.remove(&hash);
                true
            } else {
                false
            }
        })
    }
}

/// PoT message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"subspace-proof-of-time-gossip")
}

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}
