//! PoT gossip functionality.

use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use futures::channel::mpsc;
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
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
use std::time::Instant;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{Blake2b256Hash, PotProof};
use subspace_proof_of_time::ProofOfTime;
use tracing::{error, trace};

pub(crate) const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time";

/// PoT gossip worker
#[must_use = "Gossip worker doesn't do anything unless run() method is called"]
pub struct PotGossipWorker<Block>
where
    Block: BlockT,
{
    engine: Arc<Mutex<GossipEngine<Block>>>,
    validator: Arc<PotGossipValidator<Block>>,
    pot_state: Arc<dyn PotProtocolState>,
    topic: Block::Hash,
    outgoing_messages_sender: mpsc::Sender<PotProof>,
    outgoing_messages_receiver: mpsc::Receiver<PotProof>,
}

impl<Block> PotGossipWorker<Block>
where
    Block: BlockT,
{
    /// Instantiate gossip worker
    pub fn new<Network, GossipSync>(
        components: &PotComponents,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let topic =
            <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"subspace-proof-of-time-gossip");

        let validator = Arc::new(PotGossipValidator::new(
            Arc::clone(&components.protocol_state),
            components.proof_of_time,
            topic,
        ));
        let engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            GOSSIP_PROTOCOL,
            validator.clone(),
            None,
        )));

        let (outgoing_messages_sender, outgoing_messages_receiver) = mpsc::channel(0);

        Self {
            engine,
            validator,
            pot_state: Arc::clone(&components.protocol_state),
            topic,
            outgoing_messages_sender,
            outgoing_messages_receiver,
        }
    }

    /// Sender that can be used to gossip PoT messages to the network
    pub fn gossip_sender(&self) -> mpsc::Sender<PotProof> {
        self.outgoing_messages_sender.clone()
    }

    /// Run gossip engine.
    ///
    /// NOTE: Even though this function is async, it might do blocking operations internally and
    /// should be running on a dedicated thread.
    pub async fn run(mut self) {
        let message_receiver = self.engine.lock().messages_for(self.topic);
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
            let gossip_engine_poll =
                futures::future::poll_fn(|cx| self.engine.lock().poll_unpin(cx));
            futures::select! {
                gossiped = incoming_messages.next().fuse() => {
                    if let Some((sender, proof)) = gossiped {
                        self.handle_incoming_message(sender, proof);
                    }
                },
                outgoing_message = self.outgoing_messages_receiver.select_next_some() => {
                    self.handle_outgoing_message(outgoing_message)
                },
                 _ = gossip_engine_poll.fuse() => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
    }

    /// Handles the incoming gossip message.
    fn handle_incoming_message(&self, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = self.pot_state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(error) = ret {
            trace!(%error, %sender, "On gossip");
        } else {
            trace!(%proof, ?elapsed, %sender, "On gossip");
            self.engine
                .lock()
                .gossip_message(self.topic, proof.encode(), false);
        }
    }

    fn handle_outgoing_message(&self, proof: PotProof) {
        let message = proof.encode();
        self.validator.on_broadcast(&message);
        self.engine
            .lock()
            .gossip_message(self.topic, message, false);
    }
}

/// Validator for gossiped messages
struct PotGossipValidator<Block>
where
    Block: BlockT,
{
    pot_state: Arc<dyn PotProtocolState>,
    proof_of_time: ProofOfTime,
    pending: RwLock<HashSet<Blake2b256Hash>>,
    topic: Block::Hash,
}

impl<Block> PotGossipValidator<Block>
where
    Block: BlockT,
{
    /// Creates the validator.
    fn new(
        pot_state: Arc<dyn PotProtocolState>,
        proof_of_time: ProofOfTime,
        topic: Block::Hash,
    ) -> Self {
        Self {
            pot_state,
            proof_of_time,
            pending: RwLock::new(HashSet::new()),
            topic,
        }
    }

    /// Called when the message is broadcast.
    fn on_broadcast(&self, msg: &[u8]) {
        let hash = blake2b_256_hash(msg);
        self.pending.write().insert(hash);
    }
}

impl<Block> Validator<Block> for PotGossipValidator<Block>
where
    Block: BlockT,
{
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match PotProof::decode(&mut data) {
            Ok(proof) => {
                // Perform AES verification only if the proof is a candidate.
                if let Err(error) = self.pot_state.is_candidate(*sender, &proof) {
                    trace!(%error, "Not a candidate");
                    ValidationResult::Discard
                } else if let Err(error) = self.proof_of_time.verify(&proof) {
                    trace!(%error, "Verification failed");
                    ValidationResult::Discard
                } else {
                    ValidationResult::ProcessAndKeep(self.topic)
                }
            }
            Err(_) => ValidationResult::Discard,
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let hash = blake2b_256_hash(data);
            !self.pending.read().contains(&hash)
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, data| {
            let hash = blake2b_256_hash(data);
            self.pending.write().remove(&hash)
        })
    }
}

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}
