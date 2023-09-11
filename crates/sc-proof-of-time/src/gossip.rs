//! PoT gossip functionality.

use crate::verifier::PotVerifier;
use atomic::Atomic;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::config::NonDefaultSetConfig;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Network as GossipNetwork, Syncing as GossipSyncing,
    ValidationResult, Validator, ValidatorContext,
};
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::future::poll_fn;
use std::num::NonZeroU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use subspace_core_primitives::{PotCheckpoints, PotSeed};
use tracing::{debug, error, trace, warn};

const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time/1";

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub(crate) struct GossipCheckpoints {
    /// Slot number
    pub(crate) slot: Slot,
    /// Proof of time seed
    pub(crate) seed: PotSeed,
    /// Iterations per slot
    pub(crate) slot_iterations: NonZeroU32,
    /// Proof of time checkpoints
    pub(crate) checkpoints: PotCheckpoints,
}

/// PoT gossip worker
#[must_use = "Gossip worker doesn't do anything unless run() method is called"]
pub struct PotGossipWorker<Block>
where
    Block: BlockT,
{
    engine: Arc<Mutex<GossipEngine<Block>>>,
    topic: Block::Hash,
    outgoing_messages_receiver: mpsc::Receiver<GossipCheckpoints>,
    incoming_messages_sender: mpsc::Sender<(PeerId, GossipCheckpoints)>,
}

impl<Block> PotGossipWorker<Block>
where
    Block: BlockT,
{
    /// Instantiate gossip worker
    pub(crate) fn new<Network, GossipSync>(
        outgoing_messages_receiver: mpsc::Receiver<GossipCheckpoints>,
        incoming_messages_sender: mpsc::Sender<(PeerId, GossipCheckpoints)>,
        pot_verifier: PotVerifier,
        current_slot_iterations: Arc<Atomic<NonZeroU32>>,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> Self
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let topic = <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"checkpoints");

        let validator = Arc::new(PotGossipValidator::new(
            pot_verifier,
            current_slot_iterations,
            topic,
        ));
        let engine = GossipEngine::new(network, sync, GOSSIP_PROTOCOL, validator, None);

        Self {
            engine: Arc::new(Mutex::new(engine)),
            topic,
            outgoing_messages_receiver,
            incoming_messages_sender,
        }
    }

    /// Run gossip engine.
    ///
    /// NOTE: Even though this function is async, it might do blocking operations internally and
    /// should be running on a dedicated thread.
    pub async fn run(mut self) {
        let message_receiver = self.engine.lock().messages_for(self.topic);
        let mut incoming_messages = Box::pin(
            message_receiver
                .filter_map(|notification| async move {
                    notification.sender.map(|sender| {
                        let message = GossipCheckpoints::decode(&mut notification.message.as_ref())
                            .expect("Only valid messages get here; qed");

                        (sender, message)
                    })
                })
                .fuse(),
        );

        loop {
            let gossip_engine_poll = poll_fn(|cx| self.engine.lock().poll_unpin(cx));
            futures::select! {
                incoming_message = incoming_messages.next() => {
                    if let Some((sender, message)) = incoming_message {
                        self.handle_incoming_message(sender, message).await;
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
    async fn handle_incoming_message(&mut self, sender: PeerId, message: GossipCheckpoints) {
        if let Err(error) = self.incoming_messages_sender.send((sender, message)).await {
            warn!(%error, "Failed to send incoming message");
        }
    }

    fn handle_outgoing_message(&self, message: GossipCheckpoints) {
        self.engine
            .lock()
            .gossip_message(self.topic, message.encode(), false);
    }
}

/// Validator for gossiped messages
struct PotGossipValidator<Block>
where
    Block: BlockT,
{
    pot_verifier: PotVerifier,
    current_slot_iterations: Arc<Atomic<NonZeroU32>>,
    topic: Block::Hash,
}

impl<Block> PotGossipValidator<Block>
where
    Block: BlockT,
{
    /// Creates the validator.
    fn new(
        pot_verifier: PotVerifier,
        current_slot_iterations: Arc<Atomic<NonZeroU32>>,
        topic: Block::Hash,
    ) -> Self {
        Self {
            pot_verifier,
            current_slot_iterations,
            topic,
        }
    }
}

impl<Block> Validator<Block> for PotGossipValidator<Block>
where
    Block: BlockT,
{
    fn validate(
        &self,
        context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        // TODO: Skip validation if node is not synced right now

        match GossipCheckpoints::decode(&mut data) {
            Ok(message) => {
                // TODO: Gossip validation should be non-blocking!
                // TODO: Check that slot number is not too far in the past of future
                let current_slot_iterations = self.current_slot_iterations.load(Ordering::Relaxed);

                // Check that number of slot iterations is between 2/3 and 1.5 of current slot
                // iterations, otherwise ignore
                // TODO: Decrease reputation if slot iterations is within range, but doesn't match
                //  exactly
                if message.slot_iterations.get() < current_slot_iterations.get() * 2 / 3
                    || message.slot_iterations.get() > current_slot_iterations.get() * 3 / 2
                {
                    debug!(
                        %sender,
                        slot = %message.slot,
                        slot_iterations = %message.slot_iterations,
                        current_slot_iterations = %current_slot_iterations,
                        "Slot iterations outside of reasonable range"
                    );

                    // TODO: Reputation change
                    return ValidationResult::Discard;
                }

                if tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        self.pot_verifier.verify_checkpoints(
                            message.seed,
                            message.slot_iterations,
                            &message.checkpoints,
                        ),
                    )
                }) {
                    trace!(%sender, slot = %message.slot, "Verification succeeded");
                    context.broadcast_message(self.topic, data.to_vec(), false);
                    ValidationResult::ProcessAndKeep(self.topic)
                } else {
                    debug!(%sender, slot = %message.slot, "Verification failed");
                    // TODO: Reputation change
                    ValidationResult::Discard
                }
            }
            Err(_) => {
                // TODO: Reputation change
                ValidationResult::Discard
            }
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, _data| {
            // TODO: Check that slots are not too far in the past or future, there is no other
            //  inherent expiration policy here
            false
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, intent, _topic, _data| {
            // We do not need force broadcast or rebroadcasting
            matches!(intent, MessageIntent::Broadcast)
        })
    }
}
