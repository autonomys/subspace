//! PoT gossip functionality.

use crate::source::state::PotState;
use crate::verifier::PotVerifier;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::config::NonDefaultSetConfig;
use sc_network::{NetworkPeers, PeerId};
use sc_network_gossip::{
    GossipEngine, MessageIntent, Network as GossipNetwork, Syncing as GossipSyncing,
    ValidationResult, Validator, ValidatorContext,
};
use sp_consensus::SyncOracle;
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::cmp;
use std::future::poll_fn;
use std::num::NonZeroU32;
use std::sync::{atomic, Arc};
use subspace_core_primitives::{PotCheckpoints, PotSeed};
use tracing::{debug, error, trace, warn};

/// How many slots can proof be before it is too far
const MAX_SLOTS_IN_THE_FUTURE: u64 = 10;

mod rep {
    use sc_network::ReputationChange;

    /// Reputation change when a peer sends us a gossip message that can't be decoded.
    pub(super) const GOSSIP_NOT_DECODABLE: ReputationChange =
        ReputationChange::new(-(1 << 3), "PoT: not decodable");
    /// Reputation change when a peer sends us checkpoints that do not match next slot inputs.
    pub(super) const GOSSIP_NEXT_SLOT_MISMATCH: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: next slot mismatch");
    /// Reputation change when a peer sends us checkpoints that correspond to old slot.
    pub(super) const GOSSIP_OLD_SLOT: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: old slot");
    /// Reputation change when a peer sends us checkpoints that correspond to slot that is too far
    /// in the future.
    pub(super) const GOSSIP_TOO_FAR_IN_THE_FUTURE: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: slot too far in the future");
    /// Reputation change when a peer sends us checkpoints that correspond to slot iterations
    /// outside of range.
    pub(super) const GOSSIP_SLOT_ITERATIONS_OUTSIDE_OF_RANGE: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: slot iterations outside of range");
    /// Reputation change when a peer sends us an invalid proof
    pub(super) const GOSSIP_INVALID_CHECKPOINTS: ReputationChange =
        ReputationChange::new_fatal("PoT: Invalid proof");
}

const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time/1";

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub(super) struct GossipCheckpoints {
    /// Slot number
    pub(super) slot: Slot,
    /// Proof of time seed
    pub(super) seed: PotSeed,
    /// Iterations per slot
    pub(super) slot_iterations: NonZeroU32,
    /// Proof of time checkpoints
    pub(super) checkpoints: PotCheckpoints,
}

#[derive(Debug)]
pub(super) enum ToGossipMessage {
    Checkpoints(GossipCheckpoints),
}

/// PoT gossip worker
#[must_use = "Gossip worker doesn't do anything unless run() method is called"]
pub struct PotGossipWorker<Block>
where
    Block: BlockT,
{
    engine: Arc<Mutex<GossipEngine<Block>>>,
    topic: Block::Hash,
    state: Arc<PotState>,
    pot_verifier: PotVerifier,
    to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
    from_gossip_sender: mpsc::Sender<(PeerId, GossipCheckpoints)>,
}

impl<Block> PotGossipWorker<Block>
where
    Block: BlockT,
{
    /// Instantiate gossip worker
    pub(super) fn new<Network, GossipSync, SO>(
        to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
        from_gossip_sender: mpsc::Sender<(PeerId, GossipCheckpoints)>,
        pot_verifier: PotVerifier,
        state: Arc<PotState>,
        network: Network,
        sync: Arc<GossipSync>,
        sync_oracle: SO,
    ) -> Self
    where
        Network: GossipNetwork<Block> + NetworkPeers + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
        SO: SyncOracle + Send + Sync + 'static,
    {
        let topic = <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"checkpoints");

        let validator = Arc::new(PotGossipValidator::new(
            Arc::clone(&state),
            topic,
            sync_oracle,
            network.clone(),
        ));
        let engine = GossipEngine::new(network, sync, GOSSIP_PROTOCOL, validator, None);

        Self {
            engine: Arc::new(Mutex::new(engine)),
            topic,
            state,
            pot_verifier,
            to_gossip_receiver,
            from_gossip_sender,
        }
    }

    /// Run gossip engine.
    ///
    /// NOTE: Even though this function is async, it might do blocking operations internally and
    /// should be running on a dedicated thread.
    pub async fn run(mut self) {
        let message_receiver = self.engine.lock().messages_for(self.topic);
        let mut incoming_unverified_messages = Box::pin(
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
                incoming_message = incoming_unverified_messages.next() => {
                    if let Some((sender, message)) = incoming_message {
                        self.handle_checkpoints_candidates(sender, message).await;
                    }
                },
                outgoing_message = self.to_gossip_receiver.select_next_some() => {
                    self.handle_to_gossip_messages(outgoing_message)
                },
                 _ = gossip_engine_poll.fuse() => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
    }

    async fn handle_checkpoints_candidates(&mut self, sender: PeerId, message: GossipCheckpoints) {
        let next_slot_input = self.state.next_slot_input(atomic::Ordering::Relaxed);

        match message.slot.cmp(&next_slot_input.slot) {
            cmp::Ordering::Less => {
                trace!(
                    %sender,
                    slot = %message.slot,
                    next_slot = %next_slot_input.slot,
                    "Checkpoints for outdated slot, ignoring",
                );

                if let Some(verified_checkpoints) = self
                    .pot_verifier
                    .get_checkpoints(message.seed, message.slot_iterations)
                {
                    if verified_checkpoints != message.checkpoints {
                        trace!(
                            %sender,
                            slot = %message.slot,
                            "Invalid old checkpoints, punishing sender",
                        );

                        self.engine
                            .lock()
                            .report(sender, rep::GOSSIP_INVALID_CHECKPOINTS);
                    }
                }

                return;
            }
            cmp::Ordering::Equal => {
                if !(message.seed == next_slot_input.seed
                    && message.slot_iterations == next_slot_input.slot_iterations)
                {
                    trace!(
                        %sender,
                        slot = %message.slot,
                        "Checkpoints with next slot mismatch, ignoring",
                    );

                    self.engine
                        .lock()
                        .report(sender, rep::GOSSIP_NEXT_SLOT_MISMATCH);
                    return;
                }
            }
            cmp::Ordering::Greater => {
                trace!(
                    %sender,
                    slot = %message.slot,
                    next_slot = %next_slot_input.slot,
                    "Checkpoints from the future",
                );

                // TODO: Store future candidates somewhere for future processing
                return;
            }
        }

        if self
            .pot_verifier
            .verify_checkpoints(message.seed, message.slot_iterations, &message.checkpoints)
            .await
        {
            debug!(%sender, slot = %message.slot, "Full verification succeeded");

            self.gossip_checkpoints(message);

            if let Err(error) = self.from_gossip_sender.send((sender, message)).await {
                warn!(%error, "Failed to send incoming message");
            }
        } else {
            debug!(%sender, slot = %message.slot, "Full verification failed");
            self.engine
                .lock()
                .report(sender, rep::GOSSIP_INVALID_CHECKPOINTS);
        }
    }

    fn handle_to_gossip_messages(&mut self, message: ToGossipMessage) {
        match message {
            ToGossipMessage::Checkpoints(checkpoints) => {
                self.gossip_checkpoints(checkpoints);
            }
        }
    }

    fn gossip_checkpoints(&self, message: GossipCheckpoints) {
        self.engine
            .lock()
            .gossip_message(self.topic, message.encode(), false);
    }
}

/// Validator for gossiped messages
struct PotGossipValidator<Block, SO, Network>
where
    Block: BlockT,
{
    state: Arc<PotState>,
    topic: Block::Hash,
    sync_oracle: SO,
    network: Network,
}

impl<Block, SO, Network> PotGossipValidator<Block, SO, Network>
where
    Block: BlockT,
    SO: SyncOracle,
{
    /// Creates the validator.
    fn new(state: Arc<PotState>, topic: Block::Hash, sync_oracle: SO, network: Network) -> Self {
        Self {
            state,
            topic,
            sync_oracle,
            network,
        }
    }
}

impl<Block, SO, Network> Validator<Block> for PotGossipValidator<Block, SO, Network>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync,
    Network: NetworkPeers + Send + Sync + 'static,
{
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        // Ignore gossip while major syncing
        if self.sync_oracle.is_major_syncing() {
            return ValidationResult::Discard;
        }

        match GossipCheckpoints::decode(&mut data) {
            Ok(message) => {
                let next_slot_input = self.state.next_slot_input(atomic::Ordering::Relaxed);
                let current_slot = Slot::from(u64::from(next_slot_input.slot) - 1);

                if message.slot < current_slot {
                    trace!(
                        %sender,
                        slot = %message.slot,
                        "Received checkpoints for old slot, ignoring",
                    );

                    self.network.report_peer(*sender, rep::GOSSIP_OLD_SLOT);
                    return ValidationResult::Discard;
                }
                if message.slot > current_slot + Slot::from(MAX_SLOTS_IN_THE_FUTURE) {
                    trace!(
                        %sender,
                        slot = %message.slot,
                        "Received checkpoints for slot too far in the future, ignoring",
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_TOO_FAR_IN_THE_FUTURE);
                    return ValidationResult::Discard;
                }
                // Next slot matches expectations, but other inputs are not
                if message.slot == next_slot_input.slot
                    && !(message.seed == next_slot_input.seed
                        && message.slot_iterations == next_slot_input.slot_iterations)
                {
                    trace!(
                        %sender,
                        slot = %message.slot,
                        "Received checkpoints with next slot mismatch, ignoring",
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_NEXT_SLOT_MISMATCH);
                    return ValidationResult::Discard;
                }

                let current_slot_iterations = next_slot_input.slot_iterations;

                // Check that number of slot iterations is between current and 1.5 of current slot
                // iterations
                if message.slot_iterations.get() < next_slot_input.slot_iterations.get()
                    || message.slot_iterations.get() > current_slot_iterations.get() * 3 / 2
                {
                    debug!(
                        %sender,
                        slot = %message.slot,
                        slot_iterations = %message.slot_iterations,
                        current_slot_iterations = %current_slot_iterations,
                        "Slot iterations outside of reasonable range"
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_SLOT_ITERATIONS_OUTSIDE_OF_RANGE);
                    return ValidationResult::Discard;
                }

                trace!(%sender, slot = %message.slot, "Superficial verification succeeded");

                // We will fully validate and re-gossip it explicitly later if necessary
                ValidationResult::ProcessAndDiscard(self.topic)
            }
            Err(error) => {
                debug!(%error, "Gossip message couldn't be decoded");

                self.network.report_peer(*sender, rep::GOSSIP_NOT_DECODABLE);
                ValidationResult::Discard
            }
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        let current_slot =
            u64::from(self.state.next_slot_input(atomic::Ordering::Relaxed).slot) - 1;
        Box::new(move |_topic, mut data| {
            if let Ok(message) = GossipCheckpoints::decode(&mut data) {
                // Slot is the only meaningful expiration policy here
                if message.slot >= current_slot {
                    return false;
                }
            }

            true
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
