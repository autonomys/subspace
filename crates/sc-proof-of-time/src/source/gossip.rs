//! PoT gossip functionality.

use crate::source::state::{NextSlotInput, PotState};
use crate::verifier::PotVerifier;
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::{FutureExt, SinkExt, StreamExt};
use lru::LruCache;
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
use std::collections::HashMap;
use std::future::poll_fn;
use std::hash::{Hash, Hasher};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{atomic, Arc};
use subspace_core_primitives::{PotCheckpoints, PotSeed, SlotNumber};
use tracing::{debug, error, trace, warn};

/// How many slots can proof be before it is too far
const MAX_SLOTS_IN_THE_FUTURE: u64 = 10;
/// How much faster PoT verification is expected to be comparing to PoT proving
const EXPECTED_POT_VERIFICATION_SPEEDUP: usize = 7;
const GOSSIP_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000).expect("Not zero; qed");

mod rep {
    use sc_network::ReputationChange;

    /// Reputation change when a peer sends us a gossip message that can't be decoded.
    pub(super) const GOSSIP_NOT_DECODABLE: ReputationChange =
        ReputationChange::new(-(1 << 3), "PoT: not decodable");
    /// Reputation change when a peer sends us proof that do not match next slot inputs.
    pub(super) const GOSSIP_NEXT_SLOT_MISMATCH: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: next slot mismatch");
    /// Reputation change when a peer sends us proof that correspond to old slot.
    pub(super) const GOSSIP_OLD_SLOT: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: old slot");
    /// Reputation change when a peer sends us proof that correspond to slot that is too far
    /// in the future.
    pub(super) const GOSSIP_TOO_FAR_IN_THE_FUTURE: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: slot too far in the future");
    /// Reputation change when a peer sends us proof that correspond to slot iterations
    /// outside of range.
    pub(super) const GOSSIP_SLOT_ITERATIONS_OUTSIDE_OF_RANGE: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: slot iterations outside of range");
    /// Reputation change when a peer sends us proof that was unused and ended up becoming
    /// outdated.
    pub(super) const GOSSIP_OUTDATED_PROOF: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: outdated proof");
    /// Reputation change when a peer sends us proof that were unused and ended up not
    /// matching slot inputs.
    pub(super) const GOSSIP_SLOT_INPUT_MISMATCH: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: slot input mismatch");
    /// Reputation change when a peer sends us an invalid proof.
    pub(super) const GOSSIP_INVALID_PROOF: ReputationChange =
        ReputationChange::new_fatal("PoT: Invalid proof");
}

const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time/1";

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
pub(super) struct GossipProof {
    /// Slot number
    pub(super) slot: Slot,
    /// Proof of time seed
    pub(super) seed: PotSeed,
    /// Iterations per slot
    pub(super) slot_iterations: NonZeroU32,
    /// Proof of time checkpoints
    pub(super) checkpoints: PotCheckpoints,
}

// TODO: Replace with derive once `Slot` implements `Hash`
impl Hash for GossipProof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        SlotNumber::from(self.slot).hash(state);
        self.seed.hash(state);
        self.slot_iterations.hash(state);
        self.checkpoints.hash(state);
    }
}

#[derive(Debug)]
pub(super) enum ToGossipMessage {
    Proof(GossipProof),
    NextSlotInput(NextSlotInput),
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
    gossip_cache: LruCache<PeerId, Vec<GossipProof>>,
    to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
    from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
}

impl<Block> PotGossipWorker<Block>
where
    Block: BlockT,
{
    /// Instantiate gossip worker
    pub(super) fn new<Network, GossipSync, SO>(
        to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
        from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
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
        let topic = <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"proofs");

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
            gossip_cache: LruCache::new(GOSSIP_CACHE_SIZE),
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
                        let proof = GossipProof::decode(&mut notification.message.as_ref())
                            .expect("Only valid messages get here; qed");

                        (sender, proof)
                    })
                })
                .fuse(),
        );

        loop {
            let gossip_engine_poll = poll_fn(|cx| self.engine.lock().poll_unpin(cx));
            futures::select! {
                incoming_message = incoming_unverified_messages.next() => {
                    if let Some((sender, message)) = incoming_message {
                        self.handle_proof_candidate(sender, message).await;
                    }
                },
                outgoing_message = self.to_gossip_receiver.select_next_some() => {
                    self.handle_to_gossip_messages(outgoing_message).await
                },
                 _ = gossip_engine_poll.fuse() => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
    }

    async fn handle_proof_candidate(&mut self, sender: PeerId, proof: GossipProof) {
        let next_slot_input = self.state.next_slot_input(atomic::Ordering::Relaxed);

        match proof.slot.cmp(&next_slot_input.slot) {
            cmp::Ordering::Less => {
                trace!(
                    %sender,
                    slot = %proof.slot,
                    next_slot = %next_slot_input.slot,
                    "Proof for outdated slot, ignoring",
                );

                if let Some(verified_checkpoints) = self
                    .pot_verifier
                    .try_get_checkpoints(proof.seed, proof.slot_iterations)
                {
                    if verified_checkpoints != proof.checkpoints {
                        trace!(
                            %sender,
                            slot = %proof.slot,
                            "Invalid old proof, punishing sender",
                        );

                        self.engine.lock().report(sender, rep::GOSSIP_INVALID_PROOF);
                    }
                } else {
                    // We didn't use it, but also didn't bother verifying
                    self.engine
                        .lock()
                        .report(sender, rep::GOSSIP_OUTDATED_PROOF);
                }

                return;
            }
            cmp::Ordering::Equal => {
                if !(proof.seed == next_slot_input.seed
                    && proof.slot_iterations == next_slot_input.slot_iterations)
                {
                    trace!(
                        %sender,
                        slot = %proof.slot,
                        "Proof with next slot mismatch, ignoring",
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
                    slot = %proof.slot,
                    next_slot = %next_slot_input.slot,
                    "Proof from the future",
                );

                self.gossip_cache
                    .get_or_insert_mut(sender, Default::default)
                    .push(proof);
                return;
            }
        }

        if self
            .pot_verifier
            .verify_checkpoints(proof.seed, proof.slot_iterations, &proof.checkpoints)
            .await
        {
            debug!(%sender, slot = %proof.slot, "Full verification succeeded");

            self.engine
                .lock()
                .gossip_message(self.topic, proof.encode(), false);

            if let Err(error) = self.from_gossip_sender.send((sender, proof)).await {
                warn!(%error, "Failed to send incoming message");
            }
        } else {
            debug!(%sender, slot = %proof.slot, "Full verification failed");
            self.engine.lock().report(sender, rep::GOSSIP_INVALID_PROOF);
        }
    }

    async fn handle_to_gossip_messages(&mut self, message: ToGossipMessage) {
        match message {
            ToGossipMessage::Proof(proof) => {
                self.engine
                    .lock()
                    .gossip_message(self.topic, proof.encode(), false);
            }
            ToGossipMessage::NextSlotInput(next_slot_input) => {
                self.handle_next_slot_input(next_slot_input).await;
            }
        }
    }

    /// Handle next slot input and try to remove outdated proofs information from internal cache as
    /// well as produce next proof if it was already received out of order before
    async fn handle_next_slot_input(&mut self, next_slot_input: NextSlotInput) {
        let mut old_proofs = HashMap::<GossipProof, Vec<PeerId>>::new();
        for (sender, proofs) in &mut self.gossip_cache {
            for proof in proofs.extract_if(|proof| proof.slot <= next_slot_input.slot) {
                old_proofs.entry(proof).or_default().push(*sender);
            }
        }

        let mut potentially_matching_proofs = Vec::new();

        for (proof, senders) in old_proofs {
            if proof.slot != next_slot_input.slot {
                let invalid_proof = self
                    .pot_verifier
                    .try_get_checkpoints(proof.seed, proof.slot_iterations)
                    .map(|verified_checkpoints| verified_checkpoints != proof.checkpoints)
                    .unwrap_or_default();

                let engine = self.engine.lock();
                if invalid_proof {
                    for sender in senders {
                        trace!(
                            %sender,
                            slot = %proof.slot,
                            "Proof ended up being invalid",
                        );

                        engine.report(sender, rep::GOSSIP_INVALID_PROOF);
                    }
                } else {
                    for sender in senders {
                        trace!(
                            %sender,
                            slot = %proof.slot,
                            "Proof ended up being unused",
                        );

                        engine.report(sender, rep::GOSSIP_OUTDATED_PROOF);
                    }
                }

                continue;
            }

            if !(proof.seed == next_slot_input.seed
                && proof.slot_iterations == next_slot_input.slot_iterations)
            {
                let engine = self.engine.lock();
                for sender in senders {
                    trace!(
                        %sender,
                        slot = %proof.slot,
                        "Proof ended up not matching slot inputs",
                    );

                    engine.report(sender, rep::GOSSIP_SLOT_INPUT_MISMATCH);
                }

                continue;
            }

            potentially_matching_proofs.push((proof, senders));
        }

        // Avoid blocking gossip for too long
        rayon::spawn({
            let engine = Arc::clone(&self.engine);
            let pot_verifier = self.pot_verifier.clone();
            let from_gossip_sender = self.from_gossip_sender.clone();
            let topic = self.topic;

            move || {
                block_on(Self::handle_potentially_matching_proofs(
                    next_slot_input,
                    potentially_matching_proofs,
                    engine,
                    &pot_verifier,
                    from_gossip_sender,
                    topic,
                ));
            }
        });
    }

    async fn handle_potentially_matching_proofs(
        next_slot_input: NextSlotInput,
        potentially_matching_proofs: Vec<(GossipProof, Vec<PeerId>)>,
        engine: Arc<Mutex<GossipEngine<Block>>>,
        pot_verifier: &PotVerifier,
        mut from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
        topic: Block::Hash,
    ) {
        if potentially_matching_proofs.is_empty() {
            // Nothing left to do
            return;
        }

        // If we have too many unique proofs to verify it might be cheaper to prove it ourselves
        let correct_proof = if potentially_matching_proofs.len() < EXPECTED_POT_VERIFICATION_SPEEDUP
        {
            let mut correct_proof = None;

            // Verify all proofs
            for (proof, _senders) in &potentially_matching_proofs {
                if pot_verifier
                    .verify_checkpoints(proof.seed, proof.slot_iterations, &proof.checkpoints)
                    .await
                {
                    correct_proof.replace(*proof);
                    break;
                }
            }

            correct_proof
        } else {
            match subspace_proof_of_time::prove(
                next_slot_input.seed,
                next_slot_input.slot_iterations,
            ) {
                Ok(checkpoints) => Some(GossipProof {
                    slot: next_slot_input.slot,
                    seed: next_slot_input.seed,
                    slot_iterations: next_slot_input.slot_iterations,
                    checkpoints,
                }),
                Err(error) => {
                    error!(
                        %error,
                        slot = %next_slot_input.slot,
                        "Failed to run proof of time, this is an implementation bug",
                    );
                    return;
                }
            }
        };

        for (proof, senders) in potentially_matching_proofs {
            if Some(proof) == correct_proof {
                let mut sent = false;
                for sender in senders {
                    debug!(%sender, slot = %proof.slot, "Correct future proof");

                    if sent {
                        continue;
                    }
                    sent = true;

                    if let Err(error) = from_gossip_sender.send((sender, proof)).await {
                        warn!(
                            %error,
                            slot = %proof.slot,
                            "Failed to send future proof",
                        );
                    }

                    engine.lock().gossip_message(topic, proof.encode(), false);
                }
            } else {
                let engine = engine.lock();
                for sender in senders {
                    debug!(%sender, slot = %proof.slot, "Next slot proof is invalid");
                    engine.report(sender, rep::GOSSIP_INVALID_PROOF);
                }
            }
        }
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

        match GossipProof::decode(&mut data) {
            Ok(proof) => {
                let next_slot_input = self.state.next_slot_input(atomic::Ordering::Relaxed);
                let current_slot = Slot::from(u64::from(next_slot_input.slot) - 1);

                if proof.slot < current_slot {
                    trace!(
                        %sender,
                        slot = %proof.slot,
                        "Received proof for old slot, ignoring",
                    );

                    self.network.report_peer(*sender, rep::GOSSIP_OLD_SLOT);
                    return ValidationResult::Discard;
                }
                if proof.slot > current_slot + Slot::from(MAX_SLOTS_IN_THE_FUTURE) {
                    trace!(
                        %sender,
                        slot = %proof.slot,
                        "Received proof for slot too far in the future, ignoring",
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_TOO_FAR_IN_THE_FUTURE);
                    return ValidationResult::Discard;
                }
                // Next slot matches expectations, but other inputs are not
                if proof.slot == next_slot_input.slot
                    && !(proof.seed == next_slot_input.seed
                        && proof.slot_iterations == next_slot_input.slot_iterations)
                {
                    trace!(
                        %sender,
                        slot = %proof.slot,
                        "Received proof with next slot mismatch, ignoring",
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_NEXT_SLOT_MISMATCH);
                    return ValidationResult::Discard;
                }

                let current_slot_iterations = next_slot_input.slot_iterations;

                // Check that number of slot iterations is between current and 1.5 of current slot
                // iterations
                if proof.slot_iterations.get() < next_slot_input.slot_iterations.get()
                    || proof.slot_iterations.get() > current_slot_iterations.get() * 3 / 2
                {
                    debug!(
                        %sender,
                        slot = %proof.slot,
                        slot_iterations = %proof.slot_iterations,
                        current_slot_iterations = %current_slot_iterations,
                        "Slot iterations outside of reasonable range"
                    );

                    self.network
                        .report_peer(*sender, rep::GOSSIP_SLOT_ITERATIONS_OUTSIDE_OF_RANGE);
                    return ValidationResult::Discard;
                }

                trace!(%sender, slot = %proof.slot, "Superficial verification succeeded");

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
            if let Ok(proof) = GossipProof::decode(&mut data) {
                // Slot is the only meaningful expiration policy here
                if proof.slot >= current_slot {
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
