//! PoT gossip functionality.

use crate::source::state::PotState;
use crate::verifier::PotVerifier;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::config::NonDefaultSetConfig;
use sc_network::{NetworkPeers, NotificationService, PeerId};
use sc_network_gossip::{
    GossipEngine, MessageIntent, Network as GossipNetwork, Syncing as GossipSyncing,
    ValidationResult, Validator, ValidatorContext,
};
use schnellru::{ByLength, LruMap};
use sp_consensus::SyncOracle;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::PotNextSlotInput;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::num::NonZeroU32;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::{PotCheckpoints, PotSeed};
use tracing::{debug, error, trace, warn};

/// How many slots can proof be before it is too far
const MAX_SLOTS_IN_THE_FUTURE: u64 = 10;
/// How much faster PoT verification is expected to be comparing to PoT proving
const EXPECTED_POT_VERIFICATION_SPEEDUP: usize = 7;
const GOSSIP_CACHE_PEER_COUNT: u32 = 1_000;
const GOSSIP_CACHE_PER_PEER_SIZE: usize = 20;

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
    /// Reputation change when a peer sends us too many proofs.
    pub(super) const GOSSIP_TOO_MANY_PROOFS: ReputationChange =
        ReputationChange::new(-(1 << 5), "PoT: too many proofs");
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
pub fn pot_gossip_peers_set_config() -> (
    NonDefaultSetConfig,
    Box<dyn sc_network::NotificationService>,
) {
    let (mut cfg, notification_service) = NonDefaultSetConfig::new(
        GOSSIP_PROTOCOL.into(),
        Vec::new(),
        1024,
        None,
        Default::default(),
    );
    cfg.allow_non_reserved(25, 25);
    (cfg, notification_service)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encode, Decode)]
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

#[derive(Debug)]
pub(super) enum ToGossipMessage {
    Proof(GossipProof),
    NextSlotInput(PotNextSlotInput),
}

/// PoT gossip worker
#[must_use = "Gossip worker doesn't do anything unless run() method is called"]
pub struct PotGossipWorker<Block>
where
    Block: BlockT,
{
    engine: Arc<Mutex<GossipEngine<Block>>>,
    network: Arc<dyn NetworkPeers + Send + Sync>,
    topic: Block::Hash,
    state: Arc<PotState>,
    pot_verifier: PotVerifier,
    gossip_cache: LruMap<PeerId, VecDeque<GossipProof>>,
    to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
    from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
}

impl<Block> PotGossipWorker<Block>
where
    Block: BlockT,
{
    /// Instantiate gossip worker
    // TODO: Struct for arguments
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<Network, GossipSync, SO>(
        to_gossip_receiver: mpsc::Receiver<ToGossipMessage>,
        from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
        pot_verifier: PotVerifier,
        state: Arc<PotState>,
        network: Network,
        notification_service: Box<dyn NotificationService>,
        sync: Arc<GossipSync>,
        sync_oracle: SO,
    ) -> Self
    where
        Network: GossipNetwork<Block> + NetworkPeers + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
        SO: SyncOracle + Send + Sync + 'static,
    {
        let topic = <Block::Header as HeaderT>::Hashing::hash(b"proofs");

        let validator = Arc::new(PotGossipValidator::new(
            Arc::clone(&state),
            topic,
            sync_oracle,
            network.clone(),
        ));
        let engine = GossipEngine::new(
            network.clone(),
            sync,
            notification_service,
            GOSSIP_PROTOCOL,
            validator,
            None,
        );

        Self {
            engine: Arc::new(Mutex::new(engine)),
            network: Arc::new(network),
            topic,
            state,
            pot_verifier,
            gossip_cache: LruMap::new(ByLength::new(GOSSIP_CACHE_PEER_COUNT)),
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
        let incoming_unverified_messages =
            pin!(message_receiver.filter_map(|notification| async move {
                notification.sender.map(|sender| {
                    let proof = GossipProof::decode(&mut notification.message.as_ref())
                        .expect("Only valid messages get here; qed");

                    (sender, proof)
                })
            }));
        let mut incoming_unverified_messages = incoming_unverified_messages.fuse();

        loop {
            let mut gossip_engine_poll = poll_fn(|cx| self.engine.lock().poll_unpin(cx)).fuse();

            futures::select! {
                (sender, proof) = incoming_unverified_messages.select_next_some() => {
                    self.handle_proof_candidate(sender, proof).await;
                },
                message = self.to_gossip_receiver.select_next_some() => {
                    self.handle_to_gossip_messages(message).await
                },
                 _ = gossip_engine_poll => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
    }

    async fn handle_proof_candidate(&mut self, sender: PeerId, proof: GossipProof) {
        let next_slot_input = self.state.next_slot_input();

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
                    .try_get_checkpoints(proof.slot_iterations, proof.seed)
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

                if let Some(proofs) = self.gossip_cache.get_or_insert(sender, Default::default) {
                    if proofs.len() == GOSSIP_CACHE_PER_PEER_SIZE {
                        if let Some(proof) = proofs.pop_front() {
                            trace!(
                                %sender,
                                slot = %proof.slot,
                                next_slot = %next_slot_input.slot,
                                "Too many proofs stored from peer",
                            );

                            self.engine
                                .lock()
                                .report(sender, rep::GOSSIP_TOO_MANY_PROOFS);
                        }
                    }
                    proofs.push_back(proof);
                    return;
                }
            }
        }

        if self.pot_verifier.verify_checkpoints(
            proof.seed,
            proof.slot_iterations,
            &proof.checkpoints,
        ) {
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
    async fn handle_next_slot_input(&mut self, next_slot_input: PotNextSlotInput) {
        let mut old_proofs = HashMap::<GossipProof, Vec<PeerId>>::new();

        for (sender, proofs) in &mut self.gossip_cache.iter_mut() {
            proofs.retain(|proof| {
                if proof.slot > next_slot_input.slot {
                    true
                } else {
                    old_proofs.entry(*proof).or_default().push(*sender);
                    false
                }
            });
        }

        let mut potentially_matching_proofs = Vec::new();

        for (proof, senders) in old_proofs {
            if proof.slot != next_slot_input.slot {
                let invalid_proof = self
                    .pot_verifier
                    .try_get_checkpoints(proof.slot_iterations, proof.seed)
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
            let network = Arc::clone(&self.network);
            let pot_verifier = self.pot_verifier.clone();
            let from_gossip_sender = self.from_gossip_sender.clone();
            let topic = self.topic;

            move || {
                Self::handle_potentially_matching_proofs(
                    next_slot_input,
                    potentially_matching_proofs,
                    engine,
                    network.as_ref(),
                    &pot_verifier,
                    from_gossip_sender,
                    topic,
                );
            }
        });
    }

    fn handle_potentially_matching_proofs(
        next_slot_input: PotNextSlotInput,
        mut potentially_matching_proofs: Vec<(GossipProof, Vec<PeerId>)>,
        engine: Arc<Mutex<GossipEngine<Block>>>,
        network: &dyn NetworkPeers,
        pot_verifier: &PotVerifier,
        mut from_gossip_sender: mpsc::Sender<(PeerId, GossipProof)>,
        topic: Block::Hash,
    ) {
        if potentially_matching_proofs.is_empty() {
            // Nothing left to do
            return;
        }

        // This sorts from lowest reputation to highest
        potentially_matching_proofs.sort_by_cached_key(|(_proof, peer_ids)| {
            peer_ids
                .iter()
                .map(|peer_id| network.peer_reputation(peer_id))
                .max()
        });

        // If we have too many unique proofs to verify it might be cheaper to prove it ourselves
        let correct_proof = if potentially_matching_proofs.len() < EXPECTED_POT_VERIFICATION_SPEEDUP
        {
            let mut correct_proof = None;

            // Verify all proofs, starting with those sent by most reputable peers
            for (proof, _senders) in potentially_matching_proofs.iter().rev() {
                if pot_verifier.verify_checkpoints(
                    proof.seed,
                    proof.slot_iterations,
                    &proof.checkpoints,
                ) {
                    correct_proof.replace(*proof);
                    break;
                }
            }

            correct_proof
        } else {
            // Last proof includes peer with the highest reputation
            let (proof, _senders) = potentially_matching_proofs
                .last()
                .expect("Guaranteed to be non-empty; qed");

            if pot_verifier.verify_checkpoints(
                proof.seed,
                proof.slot_iterations,
                &proof.checkpoints,
            ) {
                Some(*proof)
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

                    engine.lock().gossip_message(topic, proof.encode(), false);

                    if let Err(error) =
                        futures::executor::block_on(from_gossip_sender.send((sender, proof)))
                    {
                        warn!(
                            %error,
                            slot = %proof.slot,
                            "Failed to send future proof",
                        );
                    }
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
                let next_slot_input = self.state.next_slot_input();
                let current_slot = next_slot_input.slot - Slot::from(1);

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
        let current_slot = u64::from(self.state.next_slot_input().slot) - 1;
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
