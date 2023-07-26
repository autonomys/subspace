//! PoT state management.

use crate::utils::LOG_TARGET;
use crate::{PotConfig, PotConsensus, PotConsensusError};
use parking_lot::Mutex;
use sc_network::PeerId;
use sp_runtime::traits::{Block as BlockT, NumberFor, One};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_core_primitives::{NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PotStateError {
    #[error("Failed to extend chain: {expected}/{actual}")]
    TipMismatch {
        expected: SlotNumber,
        actual: SlotNumber,
    },

    #[error("Proof for an older slot number: {tip_slot}/{proof_slot}")]
    StaleProof {
        tip_slot: SlotNumber,
        proof_slot: SlotNumber,
    },

    #[error("Proof had an unexpected seed: {expected:?}/{actual:?}")]
    InvalidSeed { expected: PotSeed, actual: PotSeed },

    #[error("Proof had an unexpected key: {expected:?}/{actual:?}")]
    InvalidKey { expected: PotKey, actual: PotKey },

    #[error("Proof verification failed: {0:?}")]
    InvalidProof(PotVerificationError),

    #[error("Proof is too much into future: {tip_slot}/{proof_slot}")]
    TooFuturistic {
        tip_slot: SlotNumber,
        proof_slot: SlotNumber,
    },

    #[error("Duplicate proof from peer: {0:?}")]
    DuplicateProofFromPeer(PeerId),

    #[error("Context mismatch of proof from peer: {0:?}")]
    InvalidContextFromPeer(PeerId),
}

/// Action on extending the tip with a new proof.
#[derive(Debug, Eq, PartialEq)]
enum ExtendAction {
    /// Try to merge pending proofs for future slots.
    MergeFutureProofs,

    /// Don't merge with future proofs.
    NoMerge,
}

/// The shared PoT state.
struct InternalState {
    /// Last N entries of the PotChain, sorted by height.
    chain: Vec<PotProof>,

    /// Proofs for future slot numbers, indexed by slot number.
    /// Each entry holds the proofs indexed by sender.
    future_proofs: BTreeMap<SlotNumber, BTreeMap<PeerId, PotProof>>,
}

/// Wrapper to manage the PoT state.
struct StateManager {
    /// Pot config
    config: PotConfig,

    /// PoT wrapper for verification.
    proof_of_time: Arc<ProofOfTime>,

    /// The PoT state
    state: Mutex<InternalState>,
}

impl StateManager {
    /// Creates the state.
    pub fn new(config: PotConfig, proof_of_time: Arc<ProofOfTime>, chain: Vec<PotProof>) -> Self {
        Self {
            config,
            proof_of_time,
            state: Mutex::new(InternalState {
                chain,
                future_proofs: BTreeMap::new(),
            }),
        }
    }

    /// Extends the chain with the given proof, without verifying it
    /// (e.g) called when clock maker locally produces a proof.
    pub fn extend_chain(&self, proof: &PotProof) -> Result<(), PotStateError> {
        let mut state = self.state.lock();
        let tip = match state.chain.last() {
            Some(tip) => tip,
            None => {
                self.add_to_tip(&mut state, proof, ExtendAction::MergeFutureProofs);
                return Ok(());
            }
        };

        if (tip.slot_number + 1) == proof.slot_number {
            self.add_to_tip(&mut state, proof, ExtendAction::MergeFutureProofs);
            Ok(())
        } else {
            // The tip moved by the time the proof was computed.
            Err(PotStateError::TipMismatch {
                expected: tip.slot_number + 1,
                actual: proof.slot_number,
            })
        }
    }

    /// Extends the chain with the given proof, after verifying it
    /// (e.g) called when the proof is received from a peer via gossip.
    pub fn verify_and_extend_chain(
        &self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotStateError> {
        let mut state = self.state.lock();
        let tip = match state.chain.last() {
            Some(tip) => tip.clone(),
            None => {
                self.proof_of_time
                    .verify(proof)
                    .map_err(PotStateError::InvalidProof)?;
                self.add_to_tip(&mut state, proof, ExtendAction::MergeFutureProofs);
                return Ok(());
            }
        };

        // Case 1: the proof is for an older slot
        if proof.slot_number <= tip.slot_number {
            return Err(PotStateError::StaleProof {
                tip_slot: tip.slot_number,
                proof_slot: proof.slot_number,
            });
        }

        // Case 2: the proof extends the tip
        if (tip.slot_number + 1) == proof.slot_number {
            let expected_seed = tip.next_seed(None);
            if proof.seed != expected_seed {
                return Err(PotStateError::InvalidSeed {
                    expected: expected_seed,
                    actual: proof.seed,
                });
            }

            let expected_key = tip.next_key();
            if proof.key != expected_key {
                return Err(PotStateError::InvalidKey {
                    expected: expected_key,
                    actual: proof.key,
                });
            }

            self.proof_of_time
                .verify(proof)
                .map_err(PotStateError::InvalidProof)?;

            // All checks passed, advance the tip with the new proof
            self.add_to_tip(&mut state, proof, ExtendAction::MergeFutureProofs);
            return Ok(());
        }

        // Case 3: proof for a future slot
        self.handle_future_proof(&mut state, &tip, sender, proof)
    }

    /// Handles the received proof for a future slot.
    fn handle_future_proof(
        &self,
        state: &mut InternalState,
        tip: &PotProof,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotStateError> {
        // Reject if too much into future
        if (proof.slot_number - tip.slot_number) > self.config.max_future_slots {
            return Err(PotStateError::TooFuturistic {
                tip_slot: tip.slot_number,
                proof_slot: proof.slot_number,
            });
        }

        match state.future_proofs.entry(proof.slot_number) {
            Entry::Vacant(entry) => {
                let mut proofs = BTreeMap::new();
                proofs.insert(sender, proof.clone());
                entry.insert(proofs);
                Ok(())
            }
            Entry::Occupied(mut entry) => {
                let proofs_for_slot = entry.get_mut();
                // Reject if the sender already sent a proof for same slot number.
                if proofs_for_slot.contains_key(&sender) {
                    return Err(PotStateError::DuplicateProofFromPeer(sender));
                }

                // Reject if the there is an existing proof with same
                // seed/key but different checkpoints.
                if let Some(existing_proof) =
                    proofs_for_slot.values().find(|p| p.seed == proof.seed)
                {
                    if existing_proof.checkpoints.as_slice() != proof.checkpoints.as_slice() {
                        return Err(PotStateError::InvalidContextFromPeer(sender));
                    }
                }

                // TODO: put a max limit on future proofs per slot number.
                proofs_for_slot.insert(sender, proof.clone());
                Ok(())
            }
        }
    }

    /// Called when the chain is extended with a new proof.
    /// Tries to advance the tip as much as possible, by merging with
    /// the pending future proofs.
    fn merge_future_proofs(&self, state: &mut InternalState) {
        loop {
            let tip = if let Some(tip) = state.chain.last() {
                tip.clone()
            } else {
                return;
            };

            // Get the pending proofs for (tip.slot_number + 1).
            let next_slot = tip.slot_number + 1;
            let proofs_for_slot = match state.future_proofs.get_mut(&next_slot) {
                Some(proofs) => proofs,
                None => return,
            };

            // Look for a proof with the matching key/seed.
            let next_seed = tip.next_seed(None);
            let next_key = tip.next_key();
            let (sender, proof) = match proofs_for_slot
                .iter()
                .find(|(_, proof)| proof.seed == next_seed && proof.key == next_key)
            {
                Some((sender, proof)) => (*sender, proof.clone()),
                None => return,
            };

            // Verify the proof.
            if let Err(e) = self.proof_of_time.verify(&proof) {
                warn!(target: LOG_TARGET, "pot state::merge future proofs: failed to verify: {e:?}");
                proofs_for_slot.remove(&sender);
                if proofs_for_slot.is_empty() {
                    state.future_proofs.remove(&next_slot);
                }
                return;
            }

            // Extend the tip with the future proof.
            self.add_to_tip(state, &proof, ExtendAction::NoMerge);
        }
    }

    /// Adds the proof to the current tip
    fn add_to_tip(&self, state: &mut InternalState, proof: &PotProof, action: ExtendAction) {
        state.chain.push(proof.clone());
        state.future_proofs.remove(&proof.slot_number);
        if action == ExtendAction::MergeFutureProofs {
            self.merge_future_proofs(state)
        }
    }
}

/// PoT interface to the protocols (clock master, PoT client).
pub(crate) trait PotState: Send + Sync {
    /// Initializes the state with the given proofs.
    fn init(&self, proofs: NonEmptyVec<PotProof>);

    /// Returns the current tip
    fn tip(&self) -> Option<PotProof>;

    /// Called when the local clock master produces the next proof.
    fn on_proof(&self, proof: &PotProof) -> Result<(), PotStateError>;

    /// Called when a proof is gossiped by a peer clock master.
    fn on_proof_from_peer(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotStateError>;
}

impl PotState for StateManager {
    fn init(&self, proofs: NonEmptyVec<PotProof>) {
        let mut proofs = proofs.to_vec();
        let mut state = self.state.lock();
        state.chain.clear();
        state.chain.append(&mut proofs);
        state.future_proofs.clear();
    }
    fn tip(&self) -> Option<PotProof> {
        self.state.lock().chain.last().cloned()
    }

    fn on_proof(&self, proof: &PotProof) -> Result<(), PotStateError> {
        self.extend_chain(proof)
    }

    fn on_proof_from_peer(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotStateError> {
        self.verify_and_extend_chain(sender, proof)
    }
}

impl<Block: BlockT> PotConsensus<Block> for StateManager {
    fn get_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        parent_block_proofs: &[PotProof],
    ) -> Result<Vec<PotProof>, PotConsensusError> {
        let state = self.state.lock();
        let cur_tip = state.chain.iter().last().map_or_else(
            || "None".to_string(),
            |proof| format!("{}", proof.slot_number),
        );
        let proof_slot = slot_number - self.config.global_randomness_reveal_lag_slots;

        // For block 1, just return one proof at the target slot,
        // as the parent(genesis) does not have any proofs.
        if block_number.is_one() {
            let proof = state
                .chain
                .iter()
                .find(|proof| proof.slot_number == proof_slot)
                .ok_or(PotConsensusError::ProofUnavailable {
                    cur_tip,
                    start_slot: proof_slot,
                    end_slot: proof_slot,
                    block_number: format!("{block_number}"),
                    slot: slot_number,
                })?;
            return Ok(vec![proof.clone()]);
        }

        let start_slot = parent_block_proofs
            .iter()
            .last()
            .ok_or(PotConsensusError::ParentProofsEmpty {
                cur_tip: cur_tip.clone(),
                slot_number,
                block_number: format!("{block_number}"),
            })?
            .slot_number
            + 1;

        if start_slot > proof_slot {
            return Err(PotConsensusError::InvalidRange {
                cur_tip,
                start_slot,
                end_slot: proof_slot,
                block_number: format!("{block_number}"),
            });
        }

        // Collect the proofs in the requested range.
        let mut proofs = Vec::with_capacity((proof_slot - start_slot + 1) as usize);
        for slot in start_slot..=proof_slot {
            // TODO: avoid repeated search by copying the range.
            let proof = state
                .chain
                .iter()
                .find(|proof| proof.slot_number == slot)
                .ok_or(PotConsensusError::ProofUnavailable {
                    cur_tip: cur_tip.clone(),
                    start_slot,
                    end_slot: proof_slot,
                    block_number: format!("{block_number}"),
                    slot,
                })?;
            proofs.push(proof.clone());
        }

        Ok(proofs)
    }

    fn verify_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        block_proofs: &[PotProof],
        parent_block_proofs: &[PotProof],
    ) -> Result<(), PotConsensusError> {
        let state = self.state.lock();
        let cur_tip = state.chain.iter().last().map_or_else(
            || "None".to_string(),
            |proof| format!("{}", proof.slot_number),
        );

        if block_number.is_one() {
            // If block 1, check it has one proof.
            // TODO: we currently don't have a way to check the slot number at the
            // sender, to be resolved.
            if block_proofs.len() != 1 {
                return Err(PotConsensusError::UnexpectedProofCount {
                    cur_tip,
                    block_number: format!("{block_number}"),
                    slot: slot_number,
                    expected: 1,
                    actual: block_proofs.len(),
                });
            }

            let received = &block_proofs[0]; // Safe to index.
            let proof = state
                .chain
                .iter()
                .find(|proof| proof.slot_number == received.slot_number)
                .ok_or(PotConsensusError::ReceivedSlotMissing {
                    cur_tip: cur_tip.clone(),
                    block_number: format!("{block_number}"),
                    slot: received.slot_number,
                })?;
            // Safe to index.
            if *proof != *received {
                return Err(PotConsensusError::ReceivedProofMismatch {
                    cur_tip,
                    block_number: format!("{block_number}"),
                    slot: received.slot_number,
                });
            }

            return Ok(());
        }

        // Check that the parent last proof and the block first proof
        // form a chain.
        let last_parent_proof =
            parent_block_proofs
                .iter()
                .last()
                .ok_or(PotConsensusError::ParentProofsEmpty {
                    cur_tip: cur_tip.clone(),
                    slot_number,
                    block_number: format!("{block_number}"),
                })?;
        let first_block_proof =
            block_proofs
                .get(0)
                .ok_or(PotConsensusError::ReceivedProofsEmpty {
                    cur_tip: cur_tip.clone(),
                    slot_number,
                    block_number: format!("{block_number}"),
                })?;
        if first_block_proof.slot_number != (last_parent_proof.slot_number + 1) {
            return Err(PotConsensusError::ReceivedUnexpectedSlotNumber {
                cur_tip,
                block_number: format!("{block_number}"),
                expected: last_parent_proof.slot_number + 1,
                actual: first_block_proof.slot_number,
            });
        }

        // Compare the received proofs against the local chain. Since the
        // local chain is already validated, not doing the AES check on the
        // received proofs.
        let mut expected_slot = first_block_proof.slot_number;
        for received in block_proofs {
            if received.slot_number != expected_slot {
                return Err(PotConsensusError::ReceivedUnexpectedSlotNumber {
                    cur_tip,
                    block_number: format!("{block_number}"),
                    expected: expected_slot,
                    actual: received.slot_number,
                });
            }
            expected_slot += 1;

            // TODO: avoid repeated lookups, locate start of range
            let local_proof = state
                .chain
                .iter()
                .find(|local_proof| local_proof.slot_number == received.slot_number)
                .ok_or(PotConsensusError::ReceivedSlotMissing {
                    cur_tip: cur_tip.clone(),
                    block_number: format!("{block_number}"),
                    slot: received.slot_number,
                })?;

            if *local_proof != *received {
                return Err(PotConsensusError::ReceivedProofMismatch {
                    cur_tip,
                    block_number: format!("{block_number}"),
                    slot: received.slot_number,
                });
            }
        }

        Ok(())
    }
}

pub(crate) fn init_pot_state<Block: BlockT>(
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
    chain: Vec<PotProof>,
) -> (Arc<dyn PotState>, Arc<dyn PotConsensus<Block>>) {
    let state = Arc::new(StateManager::new(config, proof_of_time, chain));
    (state.clone(), state)
}
