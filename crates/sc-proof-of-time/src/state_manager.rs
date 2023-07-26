//! PoT state management.

use crate::PotConfig;
use parking_lot::Mutex;
use sc_network::PeerId;
use sp_runtime::traits::{Block as BlockT, NumberFor, One};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_core_primitives::{NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};

/// Error codes for PotProtocolState APIs.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PotProtocolStateError {
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
}

/// Error codes for PotConsensusState APIs.
#[derive(Debug, thiserror::Error)]
pub enum PotConsensusStateError {
    #[error("Parent block proofs empty: {summary:?}/{slot_number}/{block_number}")]
    ParentProofsEmpty {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error("Invalid slot range: {summary:?}/{slot_number}/{block_number}/{start_slot}")]
    InvalidRange {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
        start_slot: SlotNumber,
    },

    #[error("Proof unavailable to send: {summary:?}/{slot_number}/{block_number}")]
    ProofUnavailable {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error(
        "Unexpected proof count: {summary:?}/{slot_number}/{block_number}/{expected}/{actual}"
    )]
    UnexpectedProofCount {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
        expected: usize,
        actual: usize,
    },

    #[error("Received proof locally missing: {summary:?}/{slot_number}/{block_number}")]
    ReceivedSlotMissing {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error("Received proof did not match local proof: {summary:?}/{slot_number}/{block_number}")]
    ReceivedProofMismatch {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error("Received block with no proofs: {summary:?}/{slot_number}/{block_number}")]
    ReceivedProofsEmpty {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error(
    "Received proofs with unexpected slot number: {summary:?}/{slot_number}/{block_number}/{expected}/{actual}"
    )]
    ReceivedUnexpectedSlotNumber {
        summary: PotStateSummary,
        slot_number: SlotNumber,
        block_number: String,
        expected: SlotNumber,
        actual: SlotNumber,
    },
}

/// Summary of the current state.
#[derive(Debug, Clone)]
pub struct PotStateSummary {
    /// Current tip.
    pub tip: Option<SlotNumber>,

    /// Length of chain.
    pub chain_length: usize,
}

/// The shared PoT state.
struct InternalState {
    /// Last N entries of the PotChain, sorted by height.
    /// TODO: purging to be implemented.
    chain: Vec<PotProof>,

    /// Proofs for future slot numbers, indexed by slot number.
    /// Each entry holds the proofs indexed by sender. The proofs
    /// are already verified before being added to the future list.
    /// TODO: limit the number of proofs per future slot.
    future_proofs: BTreeMap<SlotNumber, BTreeMap<PeerId, PotProof>>,
}

impl InternalState {
    fn summary(&self) -> PotStateSummary {
        PotStateSummary {
            tip: self.chain.iter().last().map(|proof| proof.slot_number),
            chain_length: self.chain.len(),
        }
    }
}

/// Wrapper to manage the state.
struct StateManager {
    /// Pot config
    config: PotConfig,

    /// PoT wrapper for verification.
    proof_of_time: ProofOfTime,

    /// The PoT state
    state: Mutex<InternalState>,
}

impl StateManager {
    /// Creates the state.
    pub fn new(config: PotConfig, proof_of_time: ProofOfTime, chain: Vec<PotProof>) -> Self {
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
    pub fn extend_chain(&self, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        let mut state = self.state.lock();
        let tip = match state.chain.last() {
            Some(tip) => tip,
            None => {
                self.add_to_tip(&mut state, proof);
                return Ok(());
            }
        };

        if (tip.slot_number + 1) == proof.slot_number {
            self.add_to_tip(&mut state, proof);
            Ok(())
        } else {
            // The tip moved by the time the proof was computed.
            Err(PotProtocolStateError::TipMismatch {
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
    ) -> Result<(), PotProtocolStateError> {
        // Verify the proof outside the lock.
        // TODO: penalize peers that send too many bad proofs.
        self.proof_of_time
            .verify(proof)
            .map_err(PotProtocolStateError::InvalidProof)?;

        let mut state = self.state.lock();
        let tip = match state.chain.last() {
            Some(tip) => tip.clone(),
            None => {
                self.add_to_tip(&mut state, proof);
                return Ok(());
            }
        };

        // Case 1: the proof is for an older slot
        if proof.slot_number <= tip.slot_number {
            return Err(PotProtocolStateError::StaleProof {
                tip_slot: tip.slot_number,
                proof_slot: proof.slot_number,
            });
        }

        // Case 2: the proof extends the tip
        if (tip.slot_number + 1) == proof.slot_number {
            let expected_seed = tip.next_seed(None);
            if proof.seed != expected_seed {
                return Err(PotProtocolStateError::InvalidSeed {
                    expected: expected_seed,
                    actual: proof.seed,
                });
            }

            let expected_key = tip.next_key();
            if proof.key != expected_key {
                return Err(PotProtocolStateError::InvalidKey {
                    expected: expected_key,
                    actual: proof.key,
                });
            }

            // All checks passed, advance the tip with the new proof
            self.add_to_tip(&mut state, proof);
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
    ) -> Result<(), PotProtocolStateError> {
        // Reject if too much into future
        if (proof.slot_number - tip.slot_number) > self.config.max_future_slots {
            return Err(PotProtocolStateError::TooFuturistic {
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
                    return Err(PotProtocolStateError::DuplicateProofFromPeer(sender));
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
        let mut cur_tip = state.chain.last().cloned();
        while let Some(tip) = cur_tip.as_ref() {
            // At this point, we know the expected seed/key for the next proof
            // in the sequence. If there is at least an entry with the expected
            // key/seed(there could be several from different peers), extend the
            // chain.
            let next_slot = tip.slot_number + 1;
            let proofs_for_slot = match state.future_proofs.remove(&next_slot) {
                Some(proofs) => proofs,
                None => return,
            };

            let next_seed = tip.next_seed(None);
            let next_key = tip.next_key();
            match proofs_for_slot
                .values()
                .find(|proof| proof.seed == next_seed && proof.key == next_key)
                .cloned()
            {
                Some(next_proof) => {
                    // Extend the tip with the next proof, continue merging.
                    state.chain.push(next_proof.clone());
                    cur_tip = Some(next_proof);
                }
                None => {
                    // TODO: penalize peers that sent invalid key/seed
                    return;
                }
            }
        }
    }

    /// Adds the proof to the current tip
    fn add_to_tip(&self, state: &mut InternalState, proof: &PotProof) {
        state.chain.push(proof.clone());
        state.future_proofs.remove(&proof.slot_number);
        self.merge_future_proofs(state);
    }
}

/// Interface to the internal protocol components (clock master, PoT client).
pub(crate) trait PotProtocolState: Send + Sync {
    /// Re(initializes) the chain with the given set of proofs.
    /// TODO: the proofs are assumed to have been validated, validate
    /// if needed.
    fn reset(&self, proofs: NonEmptyVec<PotProof>);

    /// Returns the current tip.
    fn tip(&self) -> Option<PotProof>;

    /// Called when a proof is produced locally. It tries to extend the
    /// chain without verifying the proof.
    fn on_proof(&self, proof: &PotProof) -> Result<(), PotProtocolStateError>;

    /// Called when a proof is received via gossip from a peer. The proof
    /// is first verified before trying to extend the chain.
    fn on_proof_from_peer(
        &self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotProtocolStateError>;
}

impl PotProtocolState for StateManager {
    fn reset(&self, proofs: NonEmptyVec<PotProof>) {
        let mut proofs = proofs.to_vec();
        let mut state = self.state.lock();
        state.chain.clear();
        state.chain.append(&mut proofs);
        state.future_proofs.clear();
    }
    fn tip(&self) -> Option<PotProof> {
        self.state.lock().chain.last().cloned()
    }

    fn on_proof(&self, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        self.extend_chain(proof)
    }

    fn on_proof_from_peer(
        &self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotProtocolStateError> {
        self.verify_and_extend_chain(sender, proof)
    }
}

/// Interface to consensus.
pub trait PotConsensusState<Block: BlockT>: Send + Sync {
    /// Called by consensus when trying to claim the slot.
    /// Returns the proofs in the slot range
    /// [parent.last_proof.slot + 1, slot_number - global_randomness_reveal_lag_slots].
    fn get_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        parent_block_proofs: &[PotProof],
    ) -> Result<Vec<PotProof>, PotConsensusStateError>;

    /// Called during block import validation.
    /// Verifies the sequence of proofs in the block being validated.
    fn verify_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        block_proofs: &[PotProof],
        parent_block_proofs: &[PotProof],
    ) -> Result<(), PotConsensusStateError>;
}

impl<Block: BlockT> PotConsensusState<Block> for StateManager {
    fn get_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        parent_block_proofs: &[PotProof],
    ) -> Result<Vec<PotProof>, PotConsensusStateError> {
        let state = self.state.lock();
        let summary = state.summary();
        let proof_slot = slot_number - self.config.global_randomness_reveal_lag_slots;

        // For block 1, just return one proof at the target slot,
        // as the parent(genesis) does not have any proofs.
        if block_number.is_one() {
            let proof = state
                .chain
                .iter()
                .find(|proof| proof.slot_number == proof_slot)
                .ok_or(PotConsensusStateError::ProofUnavailable {
                    summary,
                    slot_number,
                    block_number: format!("{block_number}"),
                })?;
            return Ok(vec![proof.clone()]);
        }

        let start_slot = parent_block_proofs
            .iter()
            .last()
            .ok_or(PotConsensusStateError::ParentProofsEmpty {
                summary: summary.clone(),
                slot_number,
                block_number: format!("{block_number}"),
            })?
            .slot_number
            + 1;

        if start_slot > proof_slot {
            return Err(PotConsensusStateError::InvalidRange {
                summary: summary.clone(),
                slot_number,
                block_number: format!("{block_number}"),
                start_slot,
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
                .ok_or(PotConsensusStateError::ProofUnavailable {
                    summary: summary.clone(),
                    slot_number: slot,
                    block_number: format!("{block_number}"),
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
    ) -> Result<(), PotConsensusStateError> {
        let state = self.state.lock();
        let summary = state.summary();

        if block_number.is_one() {
            // If block 1, check it has one proof.
            // TODO: we currently don't have a way to check the slot number at the
            // sender, to be resolved.
            if block_proofs.len() != 1 {
                return Err(PotConsensusStateError::UnexpectedProofCount {
                    summary,
                    slot_number,
                    block_number: format!("{block_number}"),
                    expected: 1,
                    actual: block_proofs.len(),
                });
            }

            let received = &block_proofs[0]; // Safe to index.
            let proof = state
                .chain
                .iter()
                .find(|proof| proof.slot_number == received.slot_number)
                .ok_or(PotConsensusStateError::ReceivedSlotMissing {
                    summary: summary.clone(),
                    slot_number: received.slot_number,
                    block_number: format!("{block_number}"),
                })?;
            // Safe to index.
            if *proof != *received {
                return Err(PotConsensusStateError::ReceivedProofMismatch {
                    summary: summary.clone(),
                    slot_number: received.slot_number,
                    block_number: format!("{block_number}"),
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
                .ok_or(PotConsensusStateError::ParentProofsEmpty {
                    summary: summary.clone(),
                    slot_number,
                    block_number: format!("{block_number}"),
                })?;
        let first_block_proof =
            block_proofs
                .get(0)
                .ok_or(PotConsensusStateError::ReceivedProofsEmpty {
                    summary: summary.clone(),
                    slot_number,
                    block_number: format!("{block_number}"),
                })?;
        if first_block_proof.slot_number != (last_parent_proof.slot_number + 1) {
            return Err(PotConsensusStateError::ReceivedUnexpectedSlotNumber {
                summary: summary.clone(),
                slot_number,
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
                return Err(PotConsensusStateError::ReceivedUnexpectedSlotNumber {
                    summary: summary.clone(),
                    slot_number,
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
                .ok_or(PotConsensusStateError::ReceivedSlotMissing {
                    summary: summary.clone(),
                    slot_number: received.slot_number,
                    block_number: format!("{block_number}"),
                })?;

            if *local_proof != *received {
                return Err(PotConsensusStateError::ReceivedProofMismatch {
                    summary: summary.clone(),
                    slot_number: received.slot_number,
                    block_number: format!("{block_number}"),
                });
            }
        }

        Ok(())
    }
}

pub(crate) fn init_pot_state<Block: BlockT>(
    config: PotConfig,
    proof_of_time: ProofOfTime,
    chain: Vec<PotProof>,
) -> (Arc<dyn PotProtocolState>, Arc<dyn PotConsensusState<Block>>) {
    let state = Arc::new(StateManager::new(config, proof_of_time, chain));
    (state.clone(), state)
}
