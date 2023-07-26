//! PoT state management.

use crate::PotConfig;
use parking_lot::Mutex;
use sc_network::PeerId;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_core_primitives::{NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};

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

/// Wrapper to manage the state.
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
