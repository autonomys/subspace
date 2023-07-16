//! PoT state management.

use crate::utils::LOG_TARGET;
use crate::PotConfig;
use parking_lot::Mutex;
use sc_network::PeerId;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_core_primitives::{PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum PotStateError {
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
struct PotStateInternal {
    /// Last N entries of the PotChain, sorted by slot number.
    chain: Vec<PotProof>,

    /// Proofs for future slot numbers, indexed by slot number.
    /// Each entry holds the proofs indexed by sender.
    future_proofs: BTreeMap<SlotNumber, BTreeMap<PeerId, PotProof>>,
}

/// Wrapper around the PoT state.
pub struct PotState {
    /// Pot config
    config: PotConfig,

    /// PoT wrapper for verification.
    proof_of_time: Arc<ProofOfTime>,

    /// The PoT state
    state: Mutex<PotStateInternal>,
}

impl PotState {
    /// Creates the state.
    pub fn new(config: PotConfig, proof_of_time: Arc<ProofOfTime>) -> Self {
        Self {
            config,
            proof_of_time,
            state: Mutex::new(PotStateInternal {
                chain: Vec::new(),
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
        state: &mut PotStateInternal,
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
    fn merge_future_proofs(&self, state: &mut PotStateInternal) {
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
    fn add_to_tip(&self, state: &mut PotStateInternal, proof: &PotProof, action: ExtendAction) {
        state.chain.push(proof.clone());
        state.future_proofs.remove(&proof.slot_number);
        if action == ExtendAction::MergeFutureProofs {
            self.merge_future_proofs(state)
        }
    }
}

/// The state interface to the clock masters.
pub trait ClockMasterState: Send + Sync {
    /// Returns the current tip
    fn tip(&self) -> Option<PotProof>;

    /// Called when the local clock master produces the next proof.
    fn on_proof(&self, proof: &PotProof) -> Result<(), PotStateError>;

    /// Called when a proof is gossiped by a peer clock master.
    fn on_proof_from_peer(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotStateError>;
}

impl ClockMasterState for PotState {
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

pub fn clock_master_state(
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
) -> Arc<dyn ClockMasterState> {
    Arc::new(PotState::new(config, proof_of_time))
}

/// The state interface to the PoT node clients.
pub trait PotClientState: Send + Sync {
    /// Returns the current tip
    fn tip(&self) -> Option<PotProof>;

    /// Called when a proof is gossiped by a peer clock master.
    fn on_proof_from_peer(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotStateError>;
}

impl PotClientState for PotState {
    fn tip(&self) -> Option<PotProof> {
        self.state.lock().chain.last().cloned()
    }

    fn on_proof_from_peer(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotStateError> {
        self.verify_and_extend_chain(sender, proof)
    }
}

pub fn pot_client_state(
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
) -> Arc<dyn PotClientState> {
    Arc::new(PotState::new(config, proof_of_time))
}
