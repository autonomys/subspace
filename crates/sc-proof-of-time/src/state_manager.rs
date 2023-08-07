//! PoT state management.

use crate::PotConfig;
use core::num::NonZeroUsize;
use parking_lot::Mutex;
use sc_network::PeerId;
use sp_consensus_subspace::digests::PotPreDigest;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};

/// The maximum size of the PoT chain to keep (about 5 min worth of proofs for now).
/// TODO: remove this when purging is implemented.
const POT_CHAIN_MAX_SIZE: NonZeroUsize = NonZeroUsize::new(300).expect("Not zero; qed");

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

/// Error codes for PotConsensusState::get_block_proofs().
#[derive(Debug, thiserror::Error)]
pub enum PotGetBlockProofsError {
    #[error("Failed to get start slot: {summary:?}/{block_number}/{proof_slot}/{current_slot}")]
    StartSlotMissing {
        summary: PotStateSummary,
        block_number: BlockNumber,
        proof_slot: SlotNumber,
        current_slot: SlotNumber,
    },

    #[error(
        "Invalid slot range: {summary:?}/{block_number}/{start_slot}/{proof_slot}/{current_slot}"
    )]
    InvalidRange {
        summary: PotStateSummary,
        block_number: BlockNumber,
        start_slot: SlotNumber,
        proof_slot: SlotNumber,
        current_slot: SlotNumber,
    },

    #[error("Proof unavailable to send: {summary:?}/{block_number}/{missing_slot}/{current_slot}")]
    ProofUnavailable {
        summary: PotStateSummary,
        block_number: BlockNumber,
        missing_slot: SlotNumber,
        current_slot: SlotNumber,
    },
}

/// Error codes for PotConsensusState::verify_block_proofs().
#[derive(Debug, thiserror::Error)]
pub enum PotVerifyBlockProofsError {
    #[error("Block has no proofs: {summary:?}/{block_number}/{slot}/{parent_slot}")]
    NoProofs {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
    },

    #[error("Failed to get start slot: {summary:?}/{block_number}/{slot}/{parent_slot}")]
    StartSlotMissing {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
    },

    #[error("Unexpected slot number: {summary:?}/{block_number}/{slot}/{parent_slot}/{expected_slot}/{actual_slot}")]
    UnexpectedSlot {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        expected_slot: SlotNumber,
        actual_slot: SlotNumber,
    },

    #[error(
        "Local chain missing proof: {summary:?}/{block_number}/{slot}/{parent_slot}/{missing_slot}"
    )]
    LocalChainMissingProof {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        missing_slot: SlotNumber,
    },

    #[error("Mismatch with local proof: {summary:?}/{block_number}/{slot}/{parent_slot}/{mismatch_slot}")]
    ProofMismatch {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        mismatch_slot: SlotNumber,
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

/// Wrapper around the PoT chain.
struct PotChain {
    entries: VecDeque<PotProof>,
    max_entries: usize,
}

impl PotChain {
    /// Creates the chain.
    fn new(max_entries: NonZeroUsize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.get(),
        }
    }

    /// Resets the chain to the given entries.
    fn reset(&mut self, proofs: NonEmptyVec<PotProof>) {
        self.entries.clear();
        for proof in proofs.to_vec() {
            self.extend(proof);
        }
    }

    /// Helper to extend the chain.
    fn extend(&mut self, proof: PotProof) {
        if let Some(tip) = self.entries.back() {
            // This is a debug assert for now, as this should not happen.
            // Change to return error if needed.
            debug_assert!((tip.slot_number + 1) == proof.slot_number);
        }
        if self.entries.len() == self.max_entries {
            // Evict the oldest entry if full
            self.entries.pop_front();
        }
        self.entries.push_back(proof);
    }

    /// Returns the last entry in the chain.
    fn tip(&self) -> Option<PotProof> {
        self.entries.back().cloned()
    }

    /// Returns the length of the chain.
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns an iterator to the entries.
    fn iter(&self) -> Box<dyn Iterator<Item = &PotProof> + '_> {
        Box::new(self.entries.iter())
    }
}

/// The shared PoT state.
struct InternalState {
    /// Config.
    config: PotConfig,

    /// Last N entries of the PotChain, sorted by height.
    /// TODO: purging to be implemented.
    chain: PotChain,

    /// Proofs for future slot numbers, indexed by slot number.
    /// Each entry holds the proofs indexed by sender. The proofs
    /// are already verified before being added to the future list.
    /// TODO: limit the number of proofs per future slot.
    future_proofs: BTreeMap<SlotNumber, BTreeMap<PeerId, PotProof>>,
}

impl InternalState {
    /// Creates the state.
    fn new(config: PotConfig) -> Self {
        Self {
            config,
            chain: PotChain::new(POT_CHAIN_MAX_SIZE),
            future_proofs: BTreeMap::new(),
        }
    }

    /// Re-initializes the state with the given chain.
    fn reset(&mut self, proofs: NonEmptyVec<PotProof>) {
        self.chain.reset(proofs);
        self.future_proofs.clear();
    }

    /// Adds the proof to the current tip and merged possible future proofs.
    fn extend_and_merge(&mut self, proof: PotProof) {
        self.future_proofs.remove(&proof.slot_number);
        self.chain.extend(proof);
        self.merge_future_proofs();
    }

    /// Tries to extend the chain with the locally produced proof.
    fn handle_local_proof(&mut self, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        let tip = match self.chain.tip() {
            Some(tip) => tip,
            None => {
                self.extend_and_merge(proof.clone());
                return Ok(());
            }
        };

        if (tip.slot_number + 1) == proof.slot_number {
            self.extend_and_merge(proof.clone());
            Ok(())
        } else {
            // The tip moved by the time the proof was computed.
            Err(PotProtocolStateError::TipMismatch {
                expected: tip.slot_number + 1,
                actual: proof.slot_number,
            })
        }
    }

    /// Tries to extend the chain with the proof received from a peer.
    /// The proof is assumed to have passed the AES verification.
    fn handle_peer_proof(
        &mut self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotProtocolStateError> {
        let tip = match self.chain.tip() {
            Some(tip) => tip.clone(),
            None => {
                self.extend_and_merge(proof.clone());
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
            self.extend_and_merge(proof.clone());
            return Ok(());
        }

        // Case 3: proof for a future slot
        self.handle_future_proof(&tip, sender, proof)
    }

    /// Checks if the proof is a possible candidate.
    fn is_candidate(&self, _sender: PeerId, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        let tip = match self.chain.tip() {
            Some(tip) => tip.clone(),
            None => {
                // Chain is empty, possible first proof.
                return Ok(());
            }
        };

        // Case 1: the proof is for an older slot.
        // When same proof is gossiped by multiple peers, this check
        // could help early discard of the duplicates.
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
        }

        // Case 3: future proof
        // TODO: add more filtering for future proofs
        Ok(())
    }

    /// Handles the received proof for a future slot.
    fn handle_future_proof(
        &mut self,
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

        match self.future_proofs.entry(proof.slot_number) {
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
    fn merge_future_proofs(&mut self) {
        let mut cur_tip = self.chain.tip();
        while let Some(tip) = cur_tip.as_ref() {
            // At this point, we know the expected seed/key for the next proof
            // in the sequence. If there is at least an entry with the expected
            // key/seed(there could be several from different peers), extend the
            // chain.
            let next_slot = tip.slot_number + 1;
            let proofs_for_slot = match self.future_proofs.remove(&next_slot) {
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
                    self.chain.extend(next_proof.clone());
                    cur_tip = Some(next_proof);
                }
                None => {
                    // TODO: penalize peers that sent invalid key/seed
                    return;
                }
            }
        }
    }

    /// Returns the proofs for the block.
    fn get_block_proofs(
        &self,
        block_number: BlockNumber,
        current_slot: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<NonEmptyVec<PotProof>, PotGetBlockProofsError> {
        let summary = self.summary();
        let proof_slot = current_slot - self.config.global_randomness_reveal_lag_slots;
        let start_slot = parent_pre_digest.next_block_initial_slot().ok_or_else(|| {
            PotGetBlockProofsError::StartSlotMissing {
                summary: summary.clone(),
                block_number,
                proof_slot,
                current_slot,
            }
        })?;

        if start_slot > proof_slot {
            return Err(PotGetBlockProofsError::InvalidRange {
                summary: summary.clone(),
                block_number,
                start_slot,
                proof_slot,
                current_slot,
            });
        }

        // Collect the proofs in the requested range.
        let mut proofs = Vec::with_capacity((proof_slot - start_slot + 1) as usize);
        let mut iter = self.chain.iter().skip_while(|p| p.slot_number < start_slot);
        for slot in start_slot..=proof_slot {
            if let Some(proof) = iter.next() {
                debug_assert!(proof.slot_number == slot);
                proofs.push(proof.clone());
            } else {
                return Err(PotGetBlockProofsError::ProofUnavailable {
                    summary: summary.clone(),
                    block_number,
                    missing_slot: slot,
                    current_slot,
                });
            }
        }

        Ok(NonEmptyVec::new(proofs).expect("NonEmptyVec cannot fail with non-empty inputs"))
    }

    /// Verifies the block proofs.
    fn verify_block_proofs(
        &self,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        pre_digest: &PotPreDigest,
        parent_slot_number: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<(), PotVerifyBlockProofsError> {
        let summary = self.summary();
        let block_proofs = pre_digest
            .proofs()
            .ok_or(PotVerifyBlockProofsError::NoProofs {
                summary: summary.clone(),
                block_number,
                slot: slot_number,
                parent_slot: parent_slot_number,
            })?;

        // Get the expected slot of the first proof in this block.
        let start_slot = parent_pre_digest.next_block_initial_slot().ok_or_else(|| {
            PotVerifyBlockProofsError::StartSlotMissing {
                summary: summary.clone(),
                block_number,
                slot: slot_number,
                parent_slot: parent_slot_number,
            }
        })?;

        // Since we check the first proof starts with the parent.last_proof.slot + 1,
        // and we already verified the seed/key of the proofs in the chain were was
        // correctly derived from the previous proof, this implies correct chain continuity
        // from parent.
        let mut local_proofs_iter = self.chain.iter().skip_while(|p| p.slot_number < start_slot);
        for received in block_proofs.iter() {
            if let Some(local_proof) = local_proofs_iter.next() {
                // The received proof should match the proof in the local chain. No need to
                // perform AES verification, as local proof is already verified.
                if *local_proof != *received {
                    return Err(PotVerifyBlockProofsError::ProofMismatch {
                        summary: summary.clone(),
                        block_number,
                        slot: slot_number,
                        parent_slot: parent_slot_number,
                        mismatch_slot: received.slot_number,
                    });
                }
            } else {
                // TODO: extend local chain with proofs in the block.
                return Err(PotVerifyBlockProofsError::LocalChainMissingProof {
                    summary: summary.clone(),
                    block_number,
                    slot: slot_number,
                    parent_slot: parent_slot_number,
                    missing_slot: received.slot_number,
                });
            }
        }

        Ok(())
    }

    /// Returns the current tip of the chain.
    fn tip(&self) -> Option<PotProof> {
        self.chain.tip()
    }

    /// Returns the summary of the current state.
    fn summary(&self) -> PotStateSummary {
        PotStateSummary {
            tip: self.chain.tip().map(|proof| proof.slot_number),
            chain_length: self.chain.len(),
        }
    }
}

/// Wrapper to manage the state.
struct StateManager {
    /// The PoT state
    state: Mutex<InternalState>,

    /// PoT wrapper for verification.
    proof_of_time: ProofOfTime,
}

impl StateManager {
    /// Creates the state.
    pub fn new(config: PotConfig, proof_of_time: ProofOfTime) -> Self {
        Self {
            state: Mutex::new(InternalState::new(config)),
            proof_of_time,
        }
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

    /// Called by gossip validator to filter out the received proofs
    /// early on. This performs only simple/inexpensive checks, the
    /// actual AES verification happens later when the proof is delivered
    /// by gossip. This acts like a Bloom filter: false positives with an
    /// error probability, no false negatives.
    fn is_candidate(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotProtocolStateError>;
}

impl PotProtocolState for StateManager {
    fn reset(&self, proofs: NonEmptyVec<PotProof>) {
        self.state.lock().reset(proofs);
    }

    fn tip(&self) -> Option<PotProof> {
        self.state.lock().tip()
    }

    fn on_proof(&self, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        self.state.lock().handle_local_proof(proof)
    }

    fn on_proof_from_peer(
        &self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotProtocolStateError> {
        // Verify the proof outside the lock.
        // TODO: penalize peers that send too many bad proofs.
        self.proof_of_time
            .verify(proof)
            .map_err(PotProtocolStateError::InvalidProof)?;

        self.state.lock().handle_peer_proof(sender, proof)
    }

    fn is_candidate(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        self.state.lock().is_candidate(sender, proof)
    }
}

/// Interface to consensus.
pub trait PotConsensusState: Send + Sync {
    /// Called by consensus when trying to claim the slot.
    /// Returns the proofs in the slot range
    /// [start_slot, current_slot - global_randomness_reveal_lag_slots].
    fn get_block_proofs(
        &self,
        block_number: BlockNumber,
        current_slot: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<NonEmptyVec<PotProof>, PotGetBlockProofsError>;

    /// Called during block import validation.
    /// Verifies the sequence of proofs in the block being validated.
    fn verify_block_proofs(
        &self,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        pre_digest: &PotPreDigest,
        parent_slot_number: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<(), PotVerifyBlockProofsError>;
}

impl PotConsensusState for StateManager {
    fn get_block_proofs(
        &self,
        block_number: BlockNumber,
        current_slot: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<NonEmptyVec<PotProof>, PotGetBlockProofsError> {
        self.state
            .lock()
            .get_block_proofs(block_number, current_slot, parent_pre_digest)
    }

    fn verify_block_proofs(
        &self,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        pre_digest: &PotPreDigest,
        parent_slot_number: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<(), PotVerifyBlockProofsError> {
        self.state.lock().verify_block_proofs(
            block_number,
            slot_number,
            pre_digest,
            parent_slot_number,
            parent_pre_digest,
        )
    }
}

pub(crate) fn init_pot_state(
    config: PotConfig,
    proof_of_time: ProofOfTime,
) -> (Arc<dyn PotProtocolState>, Arc<dyn PotConsensusState>) {
    let state = Arc::new(StateManager::new(config, proof_of_time));
    (state.clone(), state)
}
