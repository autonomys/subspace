//! PoT state management.

use crate::PotConfig;
use async_trait::async_trait;
use core::num::NonZeroUsize;
use parking_lot::Mutex;
use sc_network::PeerId;
use sp_consensus_subspace::digests::PotPreDigest;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::{
    BlockHash, BlockNumber, NonEmptyVec, PotCheckpoint, PotKey, PotProof, PotSeed, SlotNumber,
    POT_ENTROPY_INJECTION_DELAY, POT_ENTROPY_INJECTION_INTERVAL,
    POT_ENTROPY_INJECTION_LOOK_BACK_DEPTH,
};
use subspace_proof_of_time::{PotVerificationError, ProofOfTime};
use tracing::{debug, trace};

/// The maximum size of the PoT chain to keep (about 5 min worth of proofs for now).
/// TODO: remove this when purging is implemented.
const POT_CHAIN_MAX_SIZE: NonZeroUsize = NonZeroUsize::new(300).expect("Not zero; qed");

/// The maximum number of entropy entries to keep (about 10 minutes worth now,
/// with POT_ENTROPY_INJECTION_INTERVAL = 20 blocks).
/// TODO: remove this when purging is implemented.
const ENTROPY_INJECTION_MAX_SIZE: NonZeroUsize = NonZeroUsize::new(30).expect("Not zero; qed");

/// The info to create the next proof after the current tip.
/// It has everything in PotProof except the checkpoints.
#[derive(Debug)]
pub(crate) struct PartialProof {
    /// Slot the proof was evaluated for.
    pub(crate) slot_number: SlotNumber,

    /// The seed used for evaluation.
    pub(crate) seed: PotSeed,

    /// The key used for evaluation.
    pub(crate) key: PotKey,

    /// Hash of last block at injection point.
    pub(crate) injected_block_hash: BlockHash,
}

impl PartialProof {
    /// Create the partial proof.
    pub fn new(
        slot_number: SlotNumber,
        seed: PotSeed,
        key: PotKey,
        injected_block_hash: BlockHash,
    ) -> Self {
        Self {
            slot_number,
            seed,
            key,
            injected_block_hash,
        }
    }

    /// Builds the complete proof with the checkpoints.
    pub(crate) fn proof(self, checkpoints: NonEmptyVec<PotCheckpoint>) -> PotProof {
        PotProof::new(
            self.slot_number,
            self.seed,
            self.key,
            checkpoints,
            self.injected_block_hash,
        )
    }
}

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

    #[error("Unexpected seed: {summary:?}/{block_number}/{slot}/{parent_slot}/{error_slot}")]
    UnexpectedSeed {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        error_slot: SlotNumber,
    },

    #[error("Unexpected key: {summary:?}/{block_number}/{slot}/{parent_slot}/{error_slot}")]
    UnexpectedKey {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        error_slot: SlotNumber,
    },

    #[error(
    "Verification failed: {summary:?}/{block_number}/{slot}/{parent_slot}/{error_slot:?}/{err:?}"
    )]
    VerificationFailed {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        error_slot: SlotNumber,
        err: PotVerificationError,
    },

    #[error(
        "Tip mismatch: {summary:?}/{block_number}/{slot}/{parent_slot}/{expected:?}/{actual:?}"
    )]
    TipMismatch {
        summary: PotStateSummary,
        block_number: BlockNumber,
        slot: SlotNumber,
        parent_slot: SlotNumber,
        expected: Option<SlotNumber>,
        actual: Option<SlotNumber>,
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

/// Entropy injection state.
struct EntropyInjection {
    /// Entropy injection waiting for the target block
    /// to be imported, so that the entropy can be applied.
    /// Contains the block hash and the slot number of the block.
    pending: BTreeMap<BlockNumber, (BlockHash, SlotNumber)>,

    /// Entropy to apply, indexed by slot number.
    ready: BTreeMap<SlotNumber, BlockHash>,

    /// Expected number of slots per block.
    slots_per_block: SlotNumber,

    /// Max entropy entries to keep.
    max_entries: usize,
}

impl EntropyInjection {
    /// Creates the entropy state.
    fn new(slots_per_block: SlotNumber, max_entries: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            ready: BTreeMap::new(),
            slots_per_block,
            max_entries,
        }
    }

    /// Handles a block import.
    fn handle_block_import(
        &mut self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        slot_number: SlotNumber,
    ) {
        self.add_entropy(block_number);
        self.update_pending(block_number, block_hash, slot_number);
    }

    /// Updates the entropy ready to be injected.
    fn add_entropy(&mut self, block_number: BlockNumber) {
        if (block_number % POT_ENTROPY_INJECTION_INTERVAL) != 0
            || block_number <= POT_ENTROPY_INJECTION_LOOK_BACK_DEPTH
        {
            return;
        }

        let source_block = block_number - POT_ENTROPY_INJECTION_LOOK_BACK_DEPTH;
        let (source_block_hash, source_block_slot) = match self.pending.get(&source_block) {
            Some((block_hash, slot_number)) => (*block_hash, *slot_number),
            None => {
                // This could be because of reorg: we already received an import
                // notification for the same block number, and the pending
                // entry was moved to ready state.
                debug!(%source_block, "Adding entropy: missing source block: ");
                return;
            }
        };

        // Schedule the source entropy at the injection slot.
        let injection_slot = source_block_slot
            + (POT_ENTROPY_INJECTION_LOOK_BACK_DEPTH as SlotNumber * self.slots_per_block)
            + POT_ENTROPY_INJECTION_DELAY;
        self.pending.remove(&source_block);
        let purged = if self.ready.len() >= self.max_entries {
            self.ready.pop_first()
        } else {
            None
        };
        self.ready.insert(injection_slot, source_block_hash);
        debug!(
            %block_number, %source_block, %source_block_slot, %injection_slot,
            ?source_block_hash, ?purged,
            "Adding entropy: "
        );
    }

    /// Updates the pending state.
    fn update_pending(
        &mut self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        slot_number: SlotNumber,
    ) {
        let dst_block = block_number + POT_ENTROPY_INJECTION_LOOK_BACK_DEPTH;
        if (dst_block % POT_ENTROPY_INJECTION_INTERVAL) != 0 {
            // This block is not a candidate for injection source.
            return;
        }

        if let Some(existing) = self.pending.insert(block_number, (block_hash, slot_number)) {
            // This could be because of reorg.
            debug!(%block_number, ?existing, "Adding pending entry: duplicate: ");
        }
        debug!(
            %block_number, %dst_block, %slot_number, ?block_hash,
            "Adding pending entry: "
        );
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

    /// Entropy injection state.
    entropy_injection: EntropyInjection,
}

impl InternalState {
    /// Creates the state.
    fn new(config: PotConfig) -> Self {
        Self {
            entropy_injection: EntropyInjection::new(
                config.slots_per_block,
                ENTROPY_INJECTION_MAX_SIZE.get(),
            ),
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

    /// Adds the batch of proofs to the current tip and merged possible future proofs.
    fn extend_and_merge_batch(&mut self, proofs: Vec<PotProof>) {
        for proof in proofs.into_iter() {
            self.future_proofs.remove(&proof.slot_number);
            self.chain.extend(proof);
        }
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

    /// Handles the block import notification.
    fn handle_block_import(
        &mut self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        slot_number: SlotNumber,
    ) {
        self.entropy_injection
            .handle_block_import(block_number, block_hash, slot_number)
    }

    /// Returns the inputs to build the next proof in the chain.
    fn next_proof_inputs(&self) -> Option<PartialProof> {
        self.tip().map(|tip| {
            PartialProof::new(
                tip.slot_number + 1,
                tip.next_seed(None),
                tip.next_key(),
                tip.injected_block_hash,
            )
        })
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

    /// For AES verification
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

    /// Verify the proofs and append to the chain.
    #[allow(clippy::too_many_arguments)]
    fn verify_and_append(
        &self,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        proofs: &NonEmptyVec<PotProof>,
        parent_slot_number: SlotNumber,
        tip: Option<PotProof>,
        summary: PotStateSummary,
    ) -> Result<(), PotVerifyBlockProofsError> {
        // Perform the validation, AES verification outside the lock.
        let mut prev_proof = tip.clone();
        let mut to_add = Vec::with_capacity(proofs.len());
        for proof in proofs.iter() {
            if let Some(prev_proof) = prev_proof.as_ref() {
                if proof.slot_number != (prev_proof.slot_number + 1) {
                    return Err(PotVerifyBlockProofsError::UnexpectedSlot {
                        summary: summary.clone(),
                        block_number,
                        slot: slot_number,
                        parent_slot: parent_slot_number,
                        expected_slot: prev_proof.slot_number + 1,
                        actual_slot: proof.slot_number,
                    });
                }

                if proof.seed != prev_proof.next_seed(None) {
                    return Err(PotVerifyBlockProofsError::UnexpectedSeed {
                        summary: summary.clone(),
                        block_number,
                        slot: slot_number,
                        parent_slot: parent_slot_number,
                        error_slot: proof.slot_number,
                    });
                }

                if proof.key != prev_proof.next_key() {
                    return Err(PotVerifyBlockProofsError::UnexpectedKey {
                        summary: summary.clone(),
                        block_number,
                        slot: slot_number,
                        parent_slot: parent_slot_number,
                        error_slot: proof.slot_number,
                    });
                }

                // Perform the AES check
                self.proof_of_time
                    .verify(&proof.seed, &proof.key, &proof.checkpoints)
                    .map_err(|err| PotVerifyBlockProofsError::VerificationFailed {
                        summary: summary.clone(),
                        block_number,
                        slot: slot_number,
                        parent_slot: parent_slot_number,
                        error_slot: proof.slot_number,
                        err,
                    })?;
            }
            to_add.push(proof.clone());
            prev_proof = Some(proof.clone());
        }

        // Checks passed, take the lock and try to append.
        let mut state = self.state.lock();
        let cur_tip = state.tip();
        if cur_tip != tip {
            // Fail if the tip moved meanwhile.
            // TODO: fall back to regular path if needed.
            return Err(PotVerifyBlockProofsError::TipMismatch {
                summary: summary.clone(),
                block_number,
                slot: slot_number,
                parent_slot: parent_slot_number,
                expected: tip.map(|p| p.slot_number),
                actual: cur_tip.map(|p| p.slot_number),
            });
        }
        state.extend_and_merge_batch(to_add);

        Ok(())
    }
}

/// Interface to the internal protocol components (time keeper, PoT client).
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

    /// Called when a proof is received via gossip from a peer. The AES
    /// verification is already done by the gossip validator.
    fn on_proof_from_peer(
        &self,
        sender: PeerId,
        proof: &PotProof,
    ) -> Result<(), PotProtocolStateError>;

    /// Called on block import notification to update the entropy injection
    /// state.
    fn on_block_import(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        slot_number: SlotNumber,
    );

    /// Called by gossip validator to filter out the received proofs
    /// early on. This performs only simple/inexpensive checks, the
    /// actual AES verification happens later when the proof is delivered
    /// by gossip. This acts like a Bloom filter: false positives with an
    /// error probability, no false negatives.
    fn is_candidate(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotProtocolStateError>;

    /// Returns the inputs to build the next proof in the chain.
    /// Returns None if the chain is empty.
    fn next_proof_inputs(&self) -> Option<PartialProof>;
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
        self.state.lock().handle_peer_proof(sender, proof)
    }

    fn on_block_import(
        &self,
        block_number: BlockNumber,
        block_hash: BlockHash,
        slot_number: SlotNumber,
    ) {
        self.state
            .lock()
            .handle_block_import(block_number, block_hash, slot_number)
    }

    fn is_candidate(&self, sender: PeerId, proof: &PotProof) -> Result<(), PotProtocolStateError> {
        self.state.lock().is_candidate(sender, proof)
    }

    fn next_proof_inputs(&self) -> Option<PartialProof> {
        self.state.lock().next_proof_inputs()
    }
}

/// Interface to consensus.
#[async_trait]
pub trait PotConsensusState: Send + Sync {
    /// Called by consensus when trying to claim the slot.
    /// Returns the proofs in the slot range
    /// [start_slot, current_slot - global_randomness_reveal_lag_slots].
    /// If the proofs are unavailable, retries upto wait_time(if specified).
    async fn get_block_proofs(
        &self,
        block_number: BlockNumber,
        current_slot: SlotNumber,
        parent_pre_digest: &PotPreDigest,
        wait_time: Option<Duration>,
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

#[async_trait]
impl PotConsensusState for StateManager {
    async fn get_block_proofs(
        &self,
        block_number: BlockNumber,
        current_slot: SlotNumber,
        parent_pre_digest: &PotPreDigest,
        wait_time: Option<Duration>,
    ) -> Result<NonEmptyVec<PotProof>, PotGetBlockProofsError> {
        let start_ts = Instant::now();
        let should_wait = move || {
            wait_time
                .as_ref()
                .map_or(false, |wait_time| start_ts.elapsed() < *wait_time)
        };
        let retry_delay = Duration::from_millis(200);
        let mut retries = 0;
        loop {
            let result =
                self.state
                    .lock()
                    .get_block_proofs(block_number, current_slot, parent_pre_digest);
            match result {
                Ok(_) => return result,
                Err(PotGetBlockProofsError::ProofUnavailable { .. }) => {
                    if (should_wait)() {
                        // TODO: notification instead of sleep/retry.
                        retries += 1;
                        trace!(
                            ?result,
                            %retries,
                            "Proof unavailable, retrying...",
                        );
                        tokio::time::sleep(retry_delay).await;
                    } else {
                        return result;
                    }
                }
                _ => return result,
            }
        }
    }

    fn verify_block_proofs(
        &self,
        block_number: BlockNumber,
        slot_number: SlotNumber,
        pre_digest: &PotPreDigest,
        parent_slot_number: SlotNumber,
        parent_pre_digest: &PotPreDigest,
    ) -> Result<(), PotVerifyBlockProofsError> {
        if let Some(block_proofs) = pre_digest.proofs() {
            // Opportunistically try to extend the chain with
            // the proofs from the block.
            // TODO: this also is done when the chain is empty and
            // we don't have a previous proof to verify against.
            // This needs to be revisited as part of the node sync.
            let (tip, summary) = {
                let state = self.state.lock();
                (state.tip(), state.summary())
            };
            let should_append = tip
                .as_ref()
                .map(|tip| (tip.slot_number + 1) == block_proofs.first().slot_number)
                .unwrap_or(true);
            if should_append {
                return self.verify_and_append(
                    block_number,
                    slot_number,
                    block_proofs,
                    parent_slot_number,
                    tip,
                    summary,
                );
            }
        }

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
