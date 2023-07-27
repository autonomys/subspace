//! Proof of time implementation.

#![cfg_attr(not(feature = "std"), no_std)]
mod pot_aes;

use subspace_core_primitives::{BlockHash, PotKey, PotProof, PotSeed, SlotNumber};

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum PotVerificationError {
    #[cfg_attr(
        feature = "thiserror",
        error("Unexpected number of checkpoints: {expected}, {actual}")
    )]
    CheckpointCountMismatch { expected: u8, actual: u64 },

    #[cfg_attr(feature = "thiserror", error("Checkpoint verification failed"))]
    VerificationFailed,
}

/// Wrapper for the low level AES primitives
pub struct ProofOfTime {
    /// Number of checkpoints per PoT.
    num_checkpoints: u8,

    /// Number of chained AES operations per checkpoint.
    checkpoint_iterations: u32,
}

impl ProofOfTime {
    /// Creates the AES wrapper.
    pub fn new(num_checkpoints: u8, checkpoint_iterations: u32) -> Self {
        Self {
            num_checkpoints,
            checkpoint_iterations,
        }
    }

    /// Builds the proof.
    pub fn create(
        &self,
        seed: PotSeed,
        key: PotKey,
        slot_number: SlotNumber,
        injected_block_hash: BlockHash,
    ) -> PotProof {
        PotProof::new(
            slot_number,
            seed,
            key,
            pot_aes::create(
                &seed,
                &key,
                self.num_checkpoints,
                self.checkpoint_iterations,
            ),
            injected_block_hash,
        )
    }

    /// Verifies the proof.
    pub fn verify(&self, proof: &PotProof) -> Result<(), PotVerificationError> {
        // TODO: this check may break upgrades, revisit.
        if proof.checkpoints.len() != self.num_checkpoints as usize {
            return Err(PotVerificationError::CheckpointCountMismatch {
                expected: self.num_checkpoints,
                actual: proof.checkpoints.len() as u64,
            });
        }

        if pot_aes::verify_sequential(
            &proof.seed,
            &proof.key,
            &proof.checkpoints,
            self.checkpoint_iterations,
        ) {
            Ok(())
        } else {
            Err(PotVerificationError::VerificationFailed)
        }
    }
}
