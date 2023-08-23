//! Proof of time implementation.

#![cfg_attr(not(feature = "std"), no_std)]
mod pot_aes;

use core::num::{NonZeroU32, NonZeroU8};
use subspace_core_primitives::{BlockHash, NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum PotInitError {
    #[cfg_attr(
        feature = "thiserror",
        error(
            "pot_iterations not multiple of num_checkpoints: {pot_iterations}, {num_checkpoints}"
        )
    )]
    NotMultiple {
        pot_iterations: u32,
        num_checkpoints: u8,
    },
}

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
#[derive(Debug, Clone, Copy)]
pub struct ProofOfTime {
    /// Number of checkpoints per PoT.
    num_checkpoints: u8,

    /// Number of chained AES operations per checkpoint.
    checkpoint_iterations: u32,
}

impl ProofOfTime {
    /// Creates the AES wrapper.
    pub fn new(
        pot_iterations: NonZeroU32,
        num_checkpoints: NonZeroU8,
    ) -> Result<Self, PotInitError> {
        let pot_iterations = pot_iterations.get();
        let num_checkpoints = num_checkpoints.get();
        if pot_iterations % (num_checkpoints as u32) != 0 {
            return Err(PotInitError::NotMultiple {
                pot_iterations,
                num_checkpoints,
            });
        }

        Ok(Self {
            num_checkpoints,
            checkpoint_iterations: pot_iterations / (num_checkpoints as u32),
        })
    }

    /// Builds the proof.
    pub fn create(
        &self,
        seed: PotSeed,
        key: PotKey,
        slot_number: SlotNumber,
        injected_block_hash: BlockHash,
    ) -> PotProof {
        let checkpoints = NonEmptyVec::new(pot_aes::create(
            &seed,
            &key,
            self.num_checkpoints,
            self.checkpoint_iterations,
        ))
        .expect("List of checkpoints is never empty; qed");
        PotProof::new(slot_number, seed, key, checkpoints, injected_block_hash)
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
            proof.checkpoints.as_slice(),
            self.checkpoint_iterations,
        ) {
            Ok(())
        } else {
            Err(PotVerificationError::VerificationFailed)
        }
    }
}
