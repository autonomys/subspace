//! Proof of time implementation.

#![cfg_attr(not(feature = "std"), no_std)]
mod pot_aes;

use core::num::NonZeroU32;
use subspace_core_primitives::{BlockHash, PotCheckpoints, PotKey, PotProof, PotSeed, SlotNumber};

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum PotInitError {
    #[cfg_attr(
        feature = "thiserror",
        error("Not multiple of number of checkpoints: {pot_iterations}")
    )]
    NotMultipleOfCheckpoints { pot_iterations: u32 },
}

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum PotVerificationError {
    #[cfg_attr(feature = "thiserror", error("Checkpoint verification failed"))]
    VerificationFailed,
}

/// Wrapper for the low level AES primitives
#[derive(Debug, Clone, Copy)]
pub struct ProofOfTime {
    /// Number of chained AES operations per checkpoint.
    checkpoint_iterations: u32,
}

impl ProofOfTime {
    /// Creates the AES wrapper.
    pub fn new(pot_iterations: NonZeroU32) -> Result<Self, PotInitError> {
        let pot_iterations = pot_iterations.get();
        if pot_iterations % u32::from(PotCheckpoints::NUM_CHECKPOINTS) != 0 {
            return Err(PotInitError::NotMultipleOfCheckpoints { pot_iterations });
        }

        Ok(Self {
            checkpoint_iterations: pot_iterations / u32::from(PotCheckpoints::NUM_CHECKPOINTS),
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
        let checkpoints = pot_aes::create(&seed, &key, self.checkpoint_iterations);
        PotProof::new(slot_number, seed, key, checkpoints, injected_block_hash)
    }

    /// Verifies the proof.
    pub fn verify(&self, proof: &PotProof) -> Result<(), PotVerificationError> {
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
