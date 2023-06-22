//! AES related functionality.

use crate::pot::{AesCipherText, AesKey, AesSeed, ProofOfTime, ProofOfTimeError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rayon::prelude::*;
use sp_core::H256;

/// AES wrapper.
pub struct AESWrapper {
    /// Number of checkpoints per PoT.
    pub num_checkpoints: u32,

    /// Number of chained AES operations per checkpoint.
    pub checkpoint_iterations: u32,
}

impl AESWrapper {
    /// Creates the AES wrapper.
    pub fn new(num_checkpoints: u32, checkpoint_iterations: u32) -> Self {
        Self {
            num_checkpoints,
            checkpoint_iterations,
        }
    }

    /// Builds the proof.
    pub fn create_proof(
        &self,
        seed: AesSeed,
        key: AesKey,
        slot_number: u32,
        injected_block_hash: H256,
    ) -> ProofOfTime {
        let key = GenericArray::from(key.0);
        let cipher = Aes128::new(&key);
        let num_iter = self.num_checkpoints * self.checkpoint_iterations;

        let mut checkpoints = Vec::new();
        let mut block = GenericArray::from(seed.0);
        for i in 1..(num_iter + 1) {
            // Encrypt previous block in place to produce the next block.
            cipher.encrypt_block(&mut block);
            if i % self.checkpoint_iterations == 0 {
                // End of the checkpoint, collect the result.
                checkpoints.push(AesCipherText(block.into()));
            }
        }

        ProofOfTime {
            slot_number,
            seed,
            checkpoints,
            injected_block_hash,
        }
    }

    /// Verifies the proof.
    pub fn verify_proof(&self, key: AesKey, proof: &ProofOfTime) -> Result<bool, ProofOfTimeError> {
        if proof.checkpoints.len() as u32 != self.num_checkpoints {
            return Err(ProofOfTimeError::CheckpointMismatch {
                actual: proof.checkpoints.len() as u32,
                expected: self.num_checkpoints,
            });
        }

        let key = GenericArray::from(key.0);
        let cipher = Aes128::new(&key);

        // Create the cipher pairs to be evaluated
        let mut pairs = Vec::new();
        let mut prev = GenericArray::from(proof.seed.0);
        for checkpoint in &proof.checkpoints {
            let cur = GenericArray::from(checkpoint.0);
            pairs.push((prev, cur));
            prev = cur;
        }

        // Evaluate the pairs in parallel.
        let checkpoint_iterations = self.checkpoint_iterations;
        let results: Vec<bool> = pairs
            .par_iter_mut()
            .map(|(input, expected)| {
                // Encrypt in place checkpoint_iterations times
                // and compare with the expected output.
                for _ in 0..checkpoint_iterations {
                    cipher.encrypt_block(input);
                }
                *input == *expected
            })
            .collect();

        Ok(results.iter().all(|result| *result))
    }
}
