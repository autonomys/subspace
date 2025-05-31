//! Proof of time implementation.

#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
#![feature(portable_simd)]
#![no_std]

mod aes;

use core::num::NonZeroU32;
use subspace_core_primitives::pot::{PotCheckpoints, PotSeed};

/// Proof of time error
#[derive(Debug, thiserror::Error)]
pub enum PotError {
    /// Iterations are not multiple of number of checkpoints times two
    #[error(
        "Iterations {iterations} are not multiple of number of checkpoints {num_checkpoints} \
        times two"
    )]
    NotMultipleOfCheckpoints {
        /// Slot iterations provided
        iterations: NonZeroU32,
        /// Number of checkpoints
        num_checkpoints: u32,
    },
}

/// Run PoT proving and produce checkpoints.
///
/// Returns error if `iterations` is not a multiple of checkpoints times two.
pub fn prove(seed: PotSeed, iterations: NonZeroU32) -> Result<PotCheckpoints, PotError> {
    if iterations.get() % u32::from(PotCheckpoints::NUM_CHECKPOINTS.get() * 2) != 0 {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations,
            num_checkpoints: u32::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
        });
    }

    Ok(aes::create(
        seed,
        seed.key(),
        iterations.get() / u32::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
    ))
}

/// Verify checkpoint, number of iterations is set across uniformly distributed checkpoints.
///
/// Returns error if `iterations` is not a multiple of checkpoints times two.
pub fn verify(
    seed: PotSeed,
    iterations: NonZeroU32,
    checkpoints: &PotCheckpoints,
) -> Result<bool, PotError> {
    let num_checkpoints = checkpoints.len() as u32;
    if iterations.get() % (num_checkpoints * 2) != 0 {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations,
            num_checkpoints,
        });
    }

    Ok(aes::verify_sequential(
        seed,
        seed.key(),
        checkpoints,
        iterations.get() / num_checkpoints,
    ))
}
