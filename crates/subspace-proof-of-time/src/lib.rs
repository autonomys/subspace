//! Proof of time implementation.

#![cfg_attr(not(feature = "std"), no_std)]
mod aes;

use core::num::{NonZeroU32, NonZeroU64};
use subspace_core_primitives::{PotCheckpoints, PotKey, PotProof, PotSeed};

/// Proof of time error
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum PotError {
    /// Iterations is not multiple of number of checkpoints times two
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Iterations {iterations} is not multiple of number of checkpoints {num_checkpoints} \
            times two"
        )
    )]
    NotMultipleOfCheckpoints {
        /// Slot iterations provided
        iterations: NonZeroU64,
        /// Number of checkpoints
        num_checkpoints: u64,
    },
}

/// Run PoT proving and produce checkpoints.
///
/// Returns error if `iterations` is not a multiple of checkpoints times two.
#[inline]
pub fn prove(
    seed: PotSeed,
    key: PotKey,
    iterations: NonZeroU32,
) -> Result<PotCheckpoints, PotError> {
    if iterations.get() % u32::from(PotCheckpoints::NUM_CHECKPOINTS.get() * 2) != 0 {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations: NonZeroU64::from(iterations),
            num_checkpoints: u64::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
        });
    }

    Ok(aes::create(
        &seed,
        &key,
        iterations.get() / u32::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
    ))
}

/// Verify checkpoint, number of iterations is set across uniformly distributed checkpoints.
///
/// Returns error if `iterations` is not a multiple of checkpoints times two.
#[inline]
pub fn verify(
    seed: PotSeed,
    key: PotKey,
    iterations: NonZeroU64,
    checkpoints: &[PotProof],
) -> Result<bool, PotError> {
    let num_checkpoints = checkpoints.len() as u64;
    if iterations.get() % (num_checkpoints * 2) != 0 {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations,
            num_checkpoints,
        });
    }

    Ok(aes::verify_sequential(
        &seed,
        &key,
        checkpoints,
        iterations.get() / num_checkpoints,
    ))
}
