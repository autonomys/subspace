//! Subspace proof of space implementation based on Chia
#![cfg_attr(not(feature = "std"), no_std)]
// `generic_const_exprs` is an incomplete feature
#![allow(incomplete_features)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![feature(
    array_chunks,
    array_windows,
    const_trait_impl,
    generic_const_exprs,
    int_roundings,
    iter_collect_into
)]

#[cfg(feature = "chia")]
pub mod chia;
#[cfg(feature = "chia-legacy")]
pub mod chia_legacy;
#[cfg(feature = "chia")]
pub mod chiapos;
#[cfg(feature = "shim")]
pub mod shim;

use subspace_core_primitives::{PosProof, PosQualityBytes, PosSeed};

/// Abstraction that represents quality of the solution in the table
pub trait Quality {
    /// Get underlying bytes representation of the quality
    fn to_bytes(&self) -> PosQualityBytes;

    /// Create proof for this solution
    fn create_proof(&self) -> PosProof;
}

/// Proof of space table type
#[derive(Debug, Clone, Copy)]
pub enum PosTableType {
    /// Chia table
    #[cfg(feature = "chia-legacy")]
    ChiaLegacy,
    /// Chia table
    #[cfg(feature = "chia")]
    Chia,
    /// Shim table
    #[cfg(feature = "shim")]
    Shim,
}

/// Proof of space kind
pub trait Table: Sized + Send + Sync + 'static {
    /// Proof of space table type
    const TABLE_TYPE: PosTableType;

    /// Abstraction that represents quality of the solution in the table
    type Quality<'a>: Quality
    where
        Self: 'a;

    /// Generate new table with 32 bytes seed.
    ///
    /// There is also [`Self::generate_parallel()`] that can achieve lower latency.
    fn generate(seed: &PosSeed) -> Self;

    /// Generate new table with 32 bytes seed using parallelism.
    ///
    /// This implementation will trade efficiency of CPU and memory usage for lower latency, prefer
    /// [`Self::generate()`] unless lower latency is critical.
    #[cfg(any(feature = "parallel", test))]
    fn generate_parallel(seed: &PosSeed) -> Self {
        Self::generate(seed)
    }

    /// Try to find quality of the proof at `challenge_index` if proof exists
    fn find_quality(&self, challenge_index: u32) -> Option<Self::Quality<'_>>;

    /// Check whether proof created earlier is valid and return quality bytes if yes
    fn is_proof_valid(
        seed: &PosSeed,
        challenge_index: u32,
        proof: &PosProof,
    ) -> Option<PosQualityBytes>;
}
