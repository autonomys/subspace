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
    portable_simd,
    step_trait
)]

pub mod chia;
pub mod chiapos;
pub mod shim;

use core::fmt;
use subspace_core_primitives::pos::{PosProof, PosSeed};

/// Proof of space table type
#[derive(Debug, Clone, Copy)]
pub enum PosTableType {
    /// Chia table
    Chia,
    /// Shim table
    Shim,
}

/// Stateful table generator with better performance
pub trait TableGenerator<T: Table>: fmt::Debug + Default + Clone + Send + Sized + 'static {
    /// Generate new table with 32 bytes seed.
    ///
    /// There is also [`Self::generate_parallel()`] that can achieve lower latency.
    fn generate(&mut self, seed: &PosSeed) -> T;

    /// Generate new table with 32 bytes seed using parallelism.
    ///
    /// This implementation will trade efficiency of CPU and memory usage for lower latency, prefer
    /// [`Self::generate()`] unless lower latency is critical.
    #[cfg(any(feature = "parallel", test))]
    fn generate_parallel(&mut self, seed: &PosSeed) -> T {
        self.generate(seed)
    }
}

/// Proof of space kind
pub trait Table: Sized + Send + Sync + 'static {
    /// Proof of space table type
    const TABLE_TYPE: PosTableType;
    /// Instance that can be used to generate tables with better performance
    type Generator: TableGenerator<Self>;

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

    /// Try to find proof at `challenge_index` if it exists
    fn find_proof(&self, challenge_index: u32) -> Option<PosProof>;

    /// Check whether proof created earlier is valid and return quality bytes if yes
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool;

    /// Returns a stateful table generator with better performance
    fn generator() -> Self::Generator {
        Self::Generator::default()
    }
}
