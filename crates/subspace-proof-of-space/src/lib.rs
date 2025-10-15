//! Proof of space implementation
#![no_std]
#![expect(incomplete_features, reason = "generic_const_exprs")]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![feature(
    array_windows,
    const_convert,
    const_trait_impl,
    exact_size_is_empty,
    generic_const_exprs,
    get_mut_unchecked,
    maybe_uninit_fill,
    maybe_uninit_slice,
    maybe_uninit_write_slice,
    portable_simd,
    step_trait,
    sync_unsafe_cell,
    vec_into_raw_parts
)]

pub mod chia;
pub mod chiapos;
pub mod shim;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use core::fmt;
use subspace_core_primitives::pos::{PosProof, PosSeed};
use subspace_core_primitives::solutions::SolutionPotVerifier;

/// Proof of space table type
#[derive(Debug, Clone, Copy)]
pub enum PosTableType {
    /// Chia table
    Chia,
    /// Shim table
    Shim,
}

/// Stateful table generator with better performance.
///
/// Prefer cloning it over creating multiple separate generators.
#[cfg(feature = "alloc")]
pub trait TableGenerator<T: Table>:
    fmt::Debug + Default + Clone + Send + Sync + Sized + 'static
{
    /// Generate a new table with 32 bytes seed.
    ///
    /// There is also [`Self::generate_parallel()`] that can achieve lower latency.
    fn generate(&self, seed: &PosSeed) -> T;

    /// Generate a new table with 32 bytes seed using parallelism.
    ///
    /// This implementation will trade efficiency of CPU and memory usage for lower latency, prefer
    /// [`Self::generate()`] unless lower latency is critical.
    #[cfg(feature = "parallel")]
    fn generate_parallel(&self, seed: &PosSeed) -> T {
        self.generate(seed)
    }
}

/// Proof of space kind
pub trait Table: SolutionPotVerifier + Sized + Send + Sync + 'static {
    /// Proof of space table type
    const TABLE_TYPE: PosTableType;
    /// Instance that can be used to generate tables with better performance
    #[cfg(feature = "alloc")]
    type Generator: TableGenerator<Self>;

    /// Try to find proof at `challenge_index` if it exists
    #[cfg(feature = "alloc")]
    fn find_proof(&self, challenge_index: u32) -> Option<PosProof>;

    /// Check whether proof created earlier is valid
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool;

    /// Returns a stateful table generator with better performance
    #[cfg(feature = "alloc")]
    fn generator() -> Self::Generator {
        Self::Generator::default()
    }
}
