//! Chia proof of space reimplementation in Rust

mod constants;
mod table;
mod tables;
#[cfg(test)]
mod tests;
mod utils;

pub use crate::chiapos::table::TablesCache;
use crate::chiapos::table::{
    fn_hashing_input_bytes, metadata_size_bytes, x_size_bytes, y_size_bytes,
};
use crate::chiapos::tables::TablesGeneric;
use crate::chiapos::utils::EvaluatableUsize;

type Seed = [u8; 32];
type Challenge = [u8; 32];
type Quality = [u8; 32];

/// Collection of Chia tables
#[derive(Debug)]
pub struct Tables<const K: u8>(TablesGeneric<K>)
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized;

macro_rules! impl_any {
    ($($k: expr$(,)? )*) => {
        $(
impl Tables<$k> {
    /// Create Chia proof of space tables.
    ///
    /// Advanced version of [`Self::create_simple`] that allows to reuse cache.
    pub fn create(seed: Seed, cache: &mut TablesCache<$k>) -> Self {
        Self(TablesGeneric::<$k>::create(
            seed, cache,
        ))
    }

    /// Create Chia proof of space tables.
    ///
    /// Simpler version of [`Self::create`].
    pub fn create_simple(seed: Seed) -> Self {
        Self::create(seed, &mut TablesCache::default())
    }

    /// Find proof of space quality for given challenge.
    pub fn find_quality<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = Quality> + 'a {
        self.0.find_quality(challenge)
    }

    /// Find proof of space for given challenge.
    pub fn find_proof<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = [u8; 64 * $k / 8]> + 'a {
        self.0.find_proof(challenge)
    }

    /// Verify proof of space for given seed and challenge.
    pub fn verify(
        seed: Seed,
        challenge: &Challenge,
        proof_of_space: &[u8; 64 * $k as usize / 8],
    ) -> Option<Quality> {
        TablesGeneric::<$k>::verify(seed, challenge, proof_of_space)
    }
}
        )*
    }
}

// These are all `K` which can be safely used on 32-bit platform
#[cfg(feature = "all-chia-k")]
impl_any!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20);
impl_any!(16, 17, 18);

// These are all `K` which require 64-bit platform
#[cfg(target_pointer_width = "64")]
impl_any!(32, 33, 34, 35);
#[cfg(all(target_pointer_width = "64", feature = "all-chia-k"))]
impl_any!(21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 36, 37, 38, 39, 40);
