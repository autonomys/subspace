//! Chia proof of space reimplementation in Rust

mod constants;
mod table;
mod tables;
mod utils;

#[cfg(feature = "alloc")]
pub use crate::chiapos::table::TablesCache;
use crate::chiapos::table::{metadata_size_bytes, num_buckets};
use crate::chiapos::tables::TablesGeneric;
use crate::chiapos::utils::EvaluatableUsize;

type Seed = [u8; 32];
#[cfg(any(feature = "full-chiapos", test))]
type Challenge = [u8; 32];
#[cfg(any(feature = "full-chiapos", test))]
type Quality = [u8; 32];

/// Collection of Chia tables
#[derive(Debug)]
pub struct Tables<const K: u8>(TablesGeneric<K>)
where
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:;

macro_rules! impl_any {
    ($($k: expr$(,)? )*) => {
        $(
impl Tables<$k> {
    /// Create Chia proof of space tables. There also exists [`Self::create_parallel()`] that trades
    /// memory usage for lower latency and higher CPU efficiency.
    #[cfg(feature = "alloc")]
    pub fn create(seed: Seed, cache: &TablesCache) -> Self {
        Self(TablesGeneric::<$k>::create(
            seed, cache,
        ))
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// latency and performance (though higher memory usage).
    #[cfg(feature = "parallel")]
    pub fn create_parallel(seed: Seed, cache: &TablesCache) -> Self {
        Self(TablesGeneric::<$k>::create_parallel(
            seed, cache,
        ))
    }

    /// Find proof of space quality for a given challenge.
    #[cfg(all(feature = "alloc", any(feature = "full-chiapos", test)))]
    pub fn find_quality<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = Quality> + 'a {
        self.0.find_quality(challenge)
    }

    /// Find proof of space for a given challenge.
    #[cfg(feature = "alloc")]
    pub fn find_proof<'a>(
        &'a self,
        first_challenge_bytes: [u8; 4],
    ) -> impl Iterator<Item = [u8; 64 * $k / 8]> + 'a {
        self.0.find_proof(first_challenge_bytes)
    }

    /// Verify proof of space for a given seed and challenge
    pub fn verify_only(
        seed: &Seed,
        first_challenge_bytes: [u8; 4],
        proof_of_space: &[u8; 64 * $k as usize / 8],
    ) -> bool {
        TablesGeneric::<$k>::verify_only(seed, first_challenge_bytes, proof_of_space)
    }

    /// Verify proof of space for a given seed and challenge.
    ///
    /// Similar to [`Self::verify_only()`], but also returns quality on successful verification.
    #[cfg(any(feature = "full-chiapos", test))]
    pub fn verify(
        seed: &Seed,
        challenge: &Challenge,
        proof_of_space: &[u8; 64 * $k as usize / 8],
    ) -> Option<Quality> {
        TablesGeneric::<$k>::verify(seed, challenge, proof_of_space)
    }
}
        )*
    }
}

// Only these k values are supported by the current implementation
#[cfg(feature = "full-chiapos")]
impl_any!(15, 16, 18, 19, 21, 22, 23, 24, 25);
#[cfg(any(feature = "full-chiapos", test))]
impl_any!(17);
impl_any!(20);
