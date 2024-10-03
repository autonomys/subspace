//! Chia proof of space reimplementation in Rust

mod constants;
mod table;
mod tables;
mod utils;

use crate::chiapos::table::metadata_size_bytes;
pub use crate::chiapos::table::TablesCache;
use crate::chiapos::tables::TablesGeneric;
use crate::chiapos::utils::EvaluatableUsize;

type Seed = [u8; 32];
type Challenge = [u8; 32];
type Quality = [u8; 32];

/// Collection of Chia tables
#[derive(Debug)]
pub struct Tables<const K: u8>(TablesGeneric<K>)
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized;

macro_rules! impl_any {
    ($($k: expr$(,)? )*) => {
        $(
impl Tables<$k> {
    /// Create Chia proof of space tables. There also exists [`Self::create_parallel()`] that trades
    /// CPU efficiency and memory usage for lower latency.
    ///
    /// Advanced version of [`Self::create_simple`] that allows to reuse cache.
    pub fn create(seed: Seed, cache: &mut TablesCache<$k>) -> Self {
        Self(TablesGeneric::<$k>::create(
            seed, cache,
        ))
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// performance (though not efficiency of CPU and memory usage), if you create multiple tables
    /// in parallel, prefer [`Self::create()`] for better overall performance.
    #[cfg(any(feature = "parallel", test))]
    pub fn create_parallel(seed: Seed, cache: &mut TablesCache<$k>) -> Self {
        Self(TablesGeneric::<$k>::create_parallel(
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

// Only these k values are supported by current implementation
impl_any!(15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
