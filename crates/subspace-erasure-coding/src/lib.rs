#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use blst_from_scratch::types::fft_settings::FsFFTSettings;
use blst_from_scratch::types::fr::FsFr;
use blst_from_scratch::types::poly::FsPoly;
use core::num::NonZeroUsize;
use kzg::{FFTSettings, PolyRecover, DAS};
use subspace_core_primitives::crypto::Scalar;

/// Erasure coding abstraction.
///
/// Supports creation of parity records and recovery of missing data.
#[derive(Debug, Clone)]
pub struct ErasureCoding {
    fft_settings: Arc<FsFFTSettings>,
}

impl ErasureCoding {
    /// Create new erasure coding instance.
    ///
    /// Number of shards supported is `2^scale`, half of shards are source data and the other half
    /// are parity.
    pub fn new(scale: NonZeroUsize) -> Result<Self, String> {
        let fft_settings = Arc::new(FsFFTSettings::new(scale.get())?);

        Ok(Self { fft_settings })
    }

    /// Extend sources using erasure coding.
    ///
    /// Returns parity data.
    pub fn extend(&self, source: &[Scalar]) -> Result<Vec<Scalar>, String> {
        // TODO: das_fft_extension modifies buffer internally, it needs to change to use
        //  pre-allocated buffer instead of allocating a new one
        self.fft_settings
            .das_fft_extension(Scalar::slice_to_repr(source))
            .map(Scalar::vec_from_repr)
    }

    /// Recovery of missing shards from given shards (at least 1/2 should be `Some`).
    ///
    /// Both in input and output source shards are interleaved with parity shards:
    /// source, parity, source, parity, ...
    pub fn recover(&self, shards: &[Option<Scalar>]) -> Result<Vec<Scalar>, String> {
        // TODO This is only necessary because upstream silently doesn't recover anything:
        //  https://github.com/sifraitech/rust-kzg/issues/195
        if shards.iter().filter(|scalar| scalar.is_some()).count() < self.fft_settings.max_width / 2
        {
            return Err("Impossible to recover, too many shards are missing".to_string());
        }
        let poly = <FsPoly as PolyRecover<FsFr, FsPoly, _>>::recover_poly_from_samples(
            Scalar::slice_option_to_repr(shards),
            &self.fft_settings,
        )?;

        Ok(Scalar::vec_from_repr(poly.coeffs))
    }
}
