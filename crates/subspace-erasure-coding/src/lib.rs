#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(all(test, features = "std"))]
mod tests;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use blst_from_scratch::types::fft_settings::FsFFTSettings;
use blst_from_scratch::types::fr::FsFr;
use blst_from_scratch::types::poly::FsPoly;
use core::num::NonZeroUsize;
use kzg::{FFTSettings, PolyRecover, DAS};
use subspace_core_primitives::Scalar;

/// Erasure coding abstraction.
///
/// Supports creation of parity records and recovery of missing data.
#[derive(Debug, Clone)]
pub struct ErasureCoding {
    fft_settings: FsFFTSettings,
}

impl ErasureCoding {
    /// Create new erasure coding instance.
    ///
    /// Number of shards supported is `2^scale`, half of shards are source data and the other half
    /// are parity.
    pub fn new(scale: NonZeroUsize) -> Result<Self, String> {
        let fft_settings = FsFFTSettings::new(scale.get())?;

        Ok(Self { fft_settings })
    }

    /// Extend sources using erasure coding.
    ///
    /// Returns parity data.
    pub fn extend(&self, source: &[Scalar]) -> Result<Vec<Scalar>, String> {
        // TODO: Once our scalars are based on `blst_from_scratch` we can use a bit of transmute to
        //  avoid allocation here
        // TODO: das_fft_extension modifies buffer internally, it needs to change to use
        //  pre-allocated buffer instead of allocating a new one
        let source = source
            .iter()
            .map(|scalar| {
                FsFr::from_scalar(scalar.to_bytes())
                    .map_err(|error| format!("Failed to convert scalar: {error}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let parity = self
            .fft_settings
            .das_fft_extension(&source)?
            .into_iter()
            .map(|scalar| {
                // This is fine, scalar is guaranteed to be correct here
                Scalar::from(scalar.to_scalar())
            })
            .collect();

        Ok(parity)
    }

    /// Recovery of missing shards from given shards (at least 1/2 should be `Some`).
    ///
    /// Both in input and output source shards are interleaved with parity shards:
    /// source, parity, source, parity, ....
    pub fn recover(&self, shards: &[Option<Scalar>]) -> Result<Vec<Scalar>, String> {
        // TODO This is only necessary because upstream silently doesn't recover anything:
        //  https://github.com/sifraitech/rust-kzg/issues/195
        if shards.iter().filter(|scalar| scalar.is_some()).count() < self.fft_settings.max_width / 2
        {
            return Err("Impossible to recover, too many shards are missing".to_string());
        }
        // TODO: Once our scalars are based on `blst_from_scratch` we can use a bit of transmute to
        //  avoid allocation here
        let shards = shards
            .iter()
            .map(|maybe_scalar| {
                maybe_scalar
                    .map(|scalar| {
                        FsFr::from_scalar(scalar.into())
                            .map_err(|error| format!("Failed to convert scalar: {error}"))
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let poly = <FsPoly as PolyRecover<FsFr, FsPoly, _>>::recover_poly_from_samples(
            &shards,
            &self.fft_settings,
        )?;

        Ok(poly
            .coeffs
            .iter()
            .map(|scalar| {
                // This is fine, scalar is guaranteed to be correct here
                Scalar::from(scalar.to_scalar())
            })
            .collect())
    }
}
