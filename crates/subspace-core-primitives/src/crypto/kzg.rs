//! Tools for KZG commitment scheme

#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

extern crate alloc;

use crate::Scalar;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use blst_from_scratch::eip_4844::{bytes_from_g1_rust, bytes_to_g1_rust, bytes_to_g2_rust};
use blst_from_scratch::types::fft_settings::FsFFTSettings;
use blst_from_scratch::types::fr::FsFr;
use blst_from_scratch::types::g1::FsG1;
use blst_from_scratch::types::kzg_settings::FsKZGSettings;
use blst_from_scratch::types::poly::FsPoly;
use core::hash::{Hash, Hasher};
use kzg::{FFTFr, FFTSettings, KZGSettings};
use parity_scale_codec::{Decode, Encode, EncodeLike, Input, MaxEncodedLen};
#[cfg(feature = "std")]
use parking_lot::Mutex;
use scale_info::{Type, TypeInfo};
#[cfg(not(feature = "std"))]
use spin::Mutex;
use tracing::debug;

/// Embedded KZG settings as bytes, too big for `no_std` in most cases
#[cfg(feature = "embedded-kzg-settings")]
pub const EMBEDDED_KZG_SETTINGS_BYTES: &[u8] = include_bytes!("kzg/test-public-parameters.bin");

// Symmetric function is present in tests
/// Function turns bytes into `FsKZGSettings`, it is up to the user to ensure that bytes make sense,
/// otherwise result can be very wrong (but will not panic).
pub fn bytes_to_kzg_settings(bytes: &[u8]) -> Result<FsKZGSettings, String> {
    // 48 bytes per G1 and 96 bytes per G2;
    if bytes.is_empty() || bytes.len() % (48 + 96) != 0 {
        return Err("Bad bytes".to_string());
    }
    let secret_len = bytes.len() / (48 + 96);

    let (secret_g1_bytes, secret_g2_bytes) = bytes.split_at(secret_len * 48);
    let secret_g1 = secret_g1_bytes
        .chunks_exact(48)
        .map(|bytes| {
            bytes_to_g1_rust(
                bytes
                    .try_into()
                    .expect("Chunked into correct number of bytes above; qed"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let secret_g2 = secret_g2_bytes
        .chunks_exact(96)
        .map(|bytes| {
            bytes_to_g2_rust(
                bytes
                    .try_into()
                    .expect("Chunked into correct number of bytes above; qed"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let fft_settings = FsFFTSettings::new(
        secret_len
            .checked_sub(1)
            .expect("Checked to be not empty above; qed")
            .ilog2() as usize,
    )
    .expect("Scale is within allowed bounds; qed");

    // Below is the same as `FsKZGSettings::new(&s1, &s2, secret_len, &fft_settings)`, but without
    // extra checks (parameters are static anyway) and without unnecessary allocations
    Ok(FsKZGSettings {
        fs: fft_settings,
        secret_g1,
        secret_g2,
    })
}

/// TODO: Test public parameters, must be replaced with proper public parameters later
/// Embedded KZG settings
#[cfg(feature = "embedded-kzg-settings")]
pub fn embedded_kzg_settings() -> FsKZGSettings {
    bytes_to_kzg_settings(EMBEDDED_KZG_SETTINGS_BYTES)
        .expect("Static bytes are correct, there is a test for this; qed")
}

/// Commitment to polynomial
#[derive(Debug, Clone)]
pub struct Polynomial(FsPoly);

/// Commitment size in bytes.
pub const COMMITMENT_SIZE: usize = 48;

/// Commitment to polynomial
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Commitment(FsG1);

impl Commitment {
    /// Convert commitment to raw bytes
    pub fn to_bytes(&self) -> [u8; COMMITMENT_SIZE] {
        bytes_from_g1_rust(&self.0)
    }

    /// Try to deserialize commitment from raw bytes
    pub fn try_from_bytes(bytes: &[u8; COMMITMENT_SIZE]) -> Result<Self, String> {
        Ok(Commitment(bytes_to_g1_rust(bytes)?))
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl From<Commitment> for [u8; COMMITMENT_SIZE] {
    fn from(commitment: Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl From<&Commitment> for [u8; COMMITMENT_SIZE] {
    fn from(commitment: &Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl TryFrom<&[u8; COMMITMENT_SIZE]> for Commitment {
    type Error = String;

    fn try_from(bytes: &[u8; COMMITMENT_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; COMMITMENT_SIZE]> for Commitment {
    type Error = String;

    fn try_from(bytes: [u8; COMMITMENT_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
    }
}

impl Encode for Commitment {
    fn size_hint(&self) -> usize {
        COMMITMENT_SIZE
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    fn encoded_size(&self) -> usize {
        COMMITMENT_SIZE
    }
}

impl EncodeLike for Commitment {}

impl MaxEncodedLen for Commitment {
    fn max_encoded_len() -> usize {
        COMMITMENT_SIZE
    }
}

impl Decode for Commitment {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        Self::try_from_bytes(&Decode::decode(input)?).map_err(|error| {
            parity_scale_codec::Error::from("Failed to decode from bytes")
                .chain(alloc::format!("{error:?}"))
        })
    }

    fn encoded_fixed_size() -> Option<usize> {
        Some(COMMITMENT_SIZE)
    }
}

impl TypeInfo for Commitment {
    type Identity = Self;

    fn type_info() -> Type {
        Type::builder()
            .path(scale_info::Path::new(
                stringify!(Commitment),
                module_path!(),
            ))
            .docs(&["Commitment to polynomial"])
            .composite(scale_info::build::Fields::named().field(|f| {
                f.ty::<[u8; COMMITMENT_SIZE]>()
                    .name(stringify!(inner))
                    .type_name("G1Affine")
            }))
    }
}

/// Witness for polynomial evaluation
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Witness(FsG1);

impl Witness {
    /// Convert witness to raw bytes
    pub fn to_bytes(&self) -> [u8; COMMITMENT_SIZE] {
        bytes_from_g1_rust(&self.0)
    }

    /// Try to deserialize witness from raw bytes
    pub fn try_from_bytes(bytes: &[u8; COMMITMENT_SIZE]) -> Result<Self, String> {
        Ok(Witness(bytes_to_g1_rust(bytes)?))
    }
}

impl From<Witness> for [u8; COMMITMENT_SIZE] {
    fn from(witness: Witness) -> Self {
        witness.to_bytes()
    }
}

impl From<&Witness> for [u8; COMMITMENT_SIZE] {
    fn from(witness: &Witness) -> Self {
        witness.to_bytes()
    }
}

impl TryFrom<&[u8; COMMITMENT_SIZE]> for Witness {
    type Error = String;

    fn try_from(bytes: &[u8; COMMITMENT_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; COMMITMENT_SIZE]> for Witness {
    type Error = String;

    fn try_from(bytes: [u8; COMMITMENT_SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
    }
}

impl Encode for Witness {
    fn size_hint(&self) -> usize {
        COMMITMENT_SIZE
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    fn encoded_size(&self) -> usize {
        COMMITMENT_SIZE
    }
}

impl EncodeLike for Witness {}

impl MaxEncodedLen for Witness {
    fn max_encoded_len() -> usize {
        COMMITMENT_SIZE
    }
}

impl Decode for Witness {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        Self::try_from_bytes(&Decode::decode(input)?).map_err(|error| {
            parity_scale_codec::Error::from("Failed to decode from bytes")
                .chain(alloc::format!("{error:?}"))
        })
    }

    fn encoded_fixed_size() -> Option<usize> {
        Some(COMMITMENT_SIZE)
    }
}

impl TypeInfo for Witness {
    type Identity = Self;

    fn type_info() -> Type {
        Type::builder()
            .path(scale_info::Path::new(stringify!(Witness), module_path!()))
            .docs(&["Witness for polynomial evaluation"])
            .composite(scale_info::build::Fields::named().field(|f| {
                f.ty::<[u8; COMMITMENT_SIZE]>()
                    .name(stringify!(inner))
                    .type_name("G1Affine")
            }))
    }
}

/// Wrapper data structure for working with KZG commitment scheme
#[derive(Debug, Clone)]
pub struct Kzg {
    kzg_settings: FsKZGSettings,
    fft_settings_cache: Arc<Mutex<BTreeMap<usize, Arc<FsFFTSettings>>>>,
}

impl Kzg {
    /// Create new instance with given KZG settings.
    ///
    /// Canonical KZG settings can be obtained using `embedded_kzg_settings()` function that becomes
    /// available with `embedded-kzg-settings` feature (enabled by default).
    pub fn new(kzg_settings: FsKZGSettings) -> Self {
        Self {
            kzg_settings,
            fft_settings_cache: Arc::default(),
        }
    }

    /// Create polynomial from data. Data must be multiple of 32 bytes, each containing up to 254
    /// bits of information.
    ///
    /// The resulting polynomial is in coefficient form.
    pub fn poly(&self, data: &[u8]) -> Result<Polynomial, String> {
        let evals = data
            .chunks(Scalar::FULL_BYTES)
            .map(|scalar| {
                FsFr::from_scalar(
                    scalar
                        .try_into()
                        .map_err(|_| "Failed to convert value to scalar".to_string())?,
                )
                .map_err(|error_code| {
                    format!("Failed to create scalar from bytes with code: {error_code}")
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let poly = FsPoly {
            coeffs: self.get_fft_settings(evals.len())?.fft_fr(&evals, true)?,
        };
        Ok(Polynomial(poly))
    }

    /// Computes a `Commitment` to `polynomial`
    pub fn commit(&self, polynomial: &Polynomial) -> Result<Commitment, String> {
        self.kzg_settings
            .commit_to_poly(&polynomial.0)
            .map(Commitment)
    }

    /// Computes a `Witness` of evaluation of `polynomial` at `index`
    pub fn create_witness(&self, polynomial: &Polynomial, index: u32) -> Result<Witness, String> {
        let x = self
            .get_fft_settings(polynomial.0.coeffs.len())?
            .get_expanded_roots_of_unity_at(index as usize);
        self.kzg_settings
            .compute_proof_single(&polynomial.0, &x)
            .map(Witness)
    }

    /// Verifies that `value` is the evaluation at `index` of the polynomial created from
    /// `num_values` values matching the `commitment`.
    pub fn verify(
        &self,
        commitment: &Commitment,
        num_values: usize,
        index: u32,
        value: &[u8],
        witness: &Witness,
    ) -> bool {
        let fft_settings = match self.get_fft_settings(num_values) {
            Ok(fft_settings) => fft_settings,
            Err(error) => {
                debug!(error, "Failed to derive fft settings");
                return false;
            }
        };
        let x = fft_settings.get_expanded_roots_of_unity_at(index as usize);
        let value = match value.try_into() {
            Ok(value) => value,
            Err(_) => {
                debug!("Failed to convert value to scalar");
                return false;
            }
        };
        let value = match FsFr::from_scalar(value) {
            Ok(value) => value,
            Err(error_code) => {
                debug!(error_code, "Failed to create scalar from bytes with code");
                return false;
            }
        };

        match self
            .kzg_settings
            .check_proof_single(&commitment.0, &witness.0, &x, &value)
        {
            Ok(result) => result,
            Err(error) => {
                debug!(error, "Failed to check proof");
                false
            }
        }
    }

    /// Get FFT settings for specified number of values, uses internal cache to avoid derivation
    /// every time.
    pub fn get_fft_settings(&self, num_values: usize) -> Result<Arc<FsFFTSettings>, String> {
        Ok(match self.fft_settings_cache.lock().entry(num_values) {
            Entry::Vacant(entry) => {
                let fft_settings = Arc::new(FsFFTSettings::new(num_values.ilog2() as usize)?);
                entry.insert(Arc::clone(&fft_settings));
                fft_settings
            }
            Entry::Occupied(entry) => Arc::clone(entry.get()),
        })
    }
}
