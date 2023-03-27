//! Tools for KZG commitment scheme

#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

extern crate alloc;

use crate::crypto::Scalar;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use blst_from_scratch::eip_4844::{bytes_from_g1_rust, bytes_to_g1_rust, bytes_to_g2_rust};
use blst_from_scratch::types::fft_settings::FsFFTSettings;
use blst_from_scratch::types::g1::FsG1;
use blst_from_scratch::types::kzg_settings::FsKZGSettings;
use blst_from_scratch::types::poly::FsPoly;
use core::hash::{Hash, Hasher};
use core::mem;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};
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

/// Commitment to polynomial
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, From, Into, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct Commitment(FsG1);

impl Commitment {
    /// Commitment size in bytes.
    const SIZE: usize = 48;

    /// Convert commitment to raw bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        bytes_from_g1_rust(&self.0)
    }

    /// Try to deserialize commitment from raw bytes
    pub fn try_from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, String> {
        Ok(Commitment(bytes_to_g1_rust(bytes)?))
    }

    /// Convenient conversion from slice of commitment to underlying representation for efficiency
    /// purposes.
    pub fn slice_to_repr(value: &[Self]) -> &[FsG1] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to commitment for efficiency
    /// purposes.
    pub fn slice_from_repr(value: &[FsG1]) -> &[Self] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional commitment to underlying representation for
    /// efficiency purposes.
    pub fn slice_option_to_repr(value: &[Option<Self>]) -> &[Option<FsG1>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional underlying representation to commitment for
    /// efficiency purposes.
    pub fn slice_option_from_repr(value: &[Option<FsG1>]) -> &[Option<Self>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of commitment to underlying representation for
    /// efficiency purposes.
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [FsG1] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to commitment for
    /// efficiency purposes.
    pub fn slice_mut_from_repr(value: &mut [FsG1]) -> &mut [Self] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of commitment to underlying representation
    /// for efficiency purposes.
    pub fn slice_option_mut_to_repr(value: &mut [Option<Self>]) -> &mut [Option<FsG1>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of underlying representation to commitment
    /// for efficiency purposes.
    pub fn slice_option_mut_from_repr(value: &mut [Option<FsG1>]) -> &mut [Option<Self>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from vector of commitment to underlying representation for efficiency
    /// purposes.
    pub fn vec_to_repr(value: Vec<Self>) -> Vec<FsG1> {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut FsG1,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of underlying representation to commitment for efficiency
    /// purposes.
    pub fn vec_from_repr(value: Vec<FsG1>) -> Vec<Self> {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Self,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of optional commitment to underlying representation for
    /// efficiency purposes.
    pub fn vec_option_to_repr(value: Vec<Option<Self>>) -> Vec<Option<FsG1>> {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Option<FsG1>,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of optional underlying representation to commitment for
    /// efficiency purposes.
    pub fn vec_option_from_repr(value: Vec<Option<FsG1>>) -> Vec<Option<Self>> {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Option<Self>,
                value.len(),
                value.capacity(),
            )
        }
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl From<Commitment> for [u8; Commitment::SIZE] {
    fn from(commitment: Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl From<&Commitment> for [u8; Commitment::SIZE] {
    fn from(commitment: &Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl TryFrom<&[u8; Self::SIZE]> for Commitment {
    type Error = String;

    fn try_from(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; Self::SIZE]> for Commitment {
    type Error = String;

    fn try_from(bytes: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
    }
}

impl Encode for Commitment {
    fn size_hint(&self) -> usize {
        Self::SIZE
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    fn encoded_size(&self) -> usize {
        Self::SIZE
    }
}

impl EncodeLike for Commitment {}

impl MaxEncodedLen for Commitment {
    fn max_encoded_len() -> usize {
        Self::SIZE
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
        Some(Self::SIZE)
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
                f.ty::<[u8; Self::SIZE]>()
                    .name(stringify!(inner))
                    .type_name("G1Affine")
            }))
    }
}

/// Witness for polynomial evaluation
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, From, Into, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct Witness(FsG1);

impl Witness {
    /// Commitment size in bytes.
    const SIZE: usize = 48;

    /// Convert witness to raw bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        bytes_from_g1_rust(&self.0)
    }

    /// Try to deserialize witness from raw bytes
    pub fn try_from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, String> {
        Ok(Witness(bytes_to_g1_rust(bytes)?))
    }
}

impl From<Witness> for [u8; Witness::SIZE] {
    fn from(witness: Witness) -> Self {
        witness.to_bytes()
    }
}

impl From<&Witness> for [u8; Witness::SIZE] {
    fn from(witness: &Witness) -> Self {
        witness.to_bytes()
    }
}

impl TryFrom<&[u8; Self::SIZE]> for Witness {
    type Error = String;

    fn try_from(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; Self::SIZE]> for Witness {
    type Error = String;

    fn try_from(bytes: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
    }
}

impl Encode for Witness {
    fn size_hint(&self) -> usize {
        Self::SIZE
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    fn encoded_size(&self) -> usize {
        Self::SIZE
    }
}

impl EncodeLike for Witness {}

impl MaxEncodedLen for Witness {
    fn max_encoded_len() -> usize {
        Self::SIZE
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
        Some(Self::SIZE)
    }
}

impl TypeInfo for Witness {
    type Identity = Self;

    fn type_info() -> Type {
        Type::builder()
            .path(scale_info::Path::new(stringify!(Witness), module_path!()))
            .docs(&["Witness for polynomial evaluation"])
            .composite(scale_info::build::Fields::named().field(|f| {
                f.ty::<[u8; Self::SIZE]>()
                    .name(stringify!(inner))
                    .type_name("G1Affine")
            }))
    }
}

#[derive(Debug)]
struct Inner {
    kzg_settings: FsKZGSettings,
    fft_settings_cache: Mutex<BTreeMap<usize, Arc<FsFFTSettings>>>,
}

/// Wrapper data structure for working with KZG commitment scheme
#[derive(Debug, Clone)]
pub struct Kzg {
    inner: Arc<Inner>,
}

impl Kzg {
    /// Create new instance with given KZG settings.
    ///
    /// Canonical KZG settings can be obtained using `embedded_kzg_settings()` function that becomes
    /// available with `embedded-kzg-settings` feature (enabled by default).
    pub fn new(kzg_settings: FsKZGSettings) -> Self {
        let inner = Arc::new(Inner {
            kzg_settings,
            fft_settings_cache: Mutex::default(),
        });

        Self { inner }
    }

    /// Create polynomial from data. Data must be multiple of 32 bytes, each containing up to 254
    /// bits of information.
    ///
    /// The resulting polynomial is in coefficient form.
    pub fn poly(&self, data: &[Scalar]) -> Result<Polynomial, String> {
        let poly = FsPoly {
            coeffs: self
                .get_fft_settings(data.len())?
                .fft_fr(Scalar::slice_to_repr(data), true)?,
        };
        Ok(Polynomial(poly))
    }

    /// Computes a `Commitment` to `polynomial`
    pub fn commit(&self, polynomial: &Polynomial) -> Result<Commitment, String> {
        self.inner
            .kzg_settings
            .commit_to_poly(&polynomial.0)
            .map(Commitment)
    }

    /// Computes a `Witness` of evaluation of `polynomial` at `index`
    pub fn create_witness(&self, polynomial: &Polynomial, index: u32) -> Result<Witness, String> {
        let x = self
            .get_fft_settings(polynomial.0.coeffs.len())?
            .get_expanded_roots_of_unity_at(index as usize);
        self.inner
            .kzg_settings
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
        value: &Scalar,
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

        match self
            .inner
            .kzg_settings
            .check_proof_single(&commitment.0, &witness.0, &x, value)
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
        let num_values = num_values.next_power_of_two();
        Ok(
            match self.inner.fft_settings_cache.lock().entry(num_values) {
                Entry::Vacant(entry) => {
                    let fft_settings = Arc::new(FsFFTSettings::new(num_values.ilog2() as usize)?);
                    entry.insert(Arc::clone(&fft_settings));
                    fft_settings
                }
                Entry::Occupied(entry) => Arc::clone(entry.get()),
            },
        )
    }
}
