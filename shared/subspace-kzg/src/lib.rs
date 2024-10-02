//! KZG primitives for Subspace Network

#[cfg(test)]
mod tests;

extern crate alloc;

use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::mem;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};
use kzg::eip_4844::{BYTES_PER_G1, BYTES_PER_G2};
use kzg::{FFTFr, FFTSettings, Fr, KZGSettings, G1, G2};
#[cfg(feature = "std")]
use parking_lot::Mutex;
use rust_kzg_blst::types::fft_settings::FsFFTSettings;
use rust_kzg_blst::types::fr::FsFr;
use rust_kzg_blst::types::g1::FsG1;
use rust_kzg_blst::types::g2::FsG2;
use rust_kzg_blst::types::kzg_settings::FsKZGSettings;
use rust_kzg_blst::types::poly::FsPoly;
#[cfg(not(feature = "std"))]
use spin::Mutex;
use subspace_core_primitives::pieces::{RecordCommitment, RecordWitness};
use subspace_core_primitives::segments::SegmentCommitment;
use subspace_core_primitives::{ChunkWitness, ScalarBytes};
use tracing::debug;

/// Embedded KZG settings as bytes, too big for `no_std` in most cases
/// Generated using following command (using current Ethereum KZG Summoning Ceremony):
/// ```bash
/// curl -s https://seq.ceremony.ethereum.org/info/current_state | jq '.transcripts[3].powersOfTau' | jq -r '.G1Powers + .G2Powers | map(.[2:]) | join("")' | xxd -r -p - eth-public-parameters.bin
/// ```
pub const EMBEDDED_KZG_SETTINGS_BYTES: &[u8] = include_bytes!("eth-public-parameters.bin");
/// Number of G1 powers stored in [`EMBEDDED_KZG_SETTINGS_BYTES`]
pub const NUM_G1_POWERS: usize = 32_768;
/// Number of G2 powers stored in [`EMBEDDED_KZG_SETTINGS_BYTES`]
pub const NUM_G2_POWERS: usize = 65;

// Symmetric function is present in tests
/// Function turns bytes into `FsKZGSettings`, it is up to the user to ensure that bytes make sense,
/// otherwise result can be very wrong (but will not panic).
fn bytes_to_kzg_settings(
    bytes: &[u8],
    num_g1_powers: usize,
    num_g2_powers: usize,
) -> Result<FsKZGSettings, String> {
    if bytes.len() != BYTES_PER_G1 * num_g1_powers + BYTES_PER_G2 * num_g2_powers {
        return Err("Invalid bytes length".to_string());
    }

    let (secret_g1_bytes, secret_g2_bytes) = bytes.split_at(BYTES_PER_G1 * num_g1_powers);
    let secret_g1 = secret_g1_bytes
        .chunks_exact(BYTES_PER_G1)
        .map(FsG1::from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let secret_g2 = secret_g2_bytes
        .chunks_exact(BYTES_PER_G2)
        .map(FsG2::from_bytes)
        .collect::<Result<Vec<_>, _>>()?;

    let fft_settings = FsFFTSettings::new(
        num_g1_powers
            .checked_sub(1)
            .expect("Checked to be not empty above; qed")
            .ilog2() as usize,
    )
    .expect("Scale is within allowed bounds; qed");

    // Below is the same as `FsKZGSettings::new(&s1, &s2, num_g1_powers, &fft_settings)`, but without
    // extra checks (parameters are static anyway) and without unnecessary allocations
    // TODO: Switch to `::new()` constructor once
    //  https://github.com/grandinetech/rust-kzg/issues/264 is resolved
    Ok(FsKZGSettings {
        fs: fft_settings,
        secret_g1,
        secret_g2,
        precomputation: None,
    })
}

/// Commitment to polynomial
#[derive(Debug, Clone, From)]
pub struct Polynomial(FsPoly);

impl Polynomial {
    /// Normalize polynomial by removing trailing zeroes
    pub fn normalize(&mut self) {
        let trailing_zeroes = self
            .0
            .coeffs
            .iter()
            .rev()
            .take_while(|coeff| coeff.is_zero())
            .count();
        self.0
            .coeffs
            .truncate((self.0.coeffs.len() - trailing_zeroes).max(1));
    }
}

/// Representation of a single BLS12-381 scalar value.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct Scalar(FsFr);

impl From<&[u8; ScalarBytes::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: &[u8; ScalarBytes::SAFE_BYTES]) -> Self {
        let mut bytes = [0u8; ScalarBytes::FULL_BYTES];
        bytes[1..].copy_from_slice(value);
        Self::try_from(bytes).expect("Safe bytes always fit into scalar and thus succeed; qed")
    }
}

impl From<[u8; ScalarBytes::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: [u8; ScalarBytes::SAFE_BYTES]) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&[u8; ScalarBytes::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: &[u8; ScalarBytes::FULL_BYTES]) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl TryFrom<[u8; ScalarBytes::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: [u8; ScalarBytes::FULL_BYTES]) -> Result<Self, Self::Error> {
        FsFr::from_bytes(&value).map(Scalar)
    }
}

impl TryFrom<&ScalarBytes> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: &ScalarBytes) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl TryFrom<ScalarBytes> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: ScalarBytes) -> Result<Self, Self::Error> {
        FsFr::from_bytes(value.as_ref()).map(Scalar)
    }
}

impl From<&Scalar> for [u8; ScalarBytes::FULL_BYTES] {
    #[inline]
    fn from(value: &Scalar) -> Self {
        value.0.to_bytes()
    }
}

impl From<Scalar> for [u8; ScalarBytes::FULL_BYTES] {
    #[inline]
    fn from(value: Scalar) -> Self {
        Self::from(&value)
    }
}

impl From<&Scalar> for ScalarBytes {
    #[inline]
    fn from(value: &Scalar) -> Self {
        ScalarBytes::from(value.0.to_bytes())
    }
}

impl From<Scalar> for ScalarBytes {
    #[inline]
    fn from(value: Scalar) -> Self {
        Self::from(&value)
    }
}

impl Scalar {
    /// Convert scalar into bytes
    pub fn to_bytes(&self) -> [u8; ScalarBytes::FULL_BYTES] {
        self.into()
    }

    /// Convert scalar into safe bytes, returns `None` if not possible to convert due to larger
    /// internal value
    pub fn try_to_safe_bytes(&self) -> Option<[u8; ScalarBytes::SAFE_BYTES]> {
        let bytes = self.to_bytes();
        if bytes[0] == 0 {
            Some(bytes[1..].try_into().expect("Correct length; qed"))
        } else {
            None
        }
    }

    /// Convenient conversion from slice of scalar to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[FsFr] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to scalar for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[FsFr]) -> &[Self] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional scalar to underlying representation for efficiency
    /// purposes.
    pub fn slice_option_to_repr(value: &[Option<Self>]) -> &[Option<FsFr>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional underlying representation to scalar for efficiency
    /// purposes.
    pub fn slice_option_from_repr(value: &[Option<FsFr>]) -> &[Option<Self>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of scalar to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [FsFr] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to scalar for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(value: &mut [FsFr]) -> &mut [Self] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of scalar to underlying representation for
    /// efficiency purposes.
    pub fn slice_option_mut_to_repr(value: &mut [Option<Self>]) -> &mut [Option<FsFr>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of underlying representation to scalar for
    /// efficiency purposes.
    pub fn slice_option_mut_from_repr(value: &mut [Option<FsFr>]) -> &mut [Option<Self>] {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from vector of scalar to underlying representation for efficiency
    /// purposes.
    pub fn vec_to_repr(value: Vec<Self>) -> Vec<FsFr> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut FsFr,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of underlying representation to scalar for efficiency
    /// purposes.
    pub fn vec_from_repr(value: Vec<FsFr>) -> Vec<Self> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
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

    /// Convenient conversion from vector of optional scalar to underlying representation for
    /// efficiency purposes.
    pub fn vec_option_to_repr(value: Vec<Option<Self>>) -> Vec<Option<FsFr>> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
        //  layout, original vector is not dropped
        unsafe {
            let mut value = mem::ManuallyDrop::new(value);
            Vec::from_raw_parts(
                value.as_mut_ptr() as *mut Option<FsFr>,
                value.len(),
                value.capacity(),
            )
        }
    }

    /// Convenient conversion from vector of optional underlying representation to scalar for
    /// efficiency purposes.
    pub fn vec_option_from_repr(value: Vec<Option<FsFr>>) -> Vec<Option<Self>> {
        // SAFETY: `Scalar` is `#[repr(transparent)]` and guaranteed to have the same memory
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

/// Commitment to polynomial
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, From, Into, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct Commitment(FsG1);

impl Commitment {
    /// Commitment size in bytes.
    const SIZE: usize = 48;

    /// Convert commitment to raw bytes
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    /// Try to deserialize commitment from raw bytes
    #[inline]
    pub fn try_from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, String> {
        Ok(Commitment(FsG1::from_bytes(bytes)?))
    }

    /// Convenient conversion from slice of commitment to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[FsG1] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to commitment for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[FsG1]) -> &[Self] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional commitment to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_option_to_repr(value: &[Option<Self>]) -> &[Option<FsG1>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of optional underlying representation to commitment for
    /// efficiency purposes.
    #[inline]
    pub fn slice_option_from_repr(value: &[Option<FsG1>]) -> &[Option<Self>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of commitment to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [FsG1] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to commitment for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(value: &mut [FsG1]) -> &mut [Self] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of commitment to underlying representation
    /// for efficiency purposes.
    #[inline]
    pub fn slice_option_mut_to_repr(value: &mut [Option<Self>]) -> &mut [Option<FsG1>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from optional mutable slice of underlying representation to commitment
    /// for efficiency purposes.
    #[inline]
    pub fn slice_option_mut_from_repr(value: &mut [Option<FsG1>]) -> &mut [Option<Self>] {
        // SAFETY: `Commitment` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from vector of commitment to underlying representation for efficiency
    /// purposes.
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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

impl From<Commitment> for RecordCommitment {
    #[inline]
    fn from(commitment: Commitment) -> Self {
        RecordCommitment::from(commitment.to_bytes())
    }
}

impl TryFrom<&RecordCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: &RecordCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(*commitment)
    }
}

impl TryFrom<RecordCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: RecordCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(&commitment)
    }
}

impl From<Commitment> for SegmentCommitment {
    #[inline]
    fn from(commitment: Commitment) -> Self {
        SegmentCommitment::from(commitment.to_bytes())
    }
}

impl TryFrom<&SegmentCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: &SegmentCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(*commitment)
    }
}

impl TryFrom<SegmentCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: SegmentCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(&commitment)
    }
}

impl From<Commitment> for [u8; Commitment::SIZE] {
    #[inline]
    fn from(commitment: Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl From<&Commitment> for [u8; Commitment::SIZE] {
    #[inline]
    fn from(commitment: &Commitment) -> Self {
        commitment.to_bytes()
    }
}

impl TryFrom<&[u8; Self::SIZE]> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; Self::SIZE]> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(bytes: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
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
        self.0.to_bytes()
    }

    /// Try to deserialize witness from raw bytes
    pub fn try_from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, String> {
        Ok(Witness(FsG1::from_bytes(bytes)?))
    }
}

impl From<Witness> for RecordWitness {
    #[inline]
    fn from(witness: Witness) -> Self {
        RecordWitness::from(witness.to_bytes())
    }
}

impl TryFrom<&RecordWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: &RecordWitness) -> Result<Self, Self::Error> {
        Witness::try_from(*witness)
    }
}

impl TryFrom<RecordWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: RecordWitness) -> Result<Self, Self::Error> {
        Witness::try_from(&witness)
    }
}

impl From<Witness> for ChunkWitness {
    #[inline]
    fn from(witness: Witness) -> Self {
        ChunkWitness::from(witness.to_bytes())
    }
}

impl TryFrom<&ChunkWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: &ChunkWitness) -> Result<Self, Self::Error> {
        Witness::try_from(*witness)
    }
}

impl TryFrom<ChunkWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: ChunkWitness) -> Result<Self, Self::Error> {
        Witness::try_from(&witness)
    }
}

impl From<Witness> for [u8; Witness::SIZE] {
    #[inline]
    fn from(witness: Witness) -> Self {
        witness.to_bytes()
    }
}

impl From<&Witness> for [u8; Witness::SIZE] {
    #[inline]
    fn from(witness: &Witness) -> Self {
        witness.to_bytes()
    }
}

impl TryFrom<&[u8; Self::SIZE]> for Witness {
    type Error = String;

    #[inline]
    fn try_from(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<[u8; Self::SIZE]> for Witness {
    type Error = String;

    #[inline]
    fn try_from(bytes: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::try_from(&bytes)
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
    /// Create new instance with embedded KZG settings.
    ///
    /// NOTE: Prefer cloning to instantiation since cloning is cheap and instantiation is not!
    #[allow(
        clippy::new_without_default,
        reason = "Caller really should read the function description"
    )]
    pub fn new() -> Self {
        let kzg_settings =
            bytes_to_kzg_settings(EMBEDDED_KZG_SETTINGS_BYTES, NUM_G1_POWERS, NUM_G2_POWERS)
                .expect("Static bytes are correct, there is a test for this; qed");

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
    pub fn create_witness(
        &self,
        polynomial: &Polynomial,
        num_values: usize,
        index: u32,
    ) -> Result<Witness, String> {
        let x = self
            .get_fft_settings(num_values)?
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
    fn get_fft_settings(&self, num_values: usize) -> Result<Arc<FsFFTSettings>, String> {
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
