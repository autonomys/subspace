// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Various cryptographic utilities used across Subspace Network.

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod kzg;

use crate::Blake3Hash;
#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};
use parity_scale_codec::{Decode, Encode, EncodeLike, Input, MaxEncodedLen};
use rust_kzg_blst::types::fr::FsFr;
use scale_info::{Type, TypeInfo};

/// BLAKE3 hashing of a single value.
pub fn blake3_hash(data: &[u8]) -> Blake3Hash {
    *blake3::hash(data).as_bytes()
}

/// BLAKE3 hashing of a single value in parallel (only useful for large values well above 128kiB).
#[cfg(feature = "parallel")]
pub fn blake3_hash_parallel(data: &[u8]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    state.update_rayon(data);
    *state.finalize().as_bytes()
}

/// BLAKE3 keyed hashing of a single value.
pub fn blake3_hash_with_key(key: &[u8; 32], data: &[u8]) -> Blake3Hash {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// BLAKE3 hashing of a list of values.
pub fn blake3_hash_list(data: &[&[u8]]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    for d in data {
        state.update(d);
    }
    *state.finalize().as_bytes()
}

/// BLAKE3 hashing of a single value truncated to 254 bits as Scalar for usage with KZG.
pub fn blake3_254_hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hash = blake3_hash(data);
    // Erase last 2 bits to effectively truncate the hash (number is interpreted as little-endian)
    hash[31] &= 0b00111111;
    Scalar::try_from(hash)
        .expect("Last bit erased, thus hash is guaranteed to fit into scalar; qed")
}

/// Representation of a single BLS12-381 scalar value.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, From, Into, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct Scalar(FsFr);

impl Hash for Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl PartialOrd<Self> for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Encode for Scalar {
    fn size_hint(&self) -> usize {
        Self::FULL_BYTES
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        Self::FULL_BYTES
    }
}

impl EncodeLike for Scalar {}

impl Decode for Scalar {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        Self::try_from(&<[u8; Self::FULL_BYTES]>::decode(input)?).map_err(|error_code| {
            parity_scale_codec::Error::from("Failed to create scalar from bytes")
                .chain(format!("Error code: {error_code}"))
        })
    }

    #[inline]
    fn encoded_fixed_size() -> Option<usize> {
        Some(Self::FULL_BYTES)
    }
}

impl TypeInfo for Scalar {
    type Identity = Self;

    fn type_info() -> Type {
        Type::builder()
            .path(scale_info::Path::new(stringify!(Scalar), module_path!()))
            .docs(&["BLS12-381 scalar"])
            .composite(scale_info::build::Fields::named().field(|f| {
                f.ty::<[u8; Self::FULL_BYTES]>()
                    .name(stringify!(inner))
                    .type_name("FsFr")
            }))
    }
}

impl MaxEncodedLen for Scalar {
    #[inline]
    fn max_encoded_len() -> usize {
        Self::FULL_BYTES
    }
}

#[cfg(feature = "serde")]
mod scalar_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // Custom wrapper so we don't have to write serialization/deserialization code manually
    #[derive(Serialize, Deserialize)]
    struct Scalar(#[serde(with = "hex")] pub(super) [u8; super::Scalar::FULL_BYTES]);

    impl Serialize for super::Scalar {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Scalar(self.to_bytes()).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for super::Scalar {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let Scalar(bytes) = Scalar::deserialize(deserializer)?;
            Self::try_from(bytes).map_err(D::Error::custom)
        }
    }
}

impl From<&[u8; Self::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: &[u8; Self::SAFE_BYTES]) -> Self {
        let mut bytes = [0u8; Self::FULL_BYTES];
        bytes[..Self::SAFE_BYTES].copy_from_slice(value);
        Self::try_from(bytes).expect("Safe bytes always fit into scalar and thus succeed; qed")
    }
}

impl From<[u8; Self::SAFE_BYTES]> for Scalar {
    #[inline]
    fn from(value: [u8; Self::SAFE_BYTES]) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&[u8; Self::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: &[u8; Self::FULL_BYTES]) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl TryFrom<[u8; Self::FULL_BYTES]> for Scalar {
    type Error = String;

    #[inline]
    fn try_from(value: [u8; Self::FULL_BYTES]) -> Result<Self, Self::Error> {
        // TODO: The whole method should have been just the following line, but upstream `rust-kzg`
        //  switched to big-endian and we have to maintain little-endian version for now
        // FsFr::from_bytes(&value).map(Scalar)
        let mut bls_scalar = blst::blst_scalar::default();
        let mut fr = blst::blst_fr::default();
        unsafe {
            blst::blst_scalar_from_lendian(&mut bls_scalar, value.as_ptr());
            if !blst::blst_scalar_fr_check(&bls_scalar) {
                return Err("Invalid scalar".to_string());
            }
            blst::blst_fr_from_scalar(&mut fr, &bls_scalar);
        }
        Ok(Self(FsFr(fr)))
    }
}

impl From<&Scalar> for [u8; Scalar::FULL_BYTES] {
    #[inline]
    fn from(value: &Scalar) -> Self {
        // TODO: The whole method should have been just the following line, but upstream `rust-kzg`
        //  switched to big-endian and we have to maintain little-endian version for now
        // value.0.to_bytes()
        let mut scalar = blst::blst_scalar::default();
        let mut bytes = [0u8; 32];
        unsafe {
            blst::blst_scalar_from_fr(&mut scalar, &value.0 .0);
            blst::blst_lendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }

        bytes
    }
}

impl From<Scalar> for [u8; Scalar::FULL_BYTES] {
    #[inline]
    fn from(value: Scalar) -> Self {
        Self::from(&value)
    }
}

impl Scalar {
    /// How many full bytes can be stored in BLS12-381 scalar (for instance before encoding). It is
    /// actually 254 bits, but bits are mut harder to work with and likely not worth it.
    ///
    /// NOTE: After encoding more bytes can be used, so don't rely on this as the max number of
    /// bytes stored within at all times!
    pub const SAFE_BYTES: usize = 31;
    /// How many bytes Scalar contains physically, use [`Self::SAFE_BYTES`] for the amount of data
    /// that you can put into it safely (for instance before encoding).
    pub const FULL_BYTES: usize = 32;

    /// Convert scalar into bytes
    pub fn to_bytes(&self) -> [u8; Scalar::FULL_BYTES] {
        self.into()
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
