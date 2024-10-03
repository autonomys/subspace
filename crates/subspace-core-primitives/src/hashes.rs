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

//! Hashes-related data structures and functions.

use crate::ScalarBytes;
use core::array::TryFromSliceError;
use core::fmt;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From};
use hex::FromHex;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// BLAKE3 hash output transparent wrapper
#[derive(
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    From,
    AsRef,
    AsMut,
    Deref,
    DerefMut,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Blake3Hash(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Blake3Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Blake3Hash {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl FromHex for Blake3Hash {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let data = hex::decode(hex)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;

        Ok(Self(data))
    }
}

impl From<&[u8; Self::SIZE]> for Blake3Hash {
    #[inline]
    fn from(value: &[u8; Self::SIZE]) -> Self {
        Self(*value)
    }
}

impl TryFrom<&[u8]> for Blake3Hash {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<Blake3Hash> for [u8; Blake3Hash::SIZE] {
    #[inline]
    fn from(value: Blake3Hash) -> Self {
        value.0
    }
}

impl Blake3Hash {
    /// Size of BLAKE3 hash output (in bytes).
    pub const SIZE: usize = 32;
}

/// BLAKE3 hashing of a single value.
pub fn blake3_hash(data: &[u8]) -> Blake3Hash {
    blake3::hash(data).as_bytes().into()
}

/// BLAKE3 hashing of a single value in parallel (only useful for large values well above 128kiB).
#[cfg(feature = "parallel")]
#[inline]
pub fn blake3_hash_parallel(data: &[u8]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    state.update_rayon(data);
    state.finalize().as_bytes().into()
}

/// BLAKE3 keyed hashing of a single value.
#[inline]
pub fn blake3_hash_with_key(key: &[u8; 32], data: &[u8]) -> Blake3Hash {
    blake3::keyed_hash(key, data).as_bytes().into()
}

/// BLAKE3 keyed hashing of a single value.
#[inline]
pub fn blake3_hash_list_with_key(key: &[u8; 32], data: &[&[u8]]) -> Blake3Hash {
    let mut state = blake3::Hasher::new_keyed(key);
    for d in data {
        state.update(d);
    }
    state.finalize().as_bytes().into()
}

/// BLAKE3 hashing of a list of values.
#[inline]
pub fn blake3_hash_list(data: &[&[u8]]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    for d in data {
        state.update(d);
    }
    state.finalize().as_bytes().into()
}

/// BLAKE3 hashing of a single value truncated to 254 bits as Scalar for usage with KZG.
#[inline]
pub fn blake3_254_hash_to_scalar(data: &[u8]) -> ScalarBytes {
    let mut hash = blake3_hash(data);
    // Erase first 2 bits to effectively truncate the hash (number is interpreted as big-endian)
    hash[0] &= 0b00111111;
    ScalarBytes(*hash)
}
