//! Hashes-related data structures and functions.

use crate::ScalarBytes;
use core::array::TryFromSliceError;
use core::fmt;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

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
    Into,
    AsRef,
    AsMut,
    Deref,
    DerefMut,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
pub struct Blake3Hash([u8; Blake3Hash::SIZE]);

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Blake3HashBinary([u8; Blake3Hash::SIZE]);

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Blake3HashHex(#[serde(with = "hex")] [u8; Blake3Hash::SIZE]);

#[cfg(feature = "serde")]
impl Serialize for Blake3Hash {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            Blake3HashHex(self.0).serialize(serializer)
        } else {
            Blake3HashBinary(self.0).serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Blake3Hash {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(if deserializer.is_human_readable() {
            Blake3HashHex::deserialize(deserializer)?.0
        } else {
            Blake3HashBinary::deserialize(deserializer)?.0
        }))
    }
}

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

/// BLAKE3 keyed hashing of a list of values.
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
