//! Proof of space-related data structures.

use crate::hashes::{Blake3Hash, blake3_hash};
use core::fmt;
use derive_more::{Deref, DerefMut, From, Into};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// Proof of space seed.
#[derive(Copy, Clone, Eq, PartialEq, Deref, From, Into)]
pub struct PosSeed([u8; PosSeed::SIZE]);

impl fmt::Debug for PosSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl PosSeed {
    /// Size of proof of space seed in bytes.
    pub const SIZE: usize = 32;
}

/// Proof of space proof bytes.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Deref,
    DerefMut,
    From,
    Into,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    DecodeWithMemTracking,
)]
pub struct PosProof([u8; PosProof::SIZE]);

impl fmt::Debug for PosProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct PosProofBinary(#[serde(with = "BigArray")] [u8; PosProof::SIZE]);

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct PosProofHex(#[serde(with = "hex")] [u8; PosProof::SIZE]);

#[cfg(feature = "serde")]
impl Serialize for PosProof {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            PosProofHex(self.0).serialize(serializer)
        } else {
            PosProofBinary(self.0).serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PosProof {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(if deserializer.is_human_readable() {
            PosProofHex::deserialize(deserializer)?.0
        } else {
            PosProofBinary::deserialize(deserializer)?.0
        }))
    }
}

impl Default for PosProof {
    #[inline]
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl PosProof {
    /// Constant K used for proof of space
    pub const K: u8 = 20;
    /// Size of proof of space proof in bytes.
    pub const SIZE: usize = Self::K as usize * 8;

    /// Proof hash.
    pub fn hash(&self) -> Blake3Hash {
        blake3_hash(&self.0)
    }
}
