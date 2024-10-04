//! Proof of space-related data structures.

#[cfg(feature = "serde")]
mod serde;

use crate::hashes::{blake3_hash, Blake3Hash};
use derive_more::{Deref, DerefMut, From};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Proof of space seed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PosSeed([u8; Self::SIZE]);

impl From<[u8; PosSeed::SIZE]> for PosSeed {
    #[inline]
    fn from(value: [u8; Self::SIZE]) -> Self {
        Self(value)
    }
}

impl From<PosSeed> for [u8; PosSeed::SIZE] {
    #[inline]
    fn from(value: PosSeed) -> Self {
        value.0
    }
}

impl PosSeed {
    /// Size of proof of space seed in bytes.
    pub const SIZE: usize = 32;
}

/// Proof of space proof bytes.
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
pub struct PosProof([u8; Self::SIZE]);

impl From<[u8; PosProof::SIZE]> for PosProof {
    #[inline]
    fn from(value: [u8; Self::SIZE]) -> Self {
        Self(value)
    }
}

impl From<PosProof> for [u8; PosProof::SIZE] {
    #[inline]
    fn from(value: PosProof) -> Self {
        value.0
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
