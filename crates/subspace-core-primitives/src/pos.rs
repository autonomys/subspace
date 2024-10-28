//! Proof of space-related data structures.

#[cfg(feature = "serde")]
mod serde;

use crate::hashes::{blake3_hash, Blake3Hash};
use derive_more::{Deref, DerefMut, From, Into};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Proof of space seed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, From, Into)]
pub struct PosSeed([u8; PosSeed::SIZE]);

impl PosSeed {
    /// Size of proof of space seed in bytes.
    pub const SIZE: usize = 32;
}

/// Proof of space proof bytes.
#[derive(
    Debug,
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
)]
pub struct PosProof([u8; PosProof::SIZE]);

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
