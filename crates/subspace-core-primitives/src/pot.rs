//! Proof of time-related data structures.

use crate::crypto::{blake3_hash, blake3_hash_list};
use crate::{Blake3Hash, Randomness};
use core::fmt;
use core::num::NonZeroU8;
use core::str::FromStr;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Proof of time key(input to the encryption).
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
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
pub struct PotKey(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Display for PotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for PotKey {
    type Err = hex::FromHexError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut key = Self::default();
        hex::decode_to_slice(s, key.as_mut())?;

        Ok(key)
    }
}

impl PotKey {
    /// Size of proof of time key in bytes
    pub const SIZE: usize = 16;
}

/// Proof of time seed
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
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
pub struct PotSeed(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Display for PotSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl PotSeed {
    /// Size of proof of time seed in bytes
    pub const SIZE: usize = 16;

    /// Derive initial PoT seed from genesis block hash
    #[inline]
    pub fn from_genesis(genesis_block_hash: &[u8], external_entropy: &[u8]) -> Self {
        let hash = blake3_hash_list(&[genesis_block_hash, external_entropy]);
        let mut seed = Self::default();
        seed.copy_from_slice(&hash[..Self::SIZE]);
        seed
    }

    /// Derive key from proof of time seed
    #[inline]
    pub fn key(&self) -> PotKey {
        let mut key = PotKey::default();
        key.copy_from_slice(&blake3_hash(&self.0)[..Self::SIZE]);
        key
    }
}

/// Proof of time output, can be intermediate checkpoint or final slot output
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
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
pub struct PotOutput(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Display for PotOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl PotOutput {
    /// Size of proof of time proof in bytes
    pub const SIZE: usize = 16;

    /// Derives the global randomness from the output
    #[inline]
    pub fn derive_global_randomness(&self) -> Randomness {
        Randomness::from(*blake3_hash(&self.0))
    }

    /// Derive seed from proof of time in case entropy injection is not needed
    #[inline]
    pub fn seed(&self) -> PotSeed {
        PotSeed(self.0)
    }

    /// Derive seed from proof of time with entropy injection
    #[inline]
    pub fn seed_with_entropy(&self, entropy: &Blake3Hash) -> PotSeed {
        let hash = blake3_hash_list(&[entropy.as_ref(), &self.0]);
        let mut seed = PotSeed::default();
        seed.copy_from_slice(&hash[..Self::SIZE]);
        seed
    }
}

/// Proof of time checkpoints, result of proving
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Deref,
    DerefMut,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
pub struct PotCheckpoints([PotOutput; Self::NUM_CHECKPOINTS.get() as usize]);

impl PotCheckpoints {
    /// Number of PoT checkpoints produced (used to optimize verification)
    pub const NUM_CHECKPOINTS: NonZeroU8 = NonZeroU8::new(8).expect("Not zero; qed");

    /// Get proof of time output out of checkpoints (last checkpoint)
    #[inline]
    pub fn output(&self) -> PotOutput {
        self.0[Self::NUM_CHECKPOINTS.get() as usize - 1]
    }
}
