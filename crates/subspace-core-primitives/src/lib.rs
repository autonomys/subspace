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

//! Core primitives for Subspace Network.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(feature = "std", warn(missing_debug_implementations))]
#![feature(
    array_chunks,
    const_option,
    const_trait_impl,
    const_try,
    new_zeroed_alloc,
    portable_simd,
    step_trait
)]

pub mod checksum;
pub mod crypto;
pub mod objects;
pub mod pieces;
pub mod segments;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::crypto::{blake3_hash, blake3_hash_list, blake3_hash_with_key, Scalar};
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use core::array::TryFromSliceError;
use core::fmt;
use core::num::{NonZeroU64, NonZeroU8};
use core::simd::Simd;
use core::str::FromStr;
use derive_more::{Add, AsMut, AsRef, Deref, DerefMut, Display, Div, From, Into, Mul, Rem, Sub};
use hex::FromHex;
use num_traits::{WrappingAdd, WrappingSub};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use pieces::{
    ChunkWitness, PieceIndex, PieceOffset, Record, RecordCommitment, RecordWitness, SBucket,
};
use scale_info::TypeInfo;
use segments::{HistorySize, SegmentCommitment, SegmentIndex};
use static_assertions::{const_assert, const_assert_eq};

// Refuse to compile on lower than 32-bit platforms
const_assert!(core::mem::size_of::<usize>() >= core::mem::size_of::<u32>());

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

/// Byte length of a randomness type.
pub const RANDOMNESS_LENGTH: usize = 32;

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

/// Type of randomness.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    From,
    Into,
    Deref,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Randomness(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; RANDOMNESS_LENGTH]);

impl AsRef<[u8]> for Randomness {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Randomness {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Randomness {
    /// Derive global slot challenge from global randomness.
    // TODO: Separate type for global challenge
    pub fn derive_global_challenge(&self, slot: SlotNumber) -> Blake3Hash {
        blake3_hash_list(&[&self.0, &slot.to_le_bytes()])
    }
}

/// Block number in Subspace network.
pub type BlockNumber = u32;

/// Block hash in Subspace network.
pub type BlockHash = [u8; 32];

/// Slot number in Subspace network.
pub type SlotNumber = u64;

// TODO: Add related methods to `SolutionRange`.
/// Type of solution range.
pub type SolutionRange = u64;

/// Computes the following:
/// ```text
/// MAX * slot_probability / chunks * s_buckets / sectors
/// ```
pub const fn pieces_to_solution_range(pieces: u64, slot_probability: (u64, u64)) -> SolutionRange {
    let solution_range = SolutionRange::MAX
        // Account for slot probability
        / slot_probability.1 * slot_probability.0
        // Now take probability of hitting occupied s-bucket in a piece into account
        / Record::NUM_CHUNKS as u64
        * Record::NUM_S_BUCKETS as u64;

    // Take number of pieces into account
    solution_range / pieces
}

/// Computes the following:
/// ```text
/// MAX * slot_probability / chunks * s_buckets / solution_range
/// ```
pub const fn solution_range_to_pieces(
    solution_range: SolutionRange,
    slot_probability: (u64, u64),
) -> u64 {
    let pieces = SolutionRange::MAX
        // Account for slot probability
        / slot_probability.1 * slot_probability.0
        // Now take probability of hitting occupied s-bucket in sector into account
        / Record::NUM_CHUNKS as u64
        * Record::NUM_S_BUCKETS as u64;

    // Take solution range into account
    pieces / solution_range
}

// Quick test to ensure functions above are the inverse of each other
const_assert!(solution_range_to_pieces(pieces_to_solution_range(1, (1, 6)), (1, 6)) == 1);
const_assert!(solution_range_to_pieces(pieces_to_solution_range(3, (1, 6)), (1, 6)) == 3);
const_assert!(solution_range_to_pieces(pieces_to_solution_range(5, (1, 6)), (1, 6)) == 5);

/// BlockWeight type for fork choice rules.
///
/// The closer solution's tag is to the target, the heavier it is.
pub type BlockWeight = u128;

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

/// A Ristretto Schnorr public key as bytes produced by `schnorrkel` crate.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Deref,
    From,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<PublicKey> for [u8; PublicKey::SIZE] {
    #[inline]
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Public key size in bytes
    pub const SIZE: usize = 32;

    /// Public key hash.
    pub fn hash(&self) -> Blake3Hash {
        blake3_hash(&self.0)
    }
}

/// A Ristretto Schnorr signature as bytes produced by `schnorrkel` crate.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, Deref, From,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RewardSignature(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl From<RewardSignature> for [u8; RewardSignature::SIZE] {
    #[inline]
    fn from(value: RewardSignature) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for RewardSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl RewardSignature {
    /// Reward signature size in bytes
    pub const SIZE: usize = 64;
}

/// Sector index in consensus
pub type SectorIndex = u16;

/// Farmer solution for slot challenge.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Solution<RewardAddress> {
    /// Public key of the farmer that created the solution
    pub public_key: PublicKey,
    /// Address for receiving block reward
    pub reward_address: RewardAddress,
    /// Index of the sector where solution was found
    pub sector_index: SectorIndex,
    /// Size of the blockchain history at time of sector creation
    pub history_size: HistorySize,
    /// Pieces offset within sector
    pub piece_offset: PieceOffset,
    /// Record commitment that can use used to verify that piece was included in blockchain history
    pub record_commitment: RecordCommitment,
    /// Witness for above record commitment
    pub record_witness: RecordWitness,
    /// Chunk at above offset
    pub chunk: Scalar,
    /// Witness for above chunk
    pub chunk_witness: ChunkWitness,
    /// Proof of space for piece offset
    pub proof_of_space: PosProof,
}

impl<RewardAddressA> Solution<RewardAddressA> {
    /// Transform solution with one reward address type into solution with another compatible
    /// reward address type.
    pub fn into_reward_address_format<T, RewardAddressB>(self) -> Solution<RewardAddressB>
    where
        RewardAddressA: Into<T>,
        T: Into<RewardAddressB>,
    {
        let Solution {
            public_key,
            reward_address,
            sector_index,
            history_size,
            piece_offset,
            record_commitment,
            record_witness,
            chunk,
            chunk_witness,
            proof_of_space,
        } = self;
        Solution {
            public_key,
            reward_address: Into::<T>::into(reward_address).into(),
            sector_index,
            history_size,
            piece_offset,
            record_commitment,
            record_witness,
            chunk,
            chunk_witness,
            proof_of_space,
        }
    }
}

impl<RewardAddress> Solution<RewardAddress> {
    /// Dummy solution for the genesis block
    pub fn genesis_solution(public_key: PublicKey, reward_address: RewardAddress) -> Self {
        Self {
            public_key,
            reward_address,
            sector_index: 0,
            history_size: HistorySize::from(SegmentIndex::ZERO),
            piece_offset: PieceOffset::default(),
            record_commitment: RecordCommitment::default(),
            record_witness: RecordWitness::default(),
            chunk: Scalar::default(),
            chunk_witness: ChunkWitness::default(),
            proof_of_space: PosProof::default(),
        }
    }
}

/// Bidirectional distance metric implemented on top of subtraction
#[inline(always)]
pub fn bidirectional_distance<T: WrappingSub + Ord>(a: &T, b: &T) -> T {
    let diff = a.wrapping_sub(b);
    let diff2 = b.wrapping_sub(a);
    // Find smaller diff between 2 directions.
    diff.min(diff2)
}

#[allow(clippy::assign_op_pattern, clippy::ptr_offset_with_cast)]
mod private_u256 {
    //! This module is needed to scope clippy allows
    use parity_scale_codec::{Decode, Encode};
    use scale_info::TypeInfo;

    uint::construct_uint! {
        #[derive(Encode, Decode, TypeInfo)]
        pub struct U256(4);
    }
}

/// 256-bit unsigned integer
#[derive(
    Debug,
    Display,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encode,
    Decode,
    TypeInfo,
)]
pub struct U256(private_u256::U256);

impl U256 {
    /// Zero (additive identity) of this type.
    #[inline]
    pub const fn zero() -> Self {
        Self(private_u256::U256::zero())
    }

    /// One (multiplicative identity) of this type.
    #[inline]
    pub fn one() -> Self {
        Self(private_u256::U256::one())
    }

    /// Create from big endian bytes
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(private_u256::U256::from_big_endian(&bytes))
    }

    /// Convert to big endian bytes
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_big_endian()
    }

    /// Create from little endian bytes
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(private_u256::U256::from_little_endian(&bytes))
    }

    /// Convert to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0.to_little_endian()
    }

    /// Adds two numbers, checking for overflow. If overflow happens, `None` is returned.
    pub fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).map(Self)
    }

    /// Subtracts two numbers, checking for underflow. If underflow happens, `None` is returned.
    pub fn checked_sub(&self, v: &Self) -> Option<Self> {
        self.0.checked_sub(v.0).map(Self)
    }

    /// Multiplies two numbers, checking for underflow or overflow. If underflow or overflow
    /// happens, `None` is returned.
    pub fn checked_mul(&self, v: &Self) -> Option<Self> {
        self.0.checked_mul(v.0).map(Self)
    }

    /// Divides two numbers, checking for underflow, overflow and division by zero. If any of that
    /// happens, `None` is returned.
    pub fn checked_div(&self, v: &Self) -> Option<Self> {
        self.0.checked_div(v.0).map(Self)
    }

    /// Saturating addition. Computes `self + other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_add(&self, v: &Self) -> Self {
        Self(self.0.saturating_add(v.0))
    }

    /// Saturating subtraction. Computes `self - other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_sub(&self, v: &Self) -> Self {
        Self(self.0.saturating_sub(v.0))
    }

    /// Saturating multiplication. Computes `self * other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_mul(&self, v: &Self) -> Self {
        Self(self.0.saturating_mul(v.0))
    }

    /// The middle of the piece distance field.
    /// The analogue of `0b1000_0000` for `u8`.
    pub const MIDDLE: Self = {
        // TODO: This assumes that numbers are stored little endian,
        //  should be replaced with just `Self::MAX / 2`, but it is not `const fn` in Rust yet.
        Self(private_u256::U256([
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX / 2,
        ]))
    };

    /// Maximum value.
    pub const MAX: Self = Self(private_u256::U256::MAX);
}

// Necessary for division derive
impl From<U256> for private_u256::U256 {
    #[inline]
    fn from(number: U256) -> Self {
        number.0
    }
}

impl WrappingAdd for U256 {
    #[inline]
    fn wrapping_add(&self, other: &Self) -> Self {
        Self(self.0.overflowing_add(other.0).0)
    }
}

impl WrappingSub for U256 {
    #[inline]
    fn wrapping_sub(&self, other: &Self) -> Self {
        Self(self.0.overflowing_sub(other.0).0)
    }
}

impl From<u8> for U256 {
    #[inline]
    fn from(number: u8) -> Self {
        Self(number.into())
    }
}

impl From<u16> for U256 {
    #[inline]
    fn from(number: u16) -> Self {
        Self(number.into())
    }
}

impl From<u32> for U256 {
    #[inline]
    fn from(number: u32) -> Self {
        Self(number.into())
    }
}

impl From<u64> for U256 {
    #[inline]
    fn from(number: u64) -> Self {
        Self(number.into())
    }
}

impl From<u128> for U256 {
    #[inline]
    fn from(number: u128) -> Self {
        Self(number.into())
    }
}

impl TryFrom<U256> for u8 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u16 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u32 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u64 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl Default for U256 {
    fn default() -> Self {
        Self::zero()
    }
}

/// Challenge used for a particular sector for particular slot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deref)]
pub struct SectorSlotChallenge(Blake3Hash);

impl SectorSlotChallenge {
    /// Index of s-bucket within sector to be audited
    #[inline]
    pub fn s_bucket_audit_index(&self) -> SBucket {
        // As long as number of s-buckets is 2^16, we can pick first two bytes instead of actually
        // calculating `U256::from_le_bytes(self.0) % Record::NUM_S_BUCKETS)`
        const_assert_eq!(Record::NUM_S_BUCKETS, 1 << u16::BITS as usize);
        SBucket::from(u16::from_le_bytes([self.0[0], self.0[1]]))
    }
}

/// Data structure representing sector ID in farmer's plot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SectorId(#[cfg_attr(feature = "serde", serde(with = "hex"))] Blake3Hash);

impl AsRef<[u8]> for SectorId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SectorId {
    /// Create new sector ID by deriving it from public key and sector index
    pub fn new(public_key_hash: Blake3Hash, sector_index: SectorIndex) -> Self {
        Self(blake3_hash_with_key(
            &public_key_hash,
            &sector_index.to_le_bytes(),
        ))
    }

    /// Derive piece index that should be stored in sector at `piece_offset` for specified size of
    /// blockchain history
    pub fn derive_piece_index(
        &self,
        piece_offset: PieceOffset,
        history_size: HistorySize,
        max_pieces_in_sector: u16,
        recent_segments: HistorySize,
        recent_history_fraction: (HistorySize, HistorySize),
    ) -> PieceIndex {
        let recent_segments_in_pieces = recent_segments.in_pieces().get();
        // Recent history must be at most `recent_history_fraction` of all history to use separate
        // policy for recent pieces
        let min_history_size_in_pieces = recent_segments_in_pieces
            * recent_history_fraction.1.in_pieces().get()
            / recent_history_fraction.0.in_pieces().get();
        let input_hash = {
            let piece_offset_bytes = piece_offset.to_bytes();
            let mut key = [0; 32];
            key[..piece_offset_bytes.len()].copy_from_slice(&piece_offset_bytes);
            U256::from_le_bytes(*blake3_hash_with_key(&key, self.as_ref()))
        };
        let history_size_in_pieces = history_size.in_pieces().get();
        let num_interleaved_pieces = 1.max(
            u64::from(max_pieces_in_sector) * recent_history_fraction.0.in_pieces().get()
                / recent_history_fraction.1.in_pieces().get()
                * 2,
        );

        let piece_index = if history_size_in_pieces > min_history_size_in_pieces
            && u64::from(piece_offset) < num_interleaved_pieces
            && u16::from(piece_offset) % 2 == 1
        {
            // For odd piece offsets at the beginning of the sector pick pieces at random from
            // recent history only
            input_hash % U256::from(recent_segments_in_pieces)
                + U256::from(history_size_in_pieces - recent_segments_in_pieces)
        } else {
            input_hash % U256::from(history_size_in_pieces)
        };

        PieceIndex::from(u64::try_from(piece_index).expect(
            "Remainder of division by PieceIndex is guaranteed to fit into PieceIndex; qed",
        ))
    }

    /// Derive sector slot challenge for this sector from provided global challenge
    pub fn derive_sector_slot_challenge(
        &self,
        global_challenge: &Blake3Hash,
    ) -> SectorSlotChallenge {
        let sector_slot_challenge = Simd::from(*self.0) ^ Simd::from(**global_challenge);
        SectorSlotChallenge(sector_slot_challenge.to_array().into())
    }

    /// Derive evaluation seed
    pub fn derive_evaluation_seed(
        &self,
        piece_offset: PieceOffset,
        history_size: HistorySize,
    ) -> PosSeed {
        let evaluation_seed = blake3_hash_list(&[
            self.as_ref(),
            &piece_offset.to_bytes(),
            &history_size.get().to_le_bytes(),
        ]);

        PosSeed::from(*evaluation_seed)
    }

    /// Derive history size when sector created at `history_size` expires.
    ///
    /// Returns `None` on overflow.
    pub fn derive_expiration_history_size(
        &self,
        history_size: HistorySize,
        sector_expiration_check_segment_commitment: &SegmentCommitment,
        min_sector_lifetime: HistorySize,
    ) -> Option<HistorySize> {
        let sector_expiration_check_history_size =
            history_size.sector_expiration_check(min_sector_lifetime)?;

        let input_hash = U256::from_le_bytes(*blake3_hash_list(&[
            self.as_ref(),
            sector_expiration_check_segment_commitment.as_ref(),
        ]));

        let last_possible_expiration =
            min_sector_lifetime.checked_add(history_size.get().checked_mul(4u64)?)?;
        let expires_in = input_hash
            % U256::from(
                last_possible_expiration
                    .get()
                    .checked_sub(sector_expiration_check_history_size.get())?,
            );
        let expires_in = u64::try_from(expires_in).expect("Number modulo u64 fits into u64; qed");

        let expiration_history_size = sector_expiration_check_history_size.get() + expires_in;
        let expiration_history_size = NonZeroU64::try_from(expiration_history_size).expect(
            "History size is not zero, so result is not zero even if expires immediately; qed",
        );
        Some(HistorySize::from(expiration_history_size))
    }
}
