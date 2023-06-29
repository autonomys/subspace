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
    new_uninit,
    portable_simd,
    slice_flatten,
    step_trait
)]

pub mod crypto;
pub mod objects;
mod pieces;
mod segments;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

extern crate alloc;

use crate::crypto::kzg::{Commitment, Witness};
use crate::crypto::{blake2b_256_hash, blake2b_256_hash_list, blake2b_256_hash_with_key, Scalar};
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use core::convert::AsRef;
use core::fmt;
use core::simd::Simd;
use derive_more::{Add, Deref, DerefMut, Display, Div, From, Into, Mul, Rem, Sub};
use num_traits::{WrappingAdd, WrappingSub};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
pub use pieces::{
    FlatPieces, Piece, PieceArray, PieceIndex, PieceIndexHash, PieceOffset, RawRecord, Record,
    RecordCommitment, RecordWitness, SBucket,
};
use scale_info::TypeInfo;
pub use segments::{ArchivedHistorySegment, HistorySize, RecordedHistorySegment, SegmentIndex};
use uint::static_assertions::const_assert;

// Refuse to compile on lower than 32-bit platforms
const_assert!(core::mem::size_of::<usize>() >= core::mem::size_of::<u32>());

/// Size of BLAKE2b-256 hash output (in bytes).
pub const BLAKE2B_256_HASH_SIZE: usize = 32;

/// Byte length of a randomness type.
pub const RANDOMNESS_LENGTH: usize = 32;

/// BLAKE2b-256 hash output
pub type Blake2b256Hash = [u8; BLAKE2B_256_HASH_SIZE];

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
pub struct Randomness(
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; RANDOMNESS_LENGTH],
);

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
    pub fn derive_global_challenge(&self, slot: SlotNumber) -> Blake2b256Hash {
        crypto::blake2b_256_hash_list(&[&self.0, &slot.to_le_bytes()])
    }
}

/// Block number in Subspace network.
pub type BlockNumber = u32;

/// Slot number in Subspace network.
pub type SlotNumber = u64;

/// Type of solution range.
pub type SolutionRange = u64;

/// BlockWeight type for fork choice rules.
///
/// The closer solution's tag is to the target, the heavier it is.
pub type BlockWeight = u128;

// TODO: New type
/// Segment commitment type.
pub type SegmentCommitment = Commitment;

/// Length of public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Length of signature in bytes
pub const REWARD_SIGNATURE_LENGTH: usize = 64;

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

/// Proof of space quality.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PosQualityBytes([u8; Self::SIZE]);

impl From<[u8; PosQualityBytes::SIZE]> for PosQualityBytes {
    #[inline]
    fn from(value: [u8; Self::SIZE]) -> Self {
        Self(value)
    }
}

impl From<PosQualityBytes> for [u8; PosQualityBytes::SIZE] {
    #[inline]
    fn from(value: PosQualityBytes) -> Self {
        value.0
    }
}

impl PosQualityBytes {
    /// Size of proof of space quality in bytes.
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
    /// Size of proof of space proof in bytes.
    pub const SIZE: usize = 17 * 8;
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
    Into,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey(
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; PUBLIC_KEY_LENGTH],
);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Public key hash.
    pub fn hash(&self) -> Blake2b256Hash {
        blake2b_256_hash(&self.0)
    }
}

/// A Ristretto Schnorr signature as bytes produced by `schnorrkel` crate.
#[derive(
    Debug,
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
    Into,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RewardSignature(
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; REWARD_SIGNATURE_LENGTH],
);

impl AsRef<[u8]> for RewardSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Progress of an archived block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ArchivedBlockProgress {
    /// The block has been fully archived.
    Complete,

    /// Number of partially archived bytes of a block.
    Partial(u32),
}

impl Default for ArchivedBlockProgress {
    /// We assume a block can always fit into the segment initially, but it can definitely possible
    /// to be transitioned into the partial state after some overflow checkings.
    #[inline]
    fn default() -> Self {
        Self::Complete
    }
}

impl ArchivedBlockProgress {
    /// Return the number of partially archived bytes if the progress is not complete.
    pub fn partial(&self) -> Option<u32> {
        match self {
            Self::Complete => None,
            Self::Partial(number) => Some(*number),
        }
    }

    /// Sets new number of partially archived bytes.
    pub fn set_partial(&mut self, new_partial: u32) {
        *self = Self::Partial(new_partial);
    }
}

/// Last archived block
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct LastArchivedBlock {
    /// Block number
    pub number: BlockNumber,
    /// Progress of an archived block.
    pub archived_progress: ArchivedBlockProgress,
}

impl LastArchivedBlock {
    /// Returns the number of partially archived bytes for a block.
    pub fn partial_archived(&self) -> Option<u32> {
        self.archived_progress.partial()
    }

    /// Sets new number of partially archived bytes.
    pub fn set_partial_archived(&mut self, new_partial: BlockNumber) {
        self.archived_progress.set_partial(new_partial);
    }

    /// Sets the archived state of this block to [`ArchivedBlockProgress::Complete`].
    pub fn set_complete(&mut self) {
        self.archived_progress = ArchivedBlockProgress::Complete;
    }
}

/// Segment header for a specific segment.
///
/// Each segment will have corresponding [`SegmentHeader`] included as the first item in the next
/// segment. Each `SegmentHeader` includes hash of the previous one and all together form a chain of
/// segment headers that is used for quick and efficient verification that some [`Piece`]
/// corresponds to the actual archival history of the blockchain.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum SegmentHeader {
    /// V0 of the segment header data structure
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Segment index
        segment_index: SegmentIndex,
        /// Root of commitments of all records in a segment.
        segment_commitment: SegmentCommitment,
        /// Hash of the segment header of the previous segment
        prev_segment_header_hash: Blake2b256Hash,
        /// Last archived block
        last_archived_block: LastArchivedBlock,
    },
}

impl SegmentHeader {
    /// Hash of the whole segment header
    pub fn hash(&self) -> Blake2b256Hash {
        blake2b_256_hash(&self.encode())
    }

    /// Segment index
    pub fn segment_index(&self) -> SegmentIndex {
        match self {
            Self::V0 { segment_index, .. } => *segment_index,
        }
    }

    /// Merkle root of the records in a segment.
    pub fn segment_commitment(&self) -> SegmentCommitment {
        match self {
            Self::V0 {
                segment_commitment, ..
            } => *segment_commitment,
        }
    }

    /// Hash of the segment header of the previous segment
    pub fn prev_segment_header_hash(&self) -> Blake2b256Hash {
        match self {
            Self::V0 {
                prev_segment_header_hash,
                ..
            } => *prev_segment_header_hash,
        }
    }

    /// Last archived block
    pub fn last_archived_block(&self) -> LastArchivedBlock {
        match self {
            Self::V0 {
                last_archived_block,
                ..
            } => *last_archived_block,
        }
    }
}

/// Sector index in consensus
pub type SectorIndex = u64;

// TODO: Versioned solution enum
/// Farmer solution for slot challenge.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Solution<PublicKey, RewardAddress> {
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
    pub record_commitment: Commitment,
    /// Witness for above record commitment
    pub record_witness: Witness,
    /// Chunk at above offset
    pub chunk: Scalar,
    /// Witness for above chunk
    pub chunk_witness: Witness,
    /// Audit chunk offset within above chunk
    pub audit_chunk_offset: u8,
    /// Proof of space for piece offset
    pub proof_of_space: PosProof,
}

impl<PublicKey, RewardAddressA> Solution<PublicKey, RewardAddressA> {
    /// Transform solution with one reward address type into solution with another compatible
    /// reward address type.
    pub fn into_reward_address_format<T, RewardAddressB>(
        self,
    ) -> Solution<PublicKey, RewardAddressB>
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
            audit_chunk_offset,
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
            audit_chunk_offset,
            proof_of_space,
        }
    }
}

impl<PublicKey, RewardAddress> Solution<PublicKey, RewardAddress> {
    /// Dummy solution for the genesis block
    pub fn genesis_solution(public_key: PublicKey, reward_address: RewardAddress) -> Self {
        Self {
            public_key,
            reward_address,
            sector_index: 0,
            history_size: HistorySize::from(SegmentIndex::ZERO),
            piece_offset: PieceOffset::default(),
            record_commitment: Commitment::default(),
            record_witness: Witness::default(),
            chunk: Scalar::default(),
            chunk_witness: Witness::default(),
            audit_chunk_offset: 0,
            proof_of_space: PosProof::default(),
        }
    }
}

/// Bidirectional distance metric implemented on top of subtraction
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
        let mut arr = [0u8; 32];
        self.0.to_big_endian(&mut arr);
        arr
    }

    /// Create from little endian bytes
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(private_u256::U256::from_little_endian(&bytes))
    }

    /// Convert to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        self.0.to_little_endian(&mut arr);
        arr
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

impl From<PieceIndexHash> for U256 {
    #[inline]
    fn from(hash: PieceIndexHash) -> Self {
        Self(private_u256::U256::from_big_endian(hash.as_ref()))
    }
}

impl From<U256> for PieceIndexHash {
    #[inline]
    fn from(number: U256) -> Self {
        Self::from(number.to_be_bytes())
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
pub struct SectorSlotChallenge(Blake2b256Hash);

impl SectorSlotChallenge {
    /// Index of s-bucket within sector to be audited
    #[inline]
    pub fn s_bucket_audit_index(&self) -> SBucket {
        SBucket::from(
            u16::try_from(U256::from_le_bytes(self.0) % U256::from(Record::NUM_S_BUCKETS as u32))
                .expect(
                    "Remainder of division by Record::NUM_S_BUCKETS is statically guaranteed \
                    to fit into SBucket; qed",
                ),
        )
    }
}

/// Data structure representing sector ID in farmer's plot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SectorId(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] Blake2b256Hash);

impl AsRef<[u8]> for SectorId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SectorId {
    /// Create new sector ID by deriving it from public key and sector index
    pub fn new(mut public_key_hash: Blake2b256Hash, sector_index: SectorIndex) -> Self {
        public_key_hash
            .iter_mut()
            .zip(&sector_index.to_le_bytes())
            .for_each(|(a, b)| {
                *a ^= *b;
            });
        Self(public_key_hash)
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
        let input_hash =
            U256::from_le_bytes(blake2b_256_hash_with_key(&piece_offset.to_bytes(), &self.0));
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
        global_challenge: &Blake2b256Hash,
    ) -> SectorSlotChallenge {
        let sector_slot_challenge = Simd::from(self.0) ^ Simd::from(*global_challenge);
        SectorSlotChallenge(sector_slot_challenge.to_array())
    }

    /// Derive evaluation seed
    pub fn evaluation_seed(&self, piece_offset: PieceOffset, history_size: HistorySize) -> PosSeed {
        let evaluation_seed = blake2b_256_hash_list(&[
            &self.0,
            &piece_offset.to_bytes(),
            &history_size.get().to_le_bytes(),
        ]);

        PosSeed::from(evaluation_seed)
    }
}
