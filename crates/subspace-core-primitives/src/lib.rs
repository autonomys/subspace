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

pub mod crypto;
pub mod objects;
mod pieces;
pub mod sector_codec;
#[cfg(test)]
mod tests;

extern crate alloc;

use crate::crypto::kzg::{Commitment, Witness};
use crate::crypto::{blake2b_256_hash, blake2b_256_hash_with_key};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use core::convert::AsRef;
use core::fmt;
use core::num::NonZeroU64;
use derive_more::{Add, Deref, Display, Div, From, Into, Mul, Rem, Sub};
use num_traits::{WrappingAdd, WrappingSub};
use parity_scale_codec::{Decode, Encode, EncodeLike, Input};
pub use pieces::{
    FlatPieces, Piece, PieceRef, PieceRefMut, RecordRef, RecordRefMut, WitnessRef, WitnessRefMut,
    PIECE_SIZE, RECORD_SIZE, WITNESS_SIZE,
};
use scale_info::{Type, TypeInfo};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use uint::static_assertions::const_assert;

// Refuse to compile on lower than 32-bit platforms
const_assert!(core::mem::size_of::<usize>() >= core::mem::size_of::<u32>());

/// Size of BLAKE2b-256 hash output (in bytes).
pub const BLAKE2B_256_HASH_SIZE: usize = 32;

/// Size of one plotted sector.
///
/// If we imagine sector as a grid containing pieces as columns, number of scalar in column must be
/// equal to number of columns, but we need to account for the fact that [`Scalar::SAFE_BYTES`] will
/// be expanded to [`Scalar::FULL_BYTES`] (padded with zero byte) before encoding to ensure encoding
/// and decoding operate on the same amount of data.
pub const PLOT_SECTOR_SIZE: u64 =
    (PIECE_SIZE as u64 / Scalar::SAFE_BYTES as u64).pow(2) * Scalar::FULL_BYTES as u64;
/// How many pieces we have in a sector
pub const PIECES_IN_SECTOR: u64 =
    PLOT_SECTOR_SIZE / (PIECE_SIZE / Scalar::SAFE_BYTES * Scalar::FULL_BYTES) as u64;

/// Byte length of a randomness type.
pub const RANDOMNESS_LENGTH: usize = 32;

/// BLAKE2b-256 hash output
pub type Blake2b256Hash = [u8; BLAKE2B_256_HASH_SIZE];

/// Type of randomness.
pub type Randomness = [u8; RANDOMNESS_LENGTH];

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

/// Segment index type.
pub type SegmentIndex = u64;

/// Records root type.
pub type RecordsRoot = Commitment;

/// Length of public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// 128 data records and 128 parity records (as a result of erasure coding).
pub const PIECES_IN_SEGMENT: u32 = 256;
/// Recorded History Segment Size includes half of the records (just data records) that will later
/// be erasure coded and together with corresponding witnesses will result in `PIECES_IN_SEGMENT`
/// pieces of archival history.
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

/// Randomness context
pub const RANDOMNESS_CONTEXT: &[u8] = b"subspace_randomness";

/// Length of signature in bytes
pub const REWARD_SIGNATURE_LENGTH: usize = 64;
const VRF_OUTPUT_LENGTH: usize = 32;
const VRF_PROOF_LENGTH: usize = 64;

/// Size of proof of space seed in bytes.
const POS_SEED_SIZE: usize = 32;

/// Proof of space seed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PosSeed(pub [u8; POS_SEED_SIZE]);

impl PosSeed {
    /// Size of proof of space seed in bytes.
    pub const SIZE: usize = POS_SEED_SIZE;
}

/// Size of proof of space quality in bytes.
const POS_QUALITY_SIZE: usize = 32;

/// Proof of space quality.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PosQualityBytes(pub [u8; POS_QUALITY_SIZE]);

impl PosQualityBytes {
    /// Size of proof of space quality in bytes.
    pub const SIZE: usize = POS_QUALITY_SIZE;
}

/// Length of proof of space proof in bytes.
const POS_PROOF_LENGTH: usize = 17 * 8;

/// Proof of space proof bytes.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PosProof(pub [u8; POS_PROOF_LENGTH]);

impl PosProof {
    /// Size of proof of space proof in bytes.
    pub const SIZE: usize = POS_PROOF_LENGTH;
}

/// Representation of a single BLS12-381 scalar value.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Scalar(Fr);

impl Encode for Scalar {
    fn size_hint(&self) -> usize {
        48
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.to_bytes())
    }

    fn encoded_size(&self) -> usize {
        48
    }
}

impl EncodeLike for Scalar {}

impl Decode for Scalar {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        Ok(Self::from(&<[u8; Self::FULL_BYTES]>::decode(input)?))
    }

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
                    .type_name("Fr")
            }))
    }
}

#[cfg(feature = "serde")]
mod scalar_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // Custom wrapper so we don't have to write serialization/deserialization code manually
    #[derive(Serialize, Deserialize)]
    struct Scalar(#[serde(with = "hex::serde")] pub(super) [u8; super::Scalar::FULL_BYTES]);

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
            Ok(Self::from(&bytes))
        }
    }
}

impl From<&[u8; Self::SAFE_BYTES]> for Scalar {
    fn from(value: &[u8; Self::SAFE_BYTES]) -> Self {
        Scalar(Fr::from_le_bytes_mod_order(value))
    }
}

impl From<[u8; Self::SAFE_BYTES]> for Scalar {
    fn from(value: [u8; Self::SAFE_BYTES]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8; Self::FULL_BYTES]> for Scalar {
    fn from(value: &[u8; Self::FULL_BYTES]) -> Self {
        Scalar(Fr::from_le_bytes_mod_order(value))
    }
}

impl From<[u8; Self::FULL_BYTES]> for Scalar {
    fn from(value: [u8; Self::FULL_BYTES]) -> Self {
        Self::from(&value)
    }
}

impl From<&Scalar> for [u8; Scalar::FULL_BYTES] {
    fn from(value: &Scalar) -> Self {
        let mut bytes = Self::default();
        value.write_to_bytes(&mut bytes);
        bytes
    }
}

impl From<Scalar> for [u8; Scalar::FULL_BYTES] {
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

    /// Converts scalar to bytes that will be written to `bytes`.
    pub fn write_to_bytes(&self, bytes: &mut [u8; Self::FULL_BYTES]) {
        self.0
            .into_repr()
            .write_le(&mut bytes.as_mut())
            .expect("Correct length input was provided; qed");
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
    fn as_ref(&self) -> &[u8] {
        &self.0
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
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// VRF signature output and proof as produced by `schnorrkel` crate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChunkSignature {
    /// VRF output bytes.
    pub output: [u8; VRF_OUTPUT_LENGTH],
    /// VRF proof bytes.
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub proof: [u8; VRF_PROOF_LENGTH],
}

/// Progress of an archived block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ArchivedBlockProgress {
    /// The block has been fully archived.
    Complete,

    /// Number of paritally archived bytes of a block.
    Partial(u32),
}

impl Default for ArchivedBlockProgress {
    /// We assume a block can always fit into the segment initially, but it can definitely possible
    /// to be transitioned into the partial state after some overflow checkings.
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
    pub number: u32,
    /// Progress of an archived block.
    pub archived_progress: ArchivedBlockProgress,
}

impl LastArchivedBlock {
    /// Returns the number of partially archived bytes for a block.
    pub fn partial_archived(&self) -> Option<u32> {
        self.archived_progress.partial()
    }

    /// Sets new number of partially archived bytes.
    pub fn set_partial_archived(&mut self, new_partial: u32) {
        self.archived_progress.set_partial(new_partial);
    }

    /// Sets the archived state of this block to [`ArchivedBlockProgress::Complete`].
    pub fn set_complete(&mut self) {
        self.archived_progress = ArchivedBlockProgress::Complete;
    }
}

/// Root block for a specific segment.
///
/// Each segment will have corresponding [`RootBlock`] included as the first item in the next
/// segment. Each `RootBlock` includes hash of the previous one and all together form a chain of
/// root blocks that is used for quick and efficient verification that some [`Piece`] corresponds to
/// the actual archival history of the blockchain.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum RootBlock {
    /// V0 of the root block data structure
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Segment index
        segment_index: SegmentIndex,
        /// Merkle root of the records in a segment.
        records_root: RecordsRoot,
        /// Hash of the root block of the previous segment
        prev_root_block_hash: Blake2b256Hash,
        /// Last archived block
        last_archived_block: LastArchivedBlock,
    },
}

impl RootBlock {
    /// Hash of the whole root block
    pub fn hash(&self) -> Blake2b256Hash {
        blake2b_256_hash(&self.encode())
    }

    /// Segment index
    pub fn segment_index(&self) -> u64 {
        match self {
            Self::V0 { segment_index, .. } => *segment_index,
        }
    }

    /// Merkle root of the records in a segment.
    pub fn records_root(&self) -> RecordsRoot {
        match self {
            Self::V0 { records_root, .. } => *records_root,
        }
    }

    /// Hash of the root block of the previous segment
    pub fn prev_root_block_hash(&self) -> Blake2b256Hash {
        match self {
            Self::V0 {
                prev_root_block_hash,
                ..
            } => *prev_root_block_hash,
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

/// Piece index in consensus
pub type PieceIndex = u64;

/// Sector index in consensus
pub type SectorIndex = u64;

/// Hash of `PieceIndex`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, From, Into)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PieceIndexHash(Blake2b256Hash);

impl AsRef<[u8]> for PieceIndexHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PieceIndexHash {
    /// Constructs `PieceIndexHash` from `PieceIndex`
    pub fn from_index(index: PieceIndex) -> Self {
        Self(blake2b_256_hash(&index.to_le_bytes()))
    }
}

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
    /// Number of pieces in archived history at time of sector creation
    pub total_pieces: NonZeroU64,
    /// Pieces offset within sector
    pub piece_offset: PieceIndex,
    /// Piece commitment that can use used to verify that piece was included in blockchain history
    pub piece_record_hash: Blake2b256Hash,
    /// Witness for above piece commitment
    pub piece_witness: Witness,
    /// Chunk offset within a piece
    pub chunk_offset: u32,
    /// Chunk at above offset
    pub chunk: Scalar,
    /// VRF signature of expanded version of the above chunk
    pub chunk_signature: ChunkSignature,
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
            total_pieces,
            piece_offset,
            piece_record_hash,
            piece_witness,
            chunk_offset,
            chunk,
            chunk_signature,
        } = self;
        Solution {
            public_key,
            reward_address: Into::<T>::into(reward_address).into(),
            sector_index,
            total_pieces,
            piece_offset,
            piece_record_hash,
            piece_witness,
            chunk_offset,
            chunk,
            chunk_signature,
        }
    }
}

impl<PublicKey, RewardAddress> Solution<PublicKey, RewardAddress>
where
    PublicKey: Clone,
    RewardAddress: Clone,
{
    /// Dummy solution for the genesis block
    pub fn genesis_solution(public_key: PublicKey, reward_address: RewardAddress) -> Self {
        Self {
            public_key,
            reward_address,
            sector_index: 0,
            total_pieces: NonZeroU64::new(1).expect("1 is not 0; qed"),
            piece_offset: 0,
            piece_record_hash: Blake2b256Hash::default(),
            piece_witness: Witness::default(),
            chunk_offset: 0,
            chunk: Scalar::default(),
            chunk_signature: ChunkSignature {
                output: [0; 32],
                proof: [0; 64],
            },
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

    uint::construct_uint! {
        pub struct U256(4);
    }
}

/// 256-bit unsigned integer
#[derive(
    Debug, Display, Add, Sub, Mul, Div, Rem, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash,
)]
pub struct U256(private_u256::U256);

impl U256 {
    /// Zero (additive identity) of this type.
    pub const fn zero() -> Self {
        Self(private_u256::U256::zero())
    }

    /// One (multiplicative identity) of this type.
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
    fn from(number: U256) -> Self {
        number.0
    }
}

impl WrappingAdd for U256 {
    fn wrapping_add(&self, other: &Self) -> Self {
        Self(self.0.overflowing_add(other.0).0)
    }
}

impl WrappingSub for U256 {
    fn wrapping_sub(&self, other: &Self) -> Self {
        Self(self.0.overflowing_sub(other.0).0)
    }
}

impl From<u8> for U256 {
    fn from(number: u8) -> Self {
        Self(number.into())
    }
}

impl From<u16> for U256 {
    fn from(number: u16) -> Self {
        Self(number.into())
    }
}

impl From<u32> for U256 {
    fn from(number: u32) -> Self {
        Self(number.into())
    }
}

impl From<u64> for U256 {
    fn from(number: u64) -> Self {
        Self(number.into())
    }
}

impl From<u128> for U256 {
    fn from(number: u128) -> Self {
        Self(number.into())
    }
}

impl From<PieceIndexHash> for U256 {
    fn from(PieceIndexHash(hash): PieceIndexHash) -> Self {
        Self(private_u256::U256::from_big_endian(&hash))
    }
}

impl From<U256> for PieceIndexHash {
    fn from(number: U256) -> Self {
        Self(number.to_be_bytes())
    }
}

impl TryFrom<U256> for u64 {
    type Error = &'static str;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

/// Data structure representing sector ID in farmer's plot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SectorId(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] Blake2b256Hash);

impl AsRef<[u8]> for SectorId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SectorId {
    /// Create new sector ID by deriving it from public key and sector index
    pub fn new(public_key: &PublicKey, sector_index: SectorIndex) -> Self {
        Self(blake2b_256_hash_with_key(
            &sector_index.to_le_bytes(),
            public_key.as_ref(),
        ))
    }

    /// Derive piece index that should be stored in sector at `piece_offset` when number of pieces
    /// of blockchain_history is `total_pieces`
    pub fn derive_piece_index(
        &self,
        piece_offset: PieceIndex,
        total_pieces: NonZeroU64,
    ) -> PieceIndex {
        let piece_index = U256::from_le_bytes(blake2b_256_hash_with_key(
            &piece_offset.to_le_bytes(),
            &self.0,
        )) % U256::from(total_pieces.get());

        piece_index
            .try_into()
            .expect("Remainder of division by PieceIndex is guaranteed to fit into PieceIndex; qed")
    }

    /// Derive local challenge for this sector from provided global challenge
    pub fn derive_local_challenge(&self, global_challenge: &Blake2b256Hash) -> SolutionRange {
        let hash = blake2b_256_hash_with_key(global_challenge, &self.0);

        SolutionRange::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ])
    }
}
