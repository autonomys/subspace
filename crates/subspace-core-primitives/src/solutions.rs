//! Solutions-related data structures and functions.

use crate::pieces::{PieceOffset, Record, RecordCommitment, RecordWitness};
use crate::pos::PosProof;
use crate::sectors::SectorIndex;
use crate::segments::{HistorySize, SegmentIndex};
use crate::{PublicKey, ScalarBytes};
use core::array::TryFromSliceError;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, Into};
use num_traits::WrappingSub;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;

// TODO: Add related methods to `SolutionRange`.
/// Type of solution range.
pub type SolutionRange = u64;

/// Computes the following:
/// ```text
/// MAX * slot_probability / chunks * s_buckets / pieces
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

/// Witness for chunk contained within a record.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Deref,
    DerefMut,
    From,
    Into,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChunkWitness(
    #[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; ChunkWitness::SIZE],
);

impl Default for ChunkWitness {
    #[inline]
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for ChunkWitness {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for ChunkWitness {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for ChunkWitness {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl ChunkWitness {
    /// Size of chunk witness in bytes.
    pub const SIZE: usize = 48;
}

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
    pub chunk: ScalarBytes,
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
            chunk: ScalarBytes::default(),
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
