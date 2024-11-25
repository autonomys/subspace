//! Segments-related data structures.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::hashes::{blake3_hash, Blake3Hash};
use crate::pieces::{FlatPieces, Piece, PieceIndex, RawRecord};
use crate::BlockNumber;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use core::array::TryFromSliceError;
use core::iter::Step;
use core::num::NonZeroU64;
use derive_more::{
    Add, AddAssign, Deref, DerefMut, Display, Div, DivAssign, From, Into, Mul, MulAssign, Sub,
    SubAssign,
};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// Segment index type.
#[derive(
    Debug,
    Display,
    Default,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    From,
    Into,
    Encode,
    Decode,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    Mul,
    MulAssign,
    Div,
    DivAssign,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(transparent)]
pub struct SegmentIndex(u64);

impl Step for SegmentIndex {
    #[inline]
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u64::steps_between(&start.0, &end.0)
    }

    #[inline]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u64::forward_checked(start.0, count).map(Self)
    }

    #[inline]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u64::backward_checked(start.0, count).map(Self)
    }
}

impl SegmentIndex {
    /// Segment index 0.
    pub const ZERO: SegmentIndex = SegmentIndex(0);
    /// Segment index 1.
    pub const ONE: SegmentIndex = SegmentIndex(1);

    /// Create new instance
    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// Get the first piece index in this segment.
    pub fn first_piece_index(&self) -> PieceIndex {
        PieceIndex::from(self.0 * ArchivedHistorySegment::NUM_PIECES as u64)
    }

    /// Get the last piece index in this segment.
    pub fn last_piece_index(&self) -> PieceIndex {
        PieceIndex::from((self.0 + 1) * ArchivedHistorySegment::NUM_PIECES as u64 - 1)
    }

    /// List of piece indexes that belong to this segment.
    pub fn segment_piece_indexes(&self) -> [PieceIndex; ArchivedHistorySegment::NUM_PIECES] {
        let mut piece_indices = [PieceIndex::ZERO; ArchivedHistorySegment::NUM_PIECES];
        (self.first_piece_index()..=self.last_piece_index())
            .zip(&mut piece_indices)
            .for_each(|(input, output)| {
                *output = input;
            });

        piece_indices
    }

    /// List of piece indexes that belong to this segment with source pieces first.
    pub fn segment_piece_indexes_source_first(
        &self,
    ) -> [PieceIndex; ArchivedHistorySegment::NUM_PIECES] {
        let mut source_first_piece_indices = [PieceIndex::ZERO; ArchivedHistorySegment::NUM_PIECES];

        let piece_indices = self.segment_piece_indexes();
        piece_indices
            .into_iter()
            .step_by(2)
            .chain(piece_indices.into_iter().skip(1).step_by(2))
            .zip(&mut source_first_piece_indices)
            .for_each(|(input, output)| {
                *output = input;
            });

        source_first_piece_indices
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }
}

/// Segment commitment contained within segment header.
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
pub struct SegmentCommitment([u8; SegmentCommitment::SIZE]);

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SegmentCommitmentBinary(#[serde(with = "BigArray")] [u8; SegmentCommitment::SIZE]);

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SegmentCommitmentHex(#[serde(with = "hex")] [u8; SegmentCommitment::SIZE]);

#[cfg(feature = "serde")]
impl Serialize for SegmentCommitment {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            SegmentCommitmentHex(self.0).serialize(serializer)
        } else {
            SegmentCommitmentBinary(self.0).serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SegmentCommitment {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(if deserializer.is_human_readable() {
            SegmentCommitmentHex::deserialize(deserializer)?.0
        } else {
            SegmentCommitmentBinary::deserialize(deserializer)?.0
        }))
    }
}

impl Default for SegmentCommitment {
    #[inline]
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for SegmentCommitment {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for SegmentCommitment {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SegmentCommitment {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl SegmentCommitment {
    /// Size of segment commitment in bytes.
    pub const SIZE: usize = 48;
}

/// Size of blockchain history in segments.
#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    From,
    Into,
    Deref,
    DerefMut,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(transparent)]
pub struct HistorySize(NonZeroU64);

impl From<SegmentIndex> for HistorySize {
    #[inline]
    fn from(value: SegmentIndex) -> Self {
        Self(NonZeroU64::new(value.0 + 1).expect("Not zero; qed"))
    }
}

impl HistorySize {
    /// History size of one
    pub const ONE: Self = Self(NonZeroU64::new(1).expect("Not zero; qed"));

    /// Create new instance.
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Size of blockchain history in pieces.
    pub const fn in_pieces(&self) -> NonZeroU64 {
        self.0.saturating_mul(
            NonZeroU64::new(ArchivedHistorySegment::NUM_PIECES as u64).expect("Not zero; qed"),
        )
    }

    /// Segment index that corresponds to this history size.
    pub fn segment_index(&self) -> SegmentIndex {
        SegmentIndex::from(self.0.get() - 1)
    }

    /// History size at which expiration check for sector happens.
    ///
    /// Returns `None` on overflow.
    pub fn sector_expiration_check(&self, min_sector_lifetime: Self) -> Option<Self> {
        self.0.checked_add(min_sector_lifetime.0.get()).map(Self)
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
    /// We assume a block can always fit into the segment initially, but it is definitely possible
    /// to be transitioned into the partial state after some overflow checking.
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
        prev_segment_header_hash: Blake3Hash,
        /// Last archived block
        last_archived_block: LastArchivedBlock,
    },
}

impl SegmentHeader {
    /// Hash of the whole segment header
    pub fn hash(&self) -> Blake3Hash {
        blake3_hash(&self.encode())
    }

    /// Segment index
    pub fn segment_index(&self) -> SegmentIndex {
        match self {
            Self::V0 { segment_index, .. } => *segment_index,
        }
    }

    /// Segment commitment of the records in a segment.
    pub fn segment_commitment(&self) -> SegmentCommitment {
        match self {
            Self::V0 {
                segment_commitment, ..
            } => *segment_commitment,
        }
    }

    /// Hash of the segment header of the previous segment
    pub fn prev_segment_header_hash(&self) -> Blake3Hash {
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

/// Recorded history segment before archiving is applied.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RecordedHistorySegment([RawRecord; Self::NUM_RAW_RECORDS]);

impl Default for RecordedHistorySegment {
    #[inline]
    fn default() -> Self {
        Self([RawRecord::default(); Self::NUM_RAW_RECORDS])
    }
}

impl AsRef<[u8]> for RecordedHistorySegment {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        RawRecord::slice_to_repr(&self.0)
            .as_flattened()
            .as_flattened()
    }
}

impl AsMut<[u8]> for RecordedHistorySegment {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        RawRecord::slice_mut_to_repr(&mut self.0)
            .as_flattened_mut()
            .as_flattened_mut()
    }
}

impl RecordedHistorySegment {
    /// Number of raw records in one segment of recorded history.
    pub const NUM_RAW_RECORDS: usize = 128;
    /// Erasure coding rate for records during archiving process.
    pub const ERASURE_CODING_RATE: (usize, usize) = (1, 2);
    /// Size of recorded history segment in bytes.
    ///
    /// It includes half of the records (just source records) that will later be erasure coded and
    /// together with corresponding commitments and witnesses will result in
    /// [`ArchivedHistorySegment::NUM_PIECES`] [`Piece`]s of archival history.
    pub const SIZE: usize = RawRecord::SIZE * Self::NUM_RAW_RECORDS;

    /// Create boxed value without hitting stack overflow
    #[inline]
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::<Self>::new_zeroed().assume_init() }
    }
}

/// Archived history segment after archiving is applied.
#[derive(Debug, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct ArchivedHistorySegment(FlatPieces);

impl Default for ArchivedHistorySegment {
    #[inline]
    fn default() -> Self {
        Self(FlatPieces::new(Self::NUM_PIECES))
    }
}

impl ArchivedHistorySegment {
    /// Number of pieces in one segment of archived history.
    pub const NUM_PIECES: usize = RecordedHistorySegment::NUM_RAW_RECORDS
        * RecordedHistorySegment::ERASURE_CODING_RATE.1
        / RecordedHistorySegment::ERASURE_CODING_RATE.0;
    /// Size of archived history segment in bytes.
    ///
    /// It includes erasure coded [`crate::pieces::PieceArray`]s (both source and parity) that are
    /// composed of [`crate::pieces::Record`]s together with corresponding commitments and
    /// witnesses.
    pub const SIZE: usize = Piece::SIZE * Self::NUM_PIECES;

    /// Ensure archived history segment contains cheaply cloneable shared data.
    ///
    /// Internally archived history segment uses CoW mechanism and can store either mutable owned
    /// data or data that is cheap to clone, calling this method will ensure further clones and
    /// returned pieces will not result in additional memory allocations.
    pub fn to_shared(self) -> Self {
        Self(self.0.to_shared())
    }
}
