//! Segments-related data structures.

use crate::crypto::kzg::Commitment;
use crate::pieces::{FlatPieces, Piece, PieceIndex, RawRecord};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::string::String;
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SegmentCommitment(
    #[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; SegmentCommitment::SIZE],
);

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

impl From<Commitment> for SegmentCommitment {
    #[inline]
    fn from(commitment: Commitment) -> Self {
        Self(commitment.to_bytes())
    }
}

impl TryFrom<&SegmentCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: &SegmentCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(&commitment.0)
    }
}

impl TryFrom<SegmentCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: SegmentCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(commitment.0)
    }
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
