use crate::pieces::{FlatPieces, Piece, PieceIndex, RawRecord};
use alloc::boxed::Box;
use core::iter::Step;
use core::mem;
use derive_more::{
    Add, AddAssign, Deref, DerefMut, Display, Div, DivAssign, Mul, MulAssign, Sub, SubAssign,
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
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u64::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u64::forward_checked(start.0, count).map(Self)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u64::backward_checked(start.0, count).map(Self)
    }
}

impl const From<u64> for SegmentIndex {
    fn from(original: u64) -> Self {
        Self(original)
    }
}

impl const From<SegmentIndex> for u64 {
    fn from(original: SegmentIndex) -> Self {
        original.0
    }
}

impl SegmentIndex {
    /// Segment index 0.
    pub const ZERO: SegmentIndex = SegmentIndex(0);
    /// Segment index 1.
    pub const ONE: SegmentIndex = SegmentIndex(1);

    /// Get the first piece index in this segment.
    pub const fn first_piece_index(&self) -> PieceIndex {
        PieceIndex::from(self.0 * ArchivedHistorySegment::NUM_PIECES as u64)
    }

    /// Iterator over piece indexes that belong to this segment.
    pub fn segment_piece_indexes(&self) -> impl Iterator<Item = PieceIndex> {
        (self.first_piece_index()..).take(ArchivedHistorySegment::NUM_PIECES)
    }

    /// Iterator over piece indexes that belong to this segment with source pieces first.
    pub fn segment_piece_indexes_source_first(&self) -> impl Iterator<Item = PieceIndex> {
        self.segment_piece_indexes()
            .step_by(2)
            .chain(self.segment_piece_indexes().skip(1).step_by(2))
    }
}

/// Recorded history segment before archiving is applied.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RecordedHistorySegment([RawRecord; Self::NUM_RAW_RECORDS]);

impl Default for RecordedHistorySegment {
    fn default() -> Self {
        Self([RawRecord::default(); Self::NUM_RAW_RECORDS])
    }
}

impl AsRef<[u8]> for RecordedHistorySegment {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let raw_records: &[[u8; RawRecord::SIZE]] = unsafe { mem::transmute(self.0.as_slice()) };
        raw_records.flatten()
    }
}

impl AsMut<[u8]> for RecordedHistorySegment {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let raw_records: &mut [[u8; RawRecord::SIZE]] =
            unsafe { mem::transmute(self.0.as_mut_slice()) };
        raw_records.flatten_mut()
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
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::<Self>::new_zeroed().assume_init() }
    }
}

/// Archived history segment after archiving is applied.
#[derive(Debug, Clone, Eq, PartialEq, Deref, DerefMut, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(transparent)]
pub struct ArchivedHistorySegment(FlatPieces);

impl Default for ArchivedHistorySegment {
    fn default() -> Self {
        Self(FlatPieces::new(Self::NUM_PIECES))
    }
}

impl MaxEncodedLen for ArchivedHistorySegment {
    fn max_encoded_len() -> usize {
        Self::SIZE
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
    /// composed from [`crate::pieces::Record`]s together with corresponding commitments and witnesses.
    pub const SIZE: usize = Piece::SIZE * Self::NUM_PIECES;
}
