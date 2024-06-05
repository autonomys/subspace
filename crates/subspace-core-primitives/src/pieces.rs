#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

use crate::crypto::kzg::{Commitment, Witness};
use crate::crypto::Scalar;
use crate::segments::{ArchivedHistorySegment, SegmentIndex};
use crate::RecordedHistorySegment;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use core::iter::Step;
use core::num::TryFromIntError;
use core::ops::{Deref, DerefMut};
use core::{mem, slice};
use derive_more::{
    Add, AddAssign, AsMut, AsRef, Deref, DerefMut, Display, Div, DivAssign, From, Into, Mul,
    MulAssign, Sub, SubAssign,
};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use scale_info::TypeInfo;

/// S-bucket used in consensus
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
pub struct SBucket(u16);

impl Step for SBucket {
    #[inline]
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u16::steps_between(&start.0, &end.0)
    }

    #[inline]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u16::forward_checked(start.0, count).map(Self)
    }

    #[inline]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u16::backward_checked(start.0, count).map(Self)
    }
}

impl TryFrom<usize> for SBucket {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(u16::try_from(value)?))
    }
}

impl From<u16> for SBucket {
    #[inline]
    fn from(original: u16) -> Self {
        Self(original)
    }
}

impl From<SBucket> for u16 {
    #[inline]
    fn from(original: SBucket) -> Self {
        original.0
    }
}

impl From<SBucket> for u32 {
    #[inline]
    fn from(original: SBucket) -> Self {
        u32::from(original.0)
    }
}

impl From<SBucket> for usize {
    #[inline]
    fn from(original: SBucket) -> Self {
        usize::from(original.0)
    }
}

impl SBucket {
    /// S-bucket 0.
    pub const ZERO: SBucket = SBucket(0);
    /// Max s-bucket index
    pub const MAX: SBucket = SBucket((Record::NUM_S_BUCKETS - 1) as u16);
}

/// Piece index in consensus
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
pub struct PieceIndex(u64);

impl Step for PieceIndex {
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

impl From<u64> for PieceIndex {
    #[inline]
    fn from(original: u64) -> Self {
        Self(original)
    }
}

impl From<PieceIndex> for u64 {
    #[inline]
    fn from(original: PieceIndex) -> Self {
        original.0
    }
}

impl PieceIndex {
    /// Size in bytes.
    pub const SIZE: usize = mem::size_of::<u64>();
    /// Piece index 0.
    pub const ZERO: PieceIndex = PieceIndex(0);
    /// Piece index 1.
    pub const ONE: PieceIndex = PieceIndex(1);

    /// Create piece index from bytes.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }

    /// Convert piece index to bytes.
    #[inline]
    pub const fn to_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }

    /// Segment index piece index corresponds to
    #[inline]
    pub fn segment_index(&self) -> SegmentIndex {
        SegmentIndex::from(self.0 / ArchivedHistorySegment::NUM_PIECES as u64)
    }

    /// Position of a piece in a segment
    #[inline]
    pub const fn position(&self) -> u32 {
        // Position is statically guaranteed to fit into u32
        (self.0 % ArchivedHistorySegment::NUM_PIECES as u64) as u32
    }
}

/// Piece offset in sector
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
pub struct PieceOffset(u16);

impl Step for PieceOffset {
    #[inline]
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u16::steps_between(&start.0, &end.0)
    }

    #[inline]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u16::forward_checked(start.0, count).map(Self)
    }

    #[inline]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u16::backward_checked(start.0, count).map(Self)
    }
}

impl From<u16> for PieceOffset {
    #[inline]
    fn from(original: u16) -> Self {
        Self(original)
    }
}

impl From<PieceOffset> for u16 {
    #[inline]
    fn from(original: PieceOffset) -> Self {
        original.0
    }
}

impl From<PieceOffset> for u32 {
    #[inline]
    fn from(original: PieceOffset) -> Self {
        Self::from(original.0)
    }
}

impl From<PieceOffset> for u64 {
    #[inline]
    fn from(original: PieceOffset) -> Self {
        Self::from(original.0)
    }
}

impl From<PieceOffset> for usize {
    #[inline]
    fn from(original: PieceOffset) -> Self {
        usize::from(original.0)
    }
}

impl PieceOffset {
    /// Piece index 0.
    pub const ZERO: PieceOffset = PieceOffset(0);
    /// Piece index 1.
    pub const ONE: PieceOffset = PieceOffset(1);

    /// Convert piece offset to bytes.
    #[inline]
    pub const fn to_bytes(self) -> [u8; mem::size_of::<u16>()] {
        self.0.to_le_bytes()
    }
}

/// Raw record contained within recorded history segment before archiving is applied.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RawRecord([[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]);

impl Default for RawRecord {
    #[inline]
    fn default() -> Self {
        Self([Default::default(); Self::NUM_CHUNKS])
    }
}

impl AsRef<[u8]> for RawRecord {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice().flatten()
    }
}

impl AsMut<[u8]> for RawRecord {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice().flatten_mut()
    }
}

impl From<&RawRecord> for &[[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS] {
    #[inline]
    fn from(value: &RawRecord) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&[[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS]> for &RawRecord {
    #[inline]
    fn from(value: &[[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS]) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut RawRecord> for &mut [[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS] {
    #[inline]
    fn from(value: &mut RawRecord) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS]> for &mut RawRecord {
    #[inline]
    fn from(value: &mut [[u8; Scalar::SAFE_BYTES]; RawRecord::NUM_CHUNKS]) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&RawRecord> for &[u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS] {
    #[inline]
    fn from(value: &RawRecord) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&[u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS]> for &RawRecord {
    #[inline]
    fn from(value: &[u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS]) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut RawRecord> for &mut [u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS] {
    #[inline]
    fn from(value: &mut RawRecord) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS]> for &mut RawRecord {
    #[inline]
    fn from(value: &mut [u8; Scalar::SAFE_BYTES * RawRecord::NUM_CHUNKS]) -> Self {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl RawRecord {
    /// Number of chunks (scalars) within one raw record.
    pub const NUM_CHUNKS: usize = 2_usize.pow(15);
    /// Size of raw record in bytes, is guaranteed to be a multiple of [`Scalar::SAFE_BYTES`].
    pub const SIZE: usize = Scalar::SAFE_BYTES * Self::NUM_CHUNKS;

    /// Create boxed value without hitting stack overflow
    #[inline]
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::new_zeroed().assume_init() }
    }

    /// Convenient conversion from slice of record to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[[[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]] {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to record for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[[[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]]) -> &[Self] {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of record to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(
        value: &mut [Self],
    ) -> &mut [[[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]] {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to record for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(
        value: &mut [[[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]],
    ) -> &mut [Self] {
        // SAFETY: `RawRecord` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

/// Record contained within a piece.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct Record([[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]);

impl Default for Record {
    #[inline]
    fn default() -> Self {
        Self([Default::default(); Self::NUM_CHUNKS])
    }
}

impl AsRef<[u8]> for Record {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.flatten()
    }
}

impl AsMut<[u8]> for Record {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.flatten_mut()
    }
}

impl From<&Record> for &[[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS] {
    #[inline]
    fn from(value: &Record) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&[[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS]> for &Record {
    #[inline]
    fn from(value: &[[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS]) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut Record> for &mut [[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS] {
    #[inline]
    fn from(value: &mut Record) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS]> for &mut Record {
    #[inline]
    fn from(value: &mut [[u8; Scalar::FULL_BYTES]; Record::NUM_CHUNKS]) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&Record> for &[u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS] {
    #[inline]
    fn from(value: &Record) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        // as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&[u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS]> for &Record {
    #[inline]
    fn from(value: &[u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS]) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        // as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut Record> for &mut [u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS] {
    #[inline]
    fn from(value: &mut Record) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        // as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS]> for &mut Record {
    #[inline]
    fn from(value: &mut [u8; Scalar::FULL_BYTES * Record::NUM_CHUNKS]) -> Self {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        // as inner array, while array of byte arrays has the same alignment as a single byte
        unsafe { mem::transmute(value) }
    }
}

impl Record {
    /// Number of chunks (scalars) within one record.
    pub const NUM_CHUNKS: usize = RawRecord::NUM_CHUNKS;
    /// Number of s-buckets contained within one record (and by extension sector).
    ///
    /// Essentially we chunk records into scalars and erasure code them.
    pub const NUM_S_BUCKETS: usize = Self::NUM_CHUNKS
        * RecordedHistorySegment::ERASURE_CODING_RATE.1
        / RecordedHistorySegment::ERASURE_CODING_RATE.0;
    /// Size of a segment record given the global piece size (in bytes) after erasure coding
    /// [`RawRecord`], is guaranteed to be a multiple of [`Scalar::FULL_BYTES`].
    pub const SIZE: usize = Scalar::FULL_BYTES * Self::NUM_CHUNKS;

    /// Create boxed value without hitting stack overflow
    #[inline]
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::new_zeroed().assume_init() }
    }

    /// Create vector filled with zeroe records without hitting stack overflow
    #[inline]
    pub fn new_zero_vec(length: usize) -> Vec<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        let mut records = Vec::with_capacity(length);
        {
            let slice = records.spare_capacity_mut();
            // SAFETY: Same memory layout due to `#[repr(transparent)]` on `Record` and
            // `MaybeUninit<[[T; M]; N]>` is guaranteed to have the same layout as
            // `[[MaybeUninit<T>; M]; N]`
            let slice = unsafe {
                slice::from_raw_parts_mut(
                    slice.as_mut_ptr()
                        as *mut [[mem::MaybeUninit<u8>; Scalar::FULL_BYTES]; Self::NUM_CHUNKS],
                    length,
                )
            };
            for byte in slice.flatten_mut().flatten_mut() {
                byte.write(0);
            }
        }
        // SAFETY: All values are initialized above.
        unsafe {
            records.set_len(records.capacity());
        }

        records
    }

    /// Convenient conversion from slice of record to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[[[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to record for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[[[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]]) -> &[Self] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of record to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(
        value: &mut [Self],
    ) -> &mut [[[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to record for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(
        value: &mut [[[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]],
    ) -> &mut [Self] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }
}

/// Record commitment contained within a piece.
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
pub struct RecordCommitment(
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; RecordCommitment::SIZE],
);

impl Default for RecordCommitment {
    #[inline]
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for RecordCommitment {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for RecordCommitment {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RecordCommitment {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<&RecordCommitment> for &[u8; RecordCommitment::SIZE] {
    #[inline]
    fn from(value: &RecordCommitment) -> Self {
        // SAFETY: `RecordCommitment` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&[u8; RecordCommitment::SIZE]> for &RecordCommitment {
    #[inline]
    fn from(value: &[u8; RecordCommitment::SIZE]) -> Self {
        // SAFETY: `RecordCommitment` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut RecordCommitment> for &mut [u8; RecordCommitment::SIZE] {
    #[inline]
    fn from(value: &mut RecordCommitment) -> Self {
        // SAFETY: `RecordCommitment` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [u8; RecordCommitment::SIZE]> for &mut RecordCommitment {
    #[inline]
    fn from(value: &mut [u8; RecordCommitment::SIZE]) -> Self {
        // SAFETY: `RecordCommitment` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl RecordCommitment {
    /// Size of record commitment in bytes.
    pub const SIZE: usize = 48;
}

impl From<Commitment> for RecordCommitment {
    #[inline]
    fn from(commitment: Commitment) -> Self {
        Self(commitment.to_bytes())
    }
}

impl TryFrom<&RecordCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: &RecordCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(&commitment.0)
    }
}

impl TryFrom<RecordCommitment> for Commitment {
    type Error = String;

    #[inline]
    fn try_from(commitment: RecordCommitment) -> Result<Self, Self::Error> {
        Commitment::try_from(commitment.0)
    }
}

/// Record witness contained within a piece.
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
pub struct RecordWitness(
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; RecordWitness::SIZE],
);

impl Default for RecordWitness {
    #[inline]
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for RecordWitness {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for RecordWitness {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RecordWitness {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<&RecordWitness> for &[u8; RecordWitness::SIZE] {
    #[inline]
    fn from(value: &RecordWitness) -> Self {
        // SAFETY: `RecordWitness` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&[u8; RecordWitness::SIZE]> for &RecordWitness {
    #[inline]
    fn from(value: &[u8; RecordWitness::SIZE]) -> Self {
        // SAFETY: `RecordWitness` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut RecordWitness> for &mut [u8; RecordWitness::SIZE] {
    #[inline]
    fn from(value: &mut RecordWitness) -> Self {
        // SAFETY: `RecordWitness` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [u8; RecordWitness::SIZE]> for &mut RecordWitness {
    #[inline]
    fn from(value: &mut [u8; RecordWitness::SIZE]) -> Self {
        // SAFETY: `RecordWitness` is `#[repr(transparent)]` and guaranteed to have the same
        // memory layout
        unsafe { mem::transmute(value) }
    }
}

impl RecordWitness {
    /// Size of record witness in bytes.
    pub const SIZE: usize = 48;
}

impl From<Witness> for RecordWitness {
    #[inline]
    fn from(witness: Witness) -> Self {
        Self(witness.to_bytes())
    }
}

impl TryFrom<&RecordWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: &RecordWitness) -> Result<Self, Self::Error> {
        Witness::try_from(&witness.0)
    }
}

impl TryFrom<RecordWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: RecordWitness) -> Result<Self, Self::Error> {
        Witness::try_from(witness.0)
    }
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
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; ChunkWitness::SIZE],
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

impl From<Witness> for ChunkWitness {
    #[inline]
    fn from(witness: Witness) -> Self {
        Self(witness.to_bytes())
    }
}

impl TryFrom<&ChunkWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: &ChunkWitness) -> Result<Self, Self::Error> {
        Witness::try_from(&witness.0)
    }
}

impl TryFrom<ChunkWitness> for Witness {
    type Error = String;

    #[inline]
    fn try_from(witness: ChunkWitness) -> Result<Self, Self::Error> {
        Witness::try_from(witness.0)
    }
}

/// A piece of archival history in Subspace Network.
///
/// This version is allocated on the heap, for stack-allocated piece see [`PieceArray`].
///
/// Internally piece contains a record and corresponding witness that together with segment
/// commitment of the segment this piece belongs to can be used to verify that a piece belongs to
/// the actual archival history of the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Piece(Box<PieceArray>);

impl Default for Piece {
    #[inline]
    fn default() -> Self {
        Self(PieceArray::new_boxed())
    }
}

impl From<Piece> for Vec<u8> {
    #[inline]
    fn from(piece: Piece) -> Self {
        piece.0.to_vec()
    }
}

impl TryFrom<&[u8]> for Piece {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let slice = <&[u8; Self::SIZE]>::try_from(slice)?;
        let mut piece = Self::default();
        piece.copy_from_slice(slice);
        Ok(piece)
    }
}

impl TryFrom<Vec<u8>> for Piece {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        // TODO: Maybe possible to transmute boxed slice into boxed array
        Self::try_from(vec.as_slice())
    }
}

impl From<&PieceArray> for Piece {
    #[inline]
    fn from(value: &PieceArray) -> Self {
        let mut piece = Piece::default();
        piece.as_mut().copy_from_slice(value.as_ref());
        piece
    }
}

impl Deref for Piece {
    type Target = PieceArray;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Piece {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Piece {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Piece {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl Piece {
    /// Size of a piece (in bytes).
    pub const SIZE: usize = Record::SIZE + RecordCommitment::SIZE + RecordWitness::SIZE;
}

/// A piece of archival history in Subspace Network.
///
/// This version is allocated on the stack, for heap-allocated piece see [`Piece`].
///
/// Internally piece contains a record and corresponding witness that together with segment
/// commitment of the segment this piece belongs to can be used to verify that a piece belongs to
/// the actual archival history of the blockchain.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    DerefMut,
    AsRef,
    AsMut,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[repr(transparent)]
pub struct PieceArray([u8; Piece::SIZE]);

impl Default for PieceArray {
    #[inline]
    fn default() -> Self {
        Self([0u8; Piece::SIZE])
    }
}

impl AsRef<[u8]> for PieceArray {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PieceArray {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<&PieceArray> for &[u8; Piece::SIZE] {
    #[inline]
    fn from(value: &PieceArray) -> Self {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&[u8; Piece::SIZE]> for &PieceArray {
    #[inline]
    fn from(value: &[u8; Piece::SIZE]) -> Self {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut PieceArray> for &mut [u8; Piece::SIZE] {
    #[inline]
    fn from(value: &mut PieceArray) -> Self {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl From<&mut [u8; Piece::SIZE]> for &mut PieceArray {
    #[inline]
    fn from(value: &mut [u8; Piece::SIZE]) -> Self {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

impl PieceArray {
    /// Create boxed value without hitting stack overflow
    #[inline]
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::<Self>::new_zeroed().assume_init() }
    }

    /// Split piece into underlying components.
    #[inline]
    pub fn split(&self) -> (&Record, &RecordCommitment, &RecordWitness) {
        let (record, extra) = self.0.split_at(Record::SIZE);
        let (commitment, witness) = extra.split_at(RecordCommitment::SIZE);

        let record = <&[u8; Record::SIZE]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let commitment = <&[u8; RecordCommitment::SIZE]>::try_from(commitment)
            .expect("Slice of memory has correct length; qed");
        let witness = <&[u8; RecordWitness::SIZE]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        (record.into(), commitment.into(), witness.into())
    }

    /// Split piece into underlying mutable components.
    #[inline]
    pub fn split_mut(&mut self) -> (&mut Record, &mut RecordCommitment, &mut RecordWitness) {
        let (record, extra) = self.0.split_at_mut(Record::SIZE);
        let (commitment, witness) = extra.split_at_mut(RecordCommitment::SIZE);

        let record = <&mut [u8; Record::SIZE]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let commitment = <&mut [u8; RecordCommitment::SIZE]>::try_from(commitment)
            .expect("Slice of memory has correct length; qed");
        let witness = <&mut [u8; RecordWitness::SIZE]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        (record.into(), commitment.into(), witness.into())
    }

    /// Record contained within a piece.
    #[inline]
    pub fn record(&self) -> &Record {
        self.split().0
    }

    /// Mutable record contained within a piece.
    #[inline]
    pub fn record_mut(&mut self) -> &mut Record {
        self.split_mut().0
    }

    /// Commitment contained within a piece.
    #[inline]
    pub fn commitment(&self) -> &RecordCommitment {
        self.split().1
    }

    /// Mutable commitment contained within a piece.
    #[inline]
    pub fn commitment_mut(&mut self) -> &mut RecordCommitment {
        self.split_mut().1
    }

    /// Witness contained within a piece.
    #[inline]
    pub fn witness(&self) -> &RecordWitness {
        self.split().2
    }

    /// Mutable witness contained within a piece.
    #[inline]
    pub fn witness_mut(&mut self) -> &mut RecordWitness {
        self.split_mut().2
    }

    /// Convenient conversion from slice of piece array to underlying representation for efficiency
    /// purposes.
    #[inline]
    pub fn slice_to_repr(value: &[Self]) -> &[[u8; Piece::SIZE]] {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to piece array for efficiency
    /// purposes.
    #[inline]
    pub fn slice_from_repr(value: &[[u8; Piece::SIZE]]) -> &[Self] {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of piece array to underlying representation for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [[u8; Piece::SIZE]] {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to piece array for
    /// efficiency purposes.
    #[inline]
    pub fn slice_mut_from_repr(value: &mut [[u8; Piece::SIZE]]) -> &mut [Self] {
        // SAFETY: `PieceArray` is `#[repr(transparent)]` and guaranteed to have the same memory
        // layout
        unsafe { mem::transmute(value) }
    }
}

/// Flat representation of multiple pieces concatenated for higher efficient for processing.
#[derive(
    Debug,
    Default,
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
    DerefMut,
)]
pub struct FlatPieces(Vec<PieceArray>);

impl FlatPieces {
    /// Allocate `FlatPieces` that will hold `piece_count` pieces filled with zeroes.
    #[inline]
    pub fn new(piece_count: usize) -> Self {
        let mut pieces = Vec::with_capacity(piece_count);
        {
            let slice = pieces.spare_capacity_mut();
            // SAFETY: Same memory layout due to `#[repr(transparent)]` on `PieceArray` and
            // `MaybeUninit<[T; N]>` is guaranteed to have the same layout as `[MaybeUninit<T>; N]`
            let slice = unsafe {
                slice::from_raw_parts_mut(
                    slice.as_mut_ptr() as *mut [mem::MaybeUninit<u8>; Piece::SIZE],
                    piece_count,
                )
            };
            for byte in slice.flatten_mut() {
                byte.write(0);
            }
        }
        // SAFETY: All values are initialized above.
        unsafe {
            pieces.set_len(pieces.capacity());
        }
        Self(pieces)
    }

    /// Extract internal representation.
    #[inline]
    pub fn into_inner(self) -> Vec<PieceArray> {
        self.0
    }

    /// Iterator over source pieces (even indices).
    #[inline]
    pub fn source(&self) -> impl ExactSizeIterator<Item = &'_ PieceArray> + '_ {
        self.0.iter().step_by(2)
    }

    /// Mutable iterator over source pieces (even indices).
    #[inline]
    pub fn source_mut(&mut self) -> impl ExactSizeIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.iter_mut().step_by(2)
    }

    /// Iterator over parity pieces (odd indices).
    #[inline]
    pub fn parity(&self) -> impl ExactSizeIterator<Item = &'_ PieceArray> + '_ {
        self.0.iter().skip(1).step_by(2)
    }

    /// Mutable iterator over parity pieces (odd indices).
    #[inline]
    pub fn parity_mut(&mut self) -> impl ExactSizeIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.iter_mut().skip(1).step_by(2)
    }
}

#[cfg(feature = "parallel")]
impl FlatPieces {
    /// Parallel iterator over source pieces (even indices).
    #[inline]
    pub fn par_source(&self) -> impl IndexedParallelIterator<Item = &'_ PieceArray> + '_ {
        self.0.par_iter().step_by(2)
    }

    /// Mutable parallel iterator over source pieces (even indices).
    #[inline]
    pub fn par_source_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.par_iter_mut().step_by(2)
    }

    /// Parallel iterator over parity pieces (odd indices).
    #[inline]
    pub fn par_parity(&self) -> impl IndexedParallelIterator<Item = &'_ PieceArray> + '_ {
        self.0.par_iter().skip(1).step_by(2)
    }

    /// Mutable parallel iterator over parity pieces (odd indices).
    #[inline]
    pub fn par_parity_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.par_iter_mut().skip(1).step_by(2)
    }
}

impl From<PieceArray> for FlatPieces {
    #[inline]
    fn from(value: PieceArray) -> Self {
        Self(vec![value])
    }
}
