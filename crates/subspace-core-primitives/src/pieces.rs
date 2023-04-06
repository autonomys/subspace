#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

use crate::crypto::{blake2b_256_hash, Scalar};
use crate::segments::{ArchivedHistorySegment, SegmentIndex};
use crate::{Blake2b256Hash, RecordedHistorySegment};
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use core::iter::Step;
use core::mem;
use core::num::TryFromIntError;
use core::ops::{Deref, DerefMut};
use derive_more::{
    Add, AddAssign, AsMut, AsRef, Deref, DerefMut, Display, Div, DivAssign, From, Into, Mul,
    MulAssign, Sub, SubAssign,
};
use parity_scale_codec::{Decode, Encode, Input, MaxEncodedLen};
#[cfg(feature = "rayon")]
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
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u16::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u16::forward_checked(start.0, count).map(Self)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u16::backward_checked(start.0, count).map(Self)
    }
}

impl const TryFrom<usize> for SBucket {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(u16::try_from(value)?))
    }
}

impl const From<u16> for SBucket {
    fn from(original: u16) -> Self {
        Self(original)
    }
}

impl const From<SBucket> for u16 {
    fn from(original: SBucket) -> Self {
        original.0
    }
}

impl const From<SBucket> for u32 {
    fn from(original: SBucket) -> Self {
        u32::from(original.0)
    }
}

impl const From<SBucket> for usize {
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

impl const From<u64> for PieceIndex {
    fn from(original: u64) -> Self {
        Self(original)
    }
}

impl const From<PieceIndex> for u64 {
    fn from(original: PieceIndex) -> Self {
        original.0
    }
}

impl PieceIndex {
    /// Piece index 0.
    pub const ZERO: PieceIndex = PieceIndex(0);
    /// Piece index 1.
    pub const ONE: PieceIndex = PieceIndex(1);

    /// Derive piece index hash
    pub fn hash(&self) -> PieceIndexHash {
        PieceIndexHash::from(blake2b_256_hash(&self.to_bytes()))
    }

    /// Convert piece index to bytes.
    pub const fn to_bytes(self) -> [u8; mem::size_of::<u64>()] {
        self.0.to_le_bytes()
    }

    /// Segment index piece index corresponds to
    pub const fn segment_index(&self) -> SegmentIndex {
        SegmentIndex::from(self.0 / ArchivedHistorySegment::NUM_PIECES as u64)
    }

    /// Position of a piece in a segment
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
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u16::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u16::forward_checked(start.0, count).map(Self)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u16::backward_checked(start.0, count).map(Self)
    }
}

impl const From<u16> for PieceOffset {
    fn from(original: u16) -> Self {
        Self(original)
    }
}

impl const From<PieceOffset> for u16 {
    fn from(original: PieceOffset) -> Self {
        original.0
    }
}

impl const From<PieceOffset> for usize {
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
    pub const fn to_bytes(self) -> [u8; mem::size_of::<u16>()] {
        self.0.to_le_bytes()
    }
}

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
    // TODO: Remove and replace uses with `index.hash()`
    /// Constructs `PieceIndexHash` from `PieceIndex`
    pub fn from_index(index: PieceIndex) -> Self {
        index.hash()
    }
}

/// Raw record contained within recorded history segment before archiving is applied.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RawRecord([[u8; Scalar::SAFE_BYTES]; Self::NUM_CHUNKS]);

impl Default for RawRecord {
    fn default() -> Self {
        Self([Default::default(); Self::NUM_CHUNKS])
    }
}

impl AsRef<[u8]> for RawRecord {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice().flatten()
    }
}

impl AsMut<[u8]> for RawRecord {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice().flatten_mut()
    }
}

impl RawRecord {
    /// Number of chunks (scalars) within one raw record.
    pub const NUM_CHUNKS: usize = 2_usize.pow(15);
    /// Size of raw record in bytes, is guaranteed to be a multiple of [`Scalar::SAFE_BYTES`].
    pub const SIZE: usize = Scalar::SAFE_BYTES * Self::NUM_CHUNKS;

    /// Create boxed value without hitting stack overflow
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::new_zeroed().assume_init() }
    }
}

/// Record contained within a piece.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct Record([[u8; Scalar::FULL_BYTES]; Self::NUM_CHUNKS]);

impl Default for Record {
    fn default() -> Self {
        Self([Default::default(); Self::NUM_CHUNKS])
    }
}

impl AsRef<[u8]> for Record {
    fn as_ref(&self) -> &[u8] {
        self.0.flatten()
    }
}

impl AsMut<[u8]> for Record {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.flatten_mut()
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
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::new_zeroed().assume_init() }
    }

    /// Convenient conversion from slice of record to underlying representation for efficiency
    /// purposes.
    pub fn slice_to_repr(value: &[Self]) -> &[[u8; Self::SIZE]] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from slice of underlying representation to record for efficiency
    /// purposes.
    pub fn slice_from_repr(value: &[[u8; Self::SIZE]]) -> &[Self] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of record to underlying representation for
    /// efficiency purposes.
    pub fn slice_mut_to_repr(value: &mut [Self]) -> &mut [[u8; Self::SIZE]] {
        // SAFETY: `Record` is `#[repr(transparent)]` and guaranteed to have the same memory layout
        unsafe { mem::transmute(value) }
    }

    /// Convenient conversion from mutable slice of underlying representation to record for
    /// efficiency purposes.
    pub fn slice_mut_from_repr(value: &mut [[u8; Self::SIZE]]) -> &mut [Self] {
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
pub struct RecordCommitment([u8; RecordCommitment::SIZE]);

impl Default for RecordCommitment {
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for RecordCommitment {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for RecordCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RecordCommitment {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl RecordCommitment {
    /// Size of record commitment in bytes.
    pub const SIZE: usize = 48;
}

/// Record witness contained within a piece.
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
#[repr(transparent)]
pub struct RecordWitness([u8; RecordWitness::SIZE]);

impl Default for RecordWitness {
    fn default() -> Self {
        Self([0; Self::SIZE])
    }
}

impl TryFrom<&[u8]> for RecordWitness {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(Self)
    }
}

impl AsRef<[u8]> for RecordWitness {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RecordWitness {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl RecordWitness {
    /// Size of record witness in bytes.
    pub const SIZE: usize = 48;
}

/// A piece of archival history in Subspace Network.
///
/// This version is allocated on the heap, for stack-allocated piece see [`PieceArray`].
///
/// Internally piece contains a record and corresponding witness that together with segment
/// commitment of the segment this piece belongs to can be used to verify that a piece belongs to
/// the actual archival history of the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Piece(Box<PieceArray>);

impl Default for Piece {
    fn default() -> Self {
        Self(PieceArray::new_boxed())
    }
}

// TODO: Manual implementation due to https://github.com/paritytech/parity-scale-codec/issues/419,
//  can be replaced with derive once fixed upstream version is released
impl Decode for Piece {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let piece = parity_scale_codec::decode_vec_with_len::<u8, _>(input, Self::SIZE)
            .map_err(|error| error.chain("Could not decode `Piece.0`"))?;
        let mut piece = mem::ManuallyDrop::new(piece);
        // SAFETY: Original memory is not dropped and guaranteed to be allocated
        let piece = unsafe { Box::from_raw(piece.as_mut_ptr() as *mut PieceArray) };
        Ok(Piece(piece))
    }
}

impl From<Piece> for Vec<u8> {
    fn from(piece: Piece) -> Self {
        piece.0.to_vec()
    }
}
impl TryFrom<&[u8]> for Piece {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::SIZE]>::try_from(slice).map(|bytes| Piece(Box::new(PieceArray(bytes))))
    }
}

impl TryFrom<Vec<u8>> for Piece {
    type Error = TryFromSliceError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        // TODO: Maybe possible to transmute boxed slice into boxed array
        Self::try_from(vec.as_slice())
    }
}

impl From<&PieceArray> for Piece {
    fn from(value: &PieceArray) -> Self {
        let mut piece = Piece::default();
        piece.as_mut().copy_from_slice(value.as_ref());
        piece
    }
}

impl Deref for Piece {
    type Target = PieceArray;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Piece {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Piece {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Piece {
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
    fn default() -> Self {
        Self([0u8; Piece::SIZE])
    }
}

impl AsRef<[u8]> for PieceArray {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PieceArray {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl PieceArray {
    /// Create boxed value without hitting stack overflow
    pub fn new_boxed() -> Box<Self> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        unsafe { Box::<Self>::new_zeroed().assume_init() }
    }

    /// Split piece into underlying components.
    pub fn split(&self) -> (&Record, &RecordCommitment, &RecordWitness) {
        let (record, extra) = self.0.split_at(Record::SIZE);
        let (commitment, witness) = extra.split_at(RecordCommitment::SIZE);

        let record = <&[u8; Record::SIZE]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let commitment = <&[u8; RecordCommitment::SIZE]>::try_from(commitment)
            .expect("Slice of memory has correct length; qed");
        let witness = <&[u8; RecordWitness::SIZE]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let record = unsafe { mem::transmute(record) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let commitment = unsafe { mem::transmute(commitment) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let witness = unsafe { mem::transmute(witness) };

        (record, commitment, witness)
    }

    /// Split piece into underlying mutable components.
    pub fn split_mut(&mut self) -> (&mut Record, &mut RecordCommitment, &mut RecordWitness) {
        let (record, extra) = self.0.split_at_mut(Record::SIZE);
        let (commitment, witness) = extra.split_at_mut(RecordCommitment::SIZE);

        let record = <&mut [u8; Record::SIZE]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let commitment = <&mut [u8; RecordCommitment::SIZE]>::try_from(commitment)
            .expect("Slice of memory has correct length; qed");
        let witness = <&mut [u8; RecordWitness::SIZE]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let record = unsafe { mem::transmute(record) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let commitment = unsafe { mem::transmute(commitment) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let witness = unsafe { mem::transmute(witness) };

        (record, commitment, witness)
    }

    /// Record contained within a piece.
    pub fn record(&self) -> &Record {
        self.split().0
    }

    /// Mutable record contained within a piece.
    pub fn record_mut(&mut self) -> &mut Record {
        self.split_mut().0
    }

    /// Commitment contained within a piece.
    pub fn commitment(&self) -> &RecordCommitment {
        self.split().1
    }

    /// Mutable commitment contained within a piece.
    pub fn commitment_mut(&mut self) -> &mut RecordCommitment {
        self.split_mut().1
    }

    /// Witness contained within a piece.
    pub fn witness(&self) -> &RecordWitness {
        self.split().2
    }

    /// Mutable witness contained within a piece.
    pub fn witness_mut(&mut self) -> &mut RecordWitness {
        self.split_mut().2
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
    pub fn new(piece_count: usize) -> Self {
        Self(vec![PieceArray::default(); piece_count])
    }

    /// Extract internal representation.
    pub fn into_inner(self) -> Vec<PieceArray> {
        self.0
    }

    /// Iterator over source pieces (even indices).
    pub fn source(&self) -> impl ExactSizeIterator<Item = &'_ PieceArray> + '_ {
        self.0.iter().step_by(2)
    }

    /// Mutable iterator over source pieces (even indices).
    pub fn source_mut(&mut self) -> impl ExactSizeIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.iter_mut().step_by(2)
    }

    /// Iterator over parity pieces (odd indices).
    pub fn parity(&self) -> impl ExactSizeIterator<Item = &'_ PieceArray> + '_ {
        self.0.iter().skip(1).step_by(2)
    }

    /// Mutable iterator over parity pieces (odd indices).
    pub fn parity_mut(&mut self) -> impl ExactSizeIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.iter_mut().skip(1).step_by(2)
    }
}

#[cfg(feature = "rayon")]
impl FlatPieces {
    /// Parallel iterator over source pieces (even indices).
    pub fn par_source(&self) -> impl IndexedParallelIterator<Item = &'_ PieceArray> + '_ {
        self.0.par_iter().step_by(2)
    }

    /// Mutable parallel iterator over source pieces (even indices).
    pub fn par_source_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.par_iter_mut().step_by(2)
    }

    /// Parallel iterator over parity pieces (odd indices).
    pub fn par_parity(&self) -> impl IndexedParallelIterator<Item = &'_ PieceArray> + '_ {
        self.0.par_iter().skip(1).step_by(2)
    }

    /// Mutable parallel iterator over parity pieces (odd indices).
    pub fn par_parity_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = &'_ mut PieceArray> + '_ {
        self.0.par_iter_mut().skip(1).step_by(2)
    }
}

impl From<PieceArray> for FlatPieces {
    fn from(value: PieceArray) -> Self {
        Self(vec![value])
    }
}

impl AsRef<[u8]> for FlatPieces {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let pieces: &[[u8; Piece::SIZE]] = unsafe { mem::transmute(self.0.as_slice()) };
        pieces.flatten()
    }
}

impl AsMut<[u8]> for FlatPieces {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let pieces: &mut [[u8; Piece::SIZE]] = unsafe { mem::transmute(self.0.as_mut_slice()) };
        pieces.flatten_mut()
    }
}
