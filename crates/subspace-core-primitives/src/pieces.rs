#[cfg(feature = "serde")]
mod serde;

use crate::crypto::Scalar;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use core::mem;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use derive_more::{AsMut, AsRef, Deref, DerefMut};
use parity_scale_codec::{Decode, Encode, Input, MaxEncodedLen};
use scale_info::TypeInfo;

// TODO: Remove once we redefine it through raw record
/// Byte size of a piece in Subspace Network, ~32KiB (a bit less due to requirement of being a
/// multiple of 2 bytes for erasure coding as well as multiple of 31 bytes in order to fit into
/// BLS12-381 scalar safely).
///
/// TODO: Requirement of being a multiple of 2 bytes may go away eventually as we switch erasure
///  coding implementation, so we might be able to bump it by one field element in size.
///
/// This can not changed after the network is launched.
const PIECE_SIZE: usize = 31_744;
// TODO: Remove once we re-define it through raw record instead
/// Size of a segment record given the global piece size (in bytes), is guaranteed to be multiple
/// of [`Scalar::FULL_BYTES`].
const RECORD_SIZE: usize = Piece::SIZE - RecordCommitment::SIZE - RecordWitness::SIZE;

/// Raw record contained within recorded history segment before archiving is applied.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RawRecord([[u8; Scalar::SAFE_BYTES]; Self::SIZE / Scalar::SAFE_BYTES]);

impl Default for RawRecord {
    fn default() -> Self {
        Self([Default::default(); Self::SIZE / Scalar::SAFE_BYTES])
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
    /// Size of raw record in bytes, is guaranteed to be a multiple of [`Scalar::SAFE_BYTES`].
    pub const SIZE: usize = Record::SIZE / Scalar::FULL_BYTES * Scalar::SAFE_BYTES;
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
    /// It includes erasure coded [`PieceArray`]s (both source and parity) that are composed from
    /// [`Record`]s together with corresponding commitments and witnesses.
    pub const SIZE: usize = Piece::SIZE * Self::NUM_PIECES;
}

/// Record contained within a piece.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct Record([u8; Self::SIZE]);

impl AsRef<[u8]> for Record {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Record {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Record {
    /// Size of a segment record given the global piece size (in bytes) after erasure coding
    /// [`RawRecord`], is guaranteed to be a multiple of [`Scalar::FULL_BYTES`].
    pub const SIZE: usize = RECORD_SIZE;

    /// Get a stream of arrays, each containing safe scalar bytes.
    ///
    /// Only useful for source records since only those contain raw record bytes that fit into safe
    /// scalar bytes and the rest is zero bytes padding.
    pub fn safe_scalar_arrays(
        &self,
    ) -> impl ExactSizeIterator<Item = &'_ [u8; Scalar::SAFE_BYTES]> + '_ {
        self.full_scalar_arrays().map(|bytes| {
            bytes
                .array_chunks::<{ Scalar::SAFE_BYTES }>()
                .next()
                .expect(
                    "Safe bytes are smaller length as safe bytes, hence first element always \
                    exists; qed",
                )
        })
    }

    /// Get a stream of mutable arrays, each containing safe scalar bytes.
    ///
    /// Only useful for source records since only those contain raw record bytes that fit into safe
    /// scalar bytes and the rest is zero bytes padding.
    pub fn safe_scalar_arrays_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = &'_ mut [u8; Scalar::SAFE_BYTES]> + '_ {
        self.full_scalar_arrays_mut().map(|bytes| {
            bytes
                .array_chunks_mut::<{ Scalar::SAFE_BYTES }>()
                .next()
                .expect(
                    "Safe bytes are smaller length as safe bytes, hence first element always \
                    exists; qed",
                )
        })
    }

    /// Get a stream of arrays, each containing scalar bytes.
    pub fn full_scalar_arrays(
        &self,
    ) -> impl ExactSizeIterator<Item = &'_ [u8; Scalar::FULL_BYTES]> + '_ {
        self.0.array_chunks::<{ Scalar::FULL_BYTES }>()
    }

    /// Get a stream of mutable arrays, each containing scalar bytes.
    pub fn full_scalar_arrays_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = &'_ mut [u8; Scalar::FULL_BYTES]> + '_ {
        self.0.array_chunks_mut::<{ Scalar::FULL_BYTES }>()
    }
}

/// Record commitment contained within a piece.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RecordCommitment([u8; Self::SIZE]);

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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RecordWitness([u8; Self::SIZE]);

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
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Piece(Box<PieceArray>);

// TODO: Manual implementation due to https://github.com/paritytech/parity-scale-codec/issues/419,
//  can be replaced with derive once fixed upstream version is released
impl Decode for Piece {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let piece = parity_scale_codec::decode_vec_with_len::<u8, _>(input, Self::SIZE)
            .map_err(|error| error.chain("Could not decode `Piece.0`"))?;
        let mut piece = ManuallyDrop::new(piece);
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
    pub const SIZE: usize = PIECE_SIZE;
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

impl From<&PieceArray> for Piece {
    fn from(value: &PieceArray) -> Self {
        Piece(Box::new(*value))
    }
}

impl From<PieceArray> for Piece {
    fn from(value: PieceArray) -> Self {
        Piece(Box::new(value))
    }
}

impl PieceArray {
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
