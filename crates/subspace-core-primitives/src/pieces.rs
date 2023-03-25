#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::array::TryFromSliceError;
use core::mem;
use core::ops::{Deref, DerefMut};
use derive_more::{AsMut, AsRef, Deref, DerefMut};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Byte size of a piece in Subspace Network, ~32KiB (a bit less due to requirement of being a
/// multiple of 2 bytes for erasure coding as well as multiple of 31 bytes in order to fit into
/// BLS12-381 scalar safely).
///
/// TODO: Requirement of being a multiple of 2 bytes may go away eventually as we switch erasure
///  coding implementation, so we might be able to bump it by one field element in size.
///
/// This can not changed after the network is launched.
pub const PIECE_SIZE: usize = 31_744;
/// Size of witness for a segment record (in bytes).
pub const WITNESS_SIZE: u32 = 48;
/// Size of a segment record given the global piece size (in bytes).
pub const RECORD_SIZE: u32 = PIECE_SIZE as u32 - WITNESS_SIZE;

/// Record contained within a piece.
///
/// NOTE: This is a stack-allocated data structure and can cause stack overflow!
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct Record([u8; RECORD_SIZE as usize]);

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

/// Record witness contained within a piece.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref, DerefMut)]
#[repr(transparent)]
pub struct RecordWitness([u8; WITNESS_SIZE as usize]);

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

/// A piece of archival history in Subspace Network.
///
/// This version is allocated on the heap, for stack-allocated piece see [`PieceArray`].
///
/// Internally piece contains a record and corresponding witness that together with records root of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Piece(Box<PieceArray>);

impl From<Piece> for Vec<u8> {
    fn from(piece: Piece) -> Self {
        piece.0.to_vec()
    }
}
impl TryFrom<&[u8]> for Piece {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; PIECE_SIZE]>::try_from(slice).map(|bytes| Piece(Box::new(PieceArray(bytes))))
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

/// A piece of archival history in Subspace Network.
///
/// This version is allocated on the stack, for heap-allocated piece see [`Piece`].
///
/// Internally piece contains a record and corresponding witness that together with records root of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
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
pub struct PieceArray([u8; PIECE_SIZE]);

impl Default for PieceArray {
    fn default() -> Self {
        Self([0u8; PIECE_SIZE])
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
    pub fn split(&self) -> (&Record, &RecordWitness) {
        let (record, witness) = self.0.split_at(RECORD_SIZE as usize);

        let record = <&[u8; RECORD_SIZE as usize]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let witness = <&[u8; WITNESS_SIZE as usize]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let record = unsafe { mem::transmute(record) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let witness = unsafe { mem::transmute(witness) };

        (record, witness)
    }

    /// Split piece into underlying mutable components.
    pub fn split_mut(&mut self) -> (&mut Record, &mut RecordWitness) {
        let (record, witness) = self.0.split_at_mut(RECORD_SIZE as usize);

        let record = <&mut [u8; RECORD_SIZE as usize]>::try_from(record)
            .expect("Slice of memory has correct length; qed");
        let witness = <&mut [u8; WITNESS_SIZE as usize]>::try_from(witness)
            .expect("Slice of memory has correct length; qed");

        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let record = unsafe { mem::transmute(record) };
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let witness = unsafe { mem::transmute(witness) };

        (record, witness)
    }

    /// Record contained within a piece.
    pub fn record(&self) -> &Record {
        self.split().0
    }

    /// Mutable record contained within a piece.
    pub fn record_mut(&mut self) -> &mut Record {
        self.split_mut().0
    }

    /// Witness contained within a piece.
    pub fn witness(&self) -> &RecordWitness {
        self.split().1
    }

    /// Mutable witness contained within a piece.
    pub fn witness_mut(&mut self) -> &mut RecordWitness {
        self.split_mut().1
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
}

impl From<PieceArray> for FlatPieces {
    fn from(value: PieceArray) -> Self {
        Self(vec![value])
    }
}

impl AsRef<[u8]> for FlatPieces {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let pieces: &[[u8; PIECE_SIZE]] = unsafe { mem::transmute(self.0.as_slice()) };
        pieces.flatten()
    }
}

impl AsMut<[u8]> for FlatPieces {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: Same memory layout due to `#[repr(transparent)]`
        let pieces: &mut [[u8; PIECE_SIZE]] = unsafe { mem::transmute(self.0.as_mut_slice()) };
        pieces.flatten_mut()
    }
}
