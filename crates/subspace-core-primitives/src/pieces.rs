use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use derive_more::{Deref, DerefMut};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

/// Reference to record sized slice of memory.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct RecordRef<'a>(&'a [u8]);

impl<'a> AsRef<[u8]> for RecordRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// Mutable reference to record sized slice of memory.
#[derive(Debug, Eq, PartialEq, Deref)]
pub struct RecordRefMut<'a>(&'a mut [u8]);

impl<'a> AsRef<[u8]> for RecordRefMut<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> AsMut<[u8]> for RecordRefMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

/// Reference to witness sized slice of memory.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct WitnessRef<'a>(&'a [u8; WITNESS_SIZE as usize]);

impl<'a> AsRef<[u8]> for WitnessRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// Mutable reference to witness sized slice of memory.
#[derive(Debug, Eq, PartialEq, Deref)]
pub struct WitnessRefMut<'a>(&'a mut [u8; WITNESS_SIZE as usize]);

impl<'a> AsRef<[u8]> for WitnessRefMut<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> AsMut<[u8]> for WitnessRefMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

/// A piece of archival history in Subspace Network.
///
/// Internally piece contains a record and corresponding witness that together with [`RootBlock`] of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Piece(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] Vec<u8>);

impl Default for Piece {
    fn default() -> Self {
        Self(vec![0u8; PIECE_SIZE])
    }
}

impl From<Piece> for Vec<u8> {
    fn from(piece: Piece) -> Self {
        piece.0
    }
}

impl TryFrom<&[u8]> for Piece {
    type Error = &'static str;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != PIECE_SIZE {
            Err("Wrong piece size, expected: 32768")
        } else {
            Ok(Self(slice.to_vec()))
        }
    }
}

impl TryFrom<Vec<u8>> for Piece {
    type Error = &'static str;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        if vec.len() != PIECE_SIZE {
            Err("Wrong piece size, expected: 32768")
        } else {
            Ok(Self(vec))
        }
    }
}

impl Deref for Piece {
    type Target = [u8];
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
        &self.0
    }
}

impl AsMut<[u8]> for Piece {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Piece {
    /// Get piece reference.
    pub fn as_ref(&self) -> PieceRef<'_> {
        PieceRef(
            self.0
                .as_slice()
                .try_into()
                .expect("Piece has correct size; qed"),
        )
    }

    /// Get mutable piece reference.
    pub fn as_mut(&mut self) -> PieceRefMut<'_> {
        PieceRefMut(
            self.0
                .as_mut_slice()
                .try_into()
                .expect("Piece has correct size; qed"),
        )
    }

    /// Split piece into underlying components.
    pub fn split(&self) -> (RecordRef<'_>, WitnessRef<'_>) {
        let (record, witness) = self.0.split_at(RECORD_SIZE as usize);
        (
            RecordRef(record),
            WitnessRef(
                witness
                    .try_into()
                    .expect("Witness withing a piece has correct size; qed"),
            ),
        )
    }

    /// Split piece into underlying mutable components.
    pub fn split_mut(&mut self) -> (RecordRefMut<'_>, WitnessRefMut<'_>) {
        let (record, witness) = self.0.split_at_mut(RECORD_SIZE as usize);
        (
            RecordRefMut(record),
            WitnessRefMut(
                witness
                    .try_into()
                    .expect("Witness withing a piece has correct size; qed"),
            ),
        )
    }

    /// Record contained within a piece.
    pub fn record(&self) -> RecordRef<'_> {
        self.split().0
    }

    /// Mutable record contained within a piece.
    pub fn record_mut(&mut self) -> RecordRefMut<'_> {
        self.split_mut().0
    }

    /// Witness contained within a piece.
    pub fn witness(&self) -> WitnessRef<'_> {
        self.split().1
    }

    /// Mutable witness contained within a piece.
    pub fn witness_mut(&mut self) -> WitnessRefMut<'_> {
        self.split_mut().1
    }
}

/// Reference to piece sized slice of memory.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deref)]
pub struct PieceRef<'a>(&'a [u8; PIECE_SIZE]);

impl<'a> AsRef<[u8]> for PieceRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> From<&'a Piece> for PieceRef<'a> {
    fn from(value: &'a Piece) -> Self {
        PieceRef(
            value
                .0
                .as_slice()
                .try_into()
                .expect("Piece has correct size; qed"),
        )
    }
}

impl From<PieceRef<'_>> for Piece {
    fn from(value: PieceRef<'_>) -> Self {
        Piece(value.0.to_vec())
    }
}

impl<'a> PieceRef<'a> {
    /// Split piece into underlying components.
    pub fn split(&'a self) -> (RecordRef<'a>, WitnessRef<'a>) {
        let (record, witness) = self.0.split_at(RECORD_SIZE as usize);
        (
            RecordRef(record),
            WitnessRef(
                witness
                    .try_into()
                    .expect("Witness withing a piece has correct size; qed"),
            ),
        )
    }

    /// Record contained within a piece.
    pub fn record(&'a self) -> RecordRef<'a> {
        self.split().0
    }

    /// Witness contained within a piece.
    pub fn witness(&'a self) -> WitnessRef<'a> {
        self.split().1
    }
}

/// Mutable reference to piece sized slice of memory.
#[derive(Debug, Eq, PartialEq, Deref, DerefMut)]
pub struct PieceRefMut<'a>(&'a mut [u8; PIECE_SIZE]);

impl<'a> AsRef<[u8]> for PieceRefMut<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> AsMut<[u8]> for PieceRefMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl<'a> From<&'a mut Piece> for PieceRefMut<'a> {
    fn from(value: &'a mut Piece) -> Self {
        PieceRefMut(
            value
                .0
                .as_mut_slice()
                .try_into()
                .expect("Piece has correct size; qed"),
        )
    }
}

impl<'a> From<PieceRefMut<'a>> for PieceRef<'a> {
    fn from(value: PieceRefMut<'a>) -> Self {
        PieceRef(value.0)
    }
}

impl<'a> From<&'a PieceRefMut<'a>> for PieceRef<'a> {
    fn from(value: &'a PieceRefMut<'a>) -> Self {
        PieceRef(value.0)
    }
}

impl From<PieceRefMut<'_>> for Piece {
    fn from(value: PieceRefMut<'_>) -> Self {
        Piece(value.0.to_vec())
    }
}

impl<'a> PieceRefMut<'a> {
    /// Split piece into underlying components.
    pub fn split(&'a self) -> (RecordRef<'a>, WitnessRef<'a>) {
        let (record, witness) = self.0.split_at(RECORD_SIZE as usize);
        (
            RecordRef(record),
            WitnessRef(
                witness
                    .try_into()
                    .expect("Witness withing a piece has correct size; qed"),
            ),
        )
    }

    /// Split piece into underlying mutable components.
    pub fn split_mut(&'a mut self) -> (RecordRefMut<'a>, WitnessRefMut<'a>) {
        let (record, witness) = self.0.split_at_mut(RECORD_SIZE as usize);
        (
            RecordRefMut(record),
            WitnessRefMut(
                witness
                    .try_into()
                    .expect("Witness withing a piece has correct size; qed"),
            ),
        )
    }

    /// Record contained within a piece.
    pub fn record(&'a self) -> RecordRef<'a> {
        self.split().0
    }

    /// Mutable record contained within a piece.
    pub fn record_mut(&'a mut self) -> RecordRefMut<'a> {
        self.split_mut().0
    }

    /// Witness contained within a piece.
    pub fn witness(&'a self) -> WitnessRef<'a> {
        self.split().1
    }

    /// Mutable witness contained within a piece.
    pub fn witness_mut(&'a mut self) -> WitnessRefMut<'a> {
        self.split_mut().1
    }
}

/// Flat representation of multiple pieces concatenated for higher efficient for processing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlatPieces(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] Vec<u8>);

// TODO: Introduce `PieceRef` and `PieceRefMut` that can be converted into `Piece` without
//  `.expect()` and maybe add convenience methods for accessing record and witness parts of it
impl FlatPieces {
    /// Allocate `FlatPieces` that will hold `piece_count` pieces filled with zeroes.
    pub fn new(piece_count: usize) -> Self {
        Self(vec![0u8; piece_count * PIECE_SIZE])
    }

    /// Number of pieces contained.
    pub fn count(&self) -> usize {
        self.0.len() / PIECE_SIZE
    }

    /// Extract internal flat representation of bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Iterator over individual pieces as byte slices.
    pub fn as_pieces(&self) -> impl ExactSizeIterator<Item = PieceRef<'_>> {
        self.0
            .chunks_exact(PIECE_SIZE)
            .map(|piece| PieceRef(piece.try_into().expect("Piece has correct size; qed")))
    }

    /// Iterator over individual pieces as byte slices.
    pub fn as_pieces_mut(&mut self) -> impl ExactSizeIterator<Item = PieceRefMut<'_>> {
        self.0
            .chunks_exact_mut(PIECE_SIZE)
            .map(|piece| PieceRefMut(piece.try_into().expect("Piece has correct size; qed")))
    }
}

impl From<Piece> for FlatPieces {
    fn from(Piece(piece): Piece) -> Self {
        Self(piece)
    }
}

impl TryFrom<Vec<u8>> for FlatPieces {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() % PIECE_SIZE != 0 {
            return Err(value);
        }

        Ok(Self(value))
    }
}

impl Deref for FlatPieces {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FlatPieces {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for FlatPieces {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for FlatPieces {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
