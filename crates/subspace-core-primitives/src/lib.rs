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
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(feature = "std", warn(missing_debug_implementations))]

#[cfg(test)]
mod tests;

pub mod crypto;
pub mod objects;

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
pub use construct_uint::U256;
use core::convert::AsRef;
use core::ops::{Deref, DerefMut};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// Size of Sha2-256 hash output (in bytes)
pub const SHA256_HASH_SIZE: usize = 32;

/// Byte size of a piece in Subspace Network, 4KiB.
///
/// This can not changed after the network is launched.
pub const PIECE_SIZE: usize = 4096;

/// Byte length of a randomness type.
pub const RANDOMNESS_LENGTH: usize = 32;

/// Sha2-256 hash output
pub type Sha256Hash = [u8; SHA256_HASH_SIZE];

/// Type of randomness.
pub type Randomness = [u8; RANDOMNESS_LENGTH];

/// Size of `Tag` in bytes.
pub const TAG_SIZE: usize = 8;

/// Type of the commitment for a particular piece.
pub type Tag = [u8; TAG_SIZE];

/// Size of `Tag` in bytes.
pub const SALT_SIZE: usize = 8;

/// Salt used for creating commitment tags for pieces.
pub type Salt = [u8; SALT_SIZE];

/// Block number in Subspace network.
pub type BlockNumber = u32;

/// Slot number in Subspace network.
pub type SlotNumber = u64;

/// Length of public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

const REWARD_SIGNATURE_LENGTH: usize = 64;
const VRF_OUTPUT_LENGTH: usize = 32;
const VRF_PROOF_LENGTH: usize = 64;

/// Context used in the randomness derivation
pub const RANDOMNESS_CONTEXT: &[u8] = b"subspace_randomness";

/// A Ristretto Schnorr public key as bytes produced by `schnorrkel` crate.
#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct PublicKey(
    #[cfg_attr(feature = "std", serde(with = "hex::serde"))] [u8; PUBLIC_KEY_LENGTH],
);

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLIC_KEY_LENGTH] {
    fn from(signature: PublicKey) -> Self {
        signature.0
    }
}

impl Deref for PublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Ristretto Schnorr signature as bytes produced by `schnorrkel` crate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct RewardSignature(
    #[cfg_attr(feature = "std", serde(with = "serde_arrays"))] [u8; REWARD_SIGNATURE_LENGTH],
);

impl From<[u8; REWARD_SIGNATURE_LENGTH]> for RewardSignature {
    fn from(bytes: [u8; REWARD_SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<RewardSignature> for [u8; REWARD_SIGNATURE_LENGTH] {
    fn from(signature: RewardSignature) -> Self {
        signature.0
    }
}

impl Deref for RewardSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for RewardSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// VRF signature output and proof as produced by `schnorrkel` crate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct TagSignature {
    /// VRF output bytes.
    pub output: [u8; VRF_OUTPUT_LENGTH],
    /// VRF proof bytes.
    #[cfg_attr(feature = "std", serde(with = "serde_arrays"))]
    pub proof: [u8; VRF_PROOF_LENGTH],
}

/// VRF signature output and proof as produced by `schnorrkel` crate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct LocalChallenge {
    /// VRF output bytes.
    pub output: [u8; VRF_OUTPUT_LENGTH],
    /// VRF proof bytes.
    #[cfg_attr(feature = "std", serde(with = "serde_arrays"))]
    pub proof: [u8; VRF_PROOF_LENGTH],
}

/// A piece of archival history in Subspace Network.
///
/// Internally piece contains a record and corresponding witness that together with [`RootBlock`] of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Piece(Vec<u8>);

impl Default for Piece {
    fn default() -> Self {
        Self(vec![0u8; PIECE_SIZE])
    }
}

impl From<[u8; PIECE_SIZE]> for Piece {
    fn from(piece: [u8; PIECE_SIZE]) -> Self {
        Self(piece.to_vec())
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
            Err("Wrong piece size, expected: 4096")
        } else {
            Ok(Self(slice.to_vec()))
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

/// Flat representation of multiple pieces concatenated for higher efficient for processing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct FlatPieces(Vec<u8>);

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
    pub fn as_pieces(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.0.chunks_exact(PIECE_SIZE)
    }

    /// Iterator over individual pieces as byte slices.
    pub fn as_pieces_mut(&mut self) -> impl ExactSizeIterator<Item = &mut [u8]> {
        self.0.chunks_exact_mut(PIECE_SIZE)
    }
}

impl From<Piece> for FlatPieces {
    fn from(Piece(piece): Piece) -> Self {
        Self(piece)
    }
}

// TODO: Remove once we no longer use `unzip` in farmer and get `(Vec<PieceIndex>, FlatPieces)`
// after requesting sequential pieces.
impl Extend<Piece> for FlatPieces {
    fn extend<T: IntoIterator<Item = Piece>>(&mut self, iter: T) {
        self.0
            .extend(iter.into_iter().flat_map(|piece| piece.0.into_iter()))
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

/// Progress of an archived block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
pub enum RootBlock {
    /// V0 of the root block data structure
    #[codec(index = 0)]
    #[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
    V0 {
        /// Segment index
        segment_index: u64,
        /// Merkle root of the records in a segment.
        records_root: Sha256Hash,
        /// Hash of the root block of the previous segment
        prev_root_block_hash: Sha256Hash,
        /// Last archived block
        last_archived_block: LastArchivedBlock,
    },
}

impl RootBlock {
    /// Hash of the whole root block
    pub fn hash(&self) -> Sha256Hash {
        crypto::sha256_hash(&self.encode())
    }

    /// Segment index
    pub fn segment_index(&self) -> u64 {
        match self {
            Self::V0 { segment_index, .. } => *segment_index,
        }
    }

    /// Merkle root of the records in a segment.
    pub fn records_root(&self) -> Sha256Hash {
        match self {
            Self::V0 { records_root, .. } => *records_root,
        }
    }

    /// Hash of the root block of the previous segment
    pub fn prev_root_block_hash(&self) -> Sha256Hash {
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

/// Hash of `PieceIndex`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PieceIndexHash(pub Sha256Hash);

impl AsRef<[u8]> for PieceIndexHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PieceIndexHash {
    /// Constructs `PieceIndexHash` from `PieceIndex`
    pub fn from_index(index: PieceIndex) -> Self {
        Self(crypto::sha256_hash(&index.to_le_bytes()))
    }
}

// TODO: Versioned solution enum
/// Farmer solution for slot challenge.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
pub struct Solution<PublicKey, RewardAddress> {
    /// Public key of the farmer that created the solution
    pub public_key: PublicKey,
    /// Address for receiving block reward
    pub reward_address: RewardAddress,
    /// Index of encoded piece
    pub piece_index: PieceIndex,
    /// Encoding
    pub encoding: Piece,
    /// VRF signature of the tag
    pub tag_signature: TagSignature,
    /// Local challenge derived from global challenge using farmer's identity.
    pub local_challenge: LocalChallenge,
    /// Tag (hmac of encoding and salt)
    pub tag: Tag,
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
            piece_index,
            encoding,
            tag_signature,
            local_challenge,
            tag,
        } = self;
        Solution {
            public_key,
            reward_address: Into::<T>::into(reward_address).into(),
            piece_index,
            encoding,
            tag_signature,
            local_challenge,
            tag,
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
            piece_index: 0,
            encoding: Piece::default(),
            tag_signature: TagSignature {
                output: [0; 32],
                proof: [0; 64],
            },
            local_challenge: LocalChallenge {
                output: [0; 32],
                proof: [0; 64],
            },
            tag: Tag::default(),
        }
    }
}

/// Bidirectional distance metric implemented on top of subtraction
pub fn bidirectional_distance<T: num_traits::WrappingSub + Ord>(a: &T, b: &T) -> T {
    let diff = a.wrapping_sub(b);
    let diff2 = b.wrapping_sub(a);
    // Find smaller diff between 2 directions.
    diff.min(diff2)
}

#[allow(clippy::assign_op_pattern, clippy::ptr_offset_with_cast)]
mod construct_uint {
    //! This module is needed to scope clippy allows

    use super::{bidirectional_distance, PieceIndexHash};
    use num_traits::{WrappingAdd, WrappingSub};

    uint::construct_uint! {
        pub struct U256(4);
    }

    impl U256 {
        /// Calculates the distance metric between piece index hash and farmer address.
        pub fn distance(PieceIndexHash(piece): &PieceIndexHash, address: &[u8]) -> U256 {
            let piece = Self::from_big_endian(piece);
            let address = Self::from_big_endian(address);
            bidirectional_distance(&piece, &address)
        }

        /// Convert piece distance to big endian bytes
        pub fn to_bytes(self) -> [u8; 32] {
            self.into()
        }

        /// The middle of the piece distance field.
        /// The analogue of `0b1000_0000` for `u8`.
        pub const MIDDLE: Self = {
            // TODO: This assumes that numbers are stored little endian,
            //  should be replaced with just `Self::MAX / 2`, but it is not `const fn` in Rust yet.
            Self([u64::MAX, u64::MAX, u64::MAX, u64::MAX / 2])
        };
    }

    impl WrappingAdd for U256 {
        fn wrapping_add(&self, other: &Self) -> Self {
            self.overflowing_add(*other).0
        }
    }

    impl WrappingSub for U256 {
        fn wrapping_sub(&self, other: &Self) -> Self {
            self.overflowing_sub(*other).0
        }
    }

    impl From<PieceIndexHash> for U256 {
        fn from(PieceIndexHash(hash): PieceIndexHash) -> Self {
            hash.into()
        }
    }

    impl From<U256> for PieceIndexHash {
        fn from(distance: U256) -> Self {
            Self(distance.into())
        }
    }
}
