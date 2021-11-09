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

pub mod crypto;
pub mod objects;

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

/// Salt used for creating commitment tags for pieces.
pub type Salt = [u8; TAG_SIZE];

const PUBLIC_KEY_LENGTH: usize = 32;

/// A Ristretto Schnorr public key as bytes produced by `schnorrkel` crate.
#[derive(Default, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

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

const SIGNATURE_LENGTH: usize = 64;

/// A Ristretto Schnorr signature as bytes produced by `schnorrkel` crate.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Signature(
    #[cfg_attr(feature = "std", serde(with = "serde_arrays"))] [u8; SIGNATURE_LENGTH],
);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; SIGNATURE_LENGTH])
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {
    fn from(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<Signature> for [u8; SIGNATURE_LENGTH] {
    fn from(signature: Signature) -> Self {
        signature.0
    }
}

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Ristretto Schnorr signature as bytes produced by `schnorrkel` crate.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct LocalChallenge(
    #[cfg_attr(feature = "std", serde(with = "serde_arrays"))] [u8; SIGNATURE_LENGTH],
);

impl Default for LocalChallenge {
    fn default() -> Self {
        Self([0u8; SIGNATURE_LENGTH])
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for LocalChallenge {
    fn from(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<LocalChallenge> for [u8; SIGNATURE_LENGTH] {
    fn from(signature: LocalChallenge) -> Self {
        signature.0
    }
}

impl Deref for LocalChallenge {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for LocalChallenge {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl LocalChallenge {
    /// Derive tags search target from local challenge.
    pub fn derive_target(&self) -> Tag {
        crypto::sha256_hash(&self.0)[..TAG_SIZE]
            .try_into()
            .expect("Signature is always bigger than tag; qed")
    }
}

/// A piece of archival history in Subspace Network.
///
/// Internally piece contains a record and corresponding witness that together with [`RootBlock`] of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
pub struct Piece(#[cfg_attr(feature = "std", serde(with = "serde_arrays"))] [u8; PIECE_SIZE]);

impl Default for Piece {
    fn default() -> Self {
        Self([0u8; PIECE_SIZE])
    }
}

impl From<[u8; PIECE_SIZE]> for Piece {
    fn from(inner: [u8; PIECE_SIZE]) -> Self {
        Self(inner)
    }
}

impl TryFrom<&[u8]> for Piece {
    type Error = &'static str;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        slice
            .try_into()
            .map(Self)
            .map_err(|_| "Wrong piece size, expected: 4096")
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

/// Progress of an archived block.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
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
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
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
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
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
