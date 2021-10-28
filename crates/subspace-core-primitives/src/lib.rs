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

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::RuntimeDebug;

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

/// A piece of archival history in Subspace Network.
///
/// Internally piece contains a record and corresponding witness that together with [`RootBlock`] of
/// the segment this piece belongs to can be used to verify that a piece belongs to the actual
/// archival history of the blockchain.
pub type Piece = [u8; PIECE_SIZE];

/// Type of randomness.
pub type Randomness = [u8; RANDOMNESS_LENGTH];

/// Type of the commitment for a particular piece.
///
/// TODO: why not use `Commitment` directly?
pub type Tag = [u8; 8];

/// Salt used for creating commitment tags for pieces.
pub type Salt = [u8; 8];

/// Progress of an archived block.
#[derive(
    Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, RuntimeDebug,
)]
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
#[derive(
    Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, RuntimeDebug,
)]
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
#[derive(
    Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, RuntimeDebug,
)]
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
