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

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

/// Size of Sha2-256 hash output (in bytes)
pub const SHA256_HASH_SIZE: usize = 32;
/// Piece size in Subspace Network (in bytes)
pub const PIECE_SIZE: usize = 4096;

// TODO: Create new types out of these
/// Sha2-256 hash output
pub type Sha256Hash = [u8; SHA256_HASH_SIZE];
/// Piece size in Subspace Network
pub type Piece = [u8; PIECE_SIZE];

/// Last archived block
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct LastArchivedBlock {
    /// Block number
    pub number: u32,
    /// `None` if the block was archived fully or number of bytes otherwise
    pub bytes: Option<u32>,
}

/// Root block for a specific segment
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
#[serde(rename_all = "camelCase")]
pub enum RootBlock {
    /// V0 of the root block data structure
    #[codec(index = 0)]
    #[serde(rename_all = "camelCase")]
    V0 {
        /// Segment index
        segment_index: u64,
        /// Merkle tree root of all pieces within segment
        merkle_tree_root: Sha256Hash,
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
            RootBlock::V0 { segment_index, .. } => *segment_index,
        }
    }

    /// Merkle tree root of all pieces within segment
    pub fn merkle_tree_root(&self) -> Sha256Hash {
        match self {
            RootBlock::V0 {
                merkle_tree_root, ..
            } => *merkle_tree_root,
        }
    }

    /// Hash of the root block of the previous segment
    pub fn prev_root_block_hash(&self) -> Sha256Hash {
        match self {
            RootBlock::V0 {
                prev_root_block_hash,
                ..
            } => *prev_root_block_hash,
        }
    }

    /// Last archived block
    pub fn last_archived_block(&self) -> LastArchivedBlock {
        match self {
            RootBlock::V0 {
                last_archived_block,
                ..
            } => *last_archived_block,
        }
    }
}

/// Object stored inside of the block
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
#[serde(rename_all = "camelCase")]
pub enum BlockObject {
    /// V0 of object mapping data structure
    #[codec(index = 0)]
    V0 {
        /// 24-bit little-endian offset of the object
        offset: [u8; 3],
        /// 24-bit little-endian size of the object
        size: [u8; 3],
    },
}

impl BlockObject {
    /// Offset of the object (limited to 24-bit size internally)
    pub fn offset(&self) -> u32 {
        match self {
            BlockObject::V0 { offset, .. } => {
                u32::from_le_bytes([offset[0], offset[1], offset[2], 0])
            }
        }
    }

    /// Offset of the object (limited to 24-bit size internally)
    pub fn size(&self) -> u32 {
        match self {
            BlockObject::V0 { size, .. } => u32::from_le_bytes([size[0], size[1], size[2], 0]),
        }
    }
}

/// Mapping of objects stored inside of the block
#[derive(
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
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BlockObjectMapping {
    /// Objects stored inside of the block
    pub objects: Vec<BlockObject>,
}

/// Object stored inside of the block
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
#[serde(rename_all = "camelCase")]
pub enum PieceObject {
    /// V0 of object mapping data structure
    #[codec(index = 0)]
    V0 {
        /// Offset of the object
        offset: u16,
        /// 24-bit little-endian size of the object
        size: [u8; 3],
    },
}

impl PieceObject {
    /// Offset of the object
    pub fn offset(&self) -> u16 {
        match self {
            PieceObject::V0 { offset, .. } => *offset,
        }
    }

    /// Offset of the object (limited to 24-bit size internally)
    pub fn size(&self) -> u32 {
        match self {
            PieceObject::V0 { size, .. } => u32::from_le_bytes([size[0], size[1], size[2], 0]),
        }
    }
}

/// Mapping of objects stored inside of the piece
#[derive(
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
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PieceObjectMapping {
    /// Objects stored inside of the block
    pub objects: Vec<PieceObject>,
}
