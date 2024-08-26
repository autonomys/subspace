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

//! Data structures related to objects (useful data) stored on Subspace Network.
//!
//! Mappings provided are of 3 kinds:
//! * for objects within a block
//! * for objects within a piece
//! * for global objects in the global history of the blockchain

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{Blake3Hash, PieceIndex};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::default::Default;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Object stored inside of the block
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum BlockObject {
    /// V0 of object mapping data structure
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Object hash
        hash: Blake3Hash,
        /// Offset of object in the encoded block.
        offset: u32,
    },
}

impl BlockObject {
    /// Object hash
    pub fn hash(&self) -> Blake3Hash {
        match self {
            Self::V0 { hash, .. } => *hash,
        }
    }

    /// Offset of object in the encoded block.
    pub fn offset(&self) -> u32 {
        match self {
            Self::V0 { offset, .. } => *offset,
        }
    }

    /// Sets new offset.
    pub fn set_offset(&mut self, new_offset: u32) {
        match self {
            Self::V0 { offset, .. } => {
                *offset = new_offset;
            }
        }
    }
}

/// Mapping of objects stored inside of the block
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BlockObjectMapping {
    /// Objects stored inside of the block
    pub objects: Vec<BlockObject>,
}

/// Object stored inside of the piece
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum PieceObject {
    /// V0 of object mapping data structure
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Object hash
        hash: Blake3Hash,
        // TODO: This is a raw record offset, not a regular one
        /// Offset of the object in that piece
        offset: u32,
    },
}

impl PieceObject {
    /// Object hash
    pub fn hash(&self) -> Blake3Hash {
        match self {
            Self::V0 { hash, .. } => *hash,
        }
    }

    /// Offset of the object
    pub fn offset(&self) -> u32 {
        match self {
            Self::V0 { offset, .. } => *offset,
        }
    }
}

/// Mapping of objects stored inside of the piece
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PieceObjectMapping {
    /// Objects stored inside of the piece
    pub objects: Vec<PieceObject>,
}

/// Object stored in the history of the blockchain
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GlobalObject {
    /// Object hash.
    /// We order by hash, so object hash lookups can be performed efficiently.
    hash: Blake3Hash,
    /// Piece index where object is contained (at least its beginning, might not fit fully)
    piece_index: PieceIndex,
    /// Offset of the object in that piece
    offset: u32,
}

impl GlobalObject {
    /// Returns a newly created GlobalObject from its fields.
    pub fn new(hash: Blake3Hash, piece_index: PieceIndex, offset: u32) -> Self {
        Self {
            hash,
            piece_index,
            offset,
        }
    }

    /// Object hash
    pub fn hash(&self) -> Blake3Hash {
        self.hash
    }

    /// Piece index where object is contained (at least its beginning, might not fit fully)
    pub fn piece_index(&self) -> PieceIndex {
        self.piece_index
    }

    /// Offset of the object
    pub fn offset(&self) -> u32 {
        self.offset
    }
}

/// Mapping of objects stored in the history of the blockchain
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(rename_all_fields = "camelCase"))]
pub enum GlobalObjectMapping {
    /// V0 of object mapping data structure.
    #[codec(index = 0)]
    V0 {
        /// Objects stored in the history of the blockchain.
        /// Mappings are ordered by the piece index and offset of the first GlobalObject in objects.
        objects: Vec<GlobalObject>,
    },
}

impl Default for GlobalObjectMapping {
    fn default() -> Self {
        Self::V0 {
            objects: Vec::new(),
        }
    }
}

impl GlobalObjectMapping {
    /// Returns a newly created GlobalObjectMapping from a list of object mappings
    #[inline]
    pub fn from_objects(objects: impl IntoIterator<Item = GlobalObject>) -> Self {
        Self::V0 {
            objects: objects.into_iter().collect(),
        }
    }

    /// Returns the object mappings
    pub fn objects(&self) -> &[GlobalObject] {
        match self {
            Self::V0 { objects, .. } => objects,
        }
    }
}
