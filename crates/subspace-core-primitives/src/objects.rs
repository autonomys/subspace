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

use crate::{Blake3Hash, Blake3HashHex, PieceIndex};
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
    // TODO: move the enum and accessor method to BlockObjectMapping
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Object hash
        #[cfg_attr(feature = "serde", serde(with = "hex"))]
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
    // TODO: move the enum and accessor method to PieceObjectMapping
    #[codec(index = 0)]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    V0 {
        /// Object hash
        #[cfg_attr(feature = "serde", serde(with = "hex"))]
        hash: Blake3Hash,
        /// Raw record offset of the object in that piece, for use with `Record::to_raw_record_bytes`
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

    /// Raw record offset of the object in that piece, for use with `Record::to_raw_record_bytes`
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
#[cfg_attr(
    feature = "serde",
    serde(from = "CompactGlobalObject", into = "CompactGlobalObject")
)]
pub struct GlobalObject {
    /// Object hash.
    /// We order by hash, so object hash lookups can be performed efficiently.
    pub hash: Blake3HashHex,
    /// Piece index where object is contained (at least its beginning, might not fit fully)
    pub piece_index: PieceIndex,
    /// Raw record offset of the object in that piece, for use with `Record::to_raw_record_bytes`
    pub offset: u32,
}

impl From<CompactGlobalObject> for GlobalObject {
    fn from(object: CompactGlobalObject) -> Self {
        Self {
            hash: object.0,
            piece_index: object.1,
            offset: object.2,
        }
    }
}

impl From<GlobalObject> for CompactGlobalObject {
    fn from(object: GlobalObject) -> Self {
        Self(object.hash, object.piece_index, object.offset)
    }
}

impl GlobalObject {
    /// Returns a newly created GlobalObject from a piece index and object.
    pub fn new(piece_index: PieceIndex, piece_object: &PieceObject) -> Self {
        Self {
            hash: piece_object.hash().into(),
            piece_index,
            offset: piece_object.offset(),
        }
    }
}

/// Space-saving serialization of an object stored in the history of the blockchain
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactGlobalObject(Blake3HashHex, PieceIndex, u32);

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
