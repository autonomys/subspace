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
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

pub mod crypto;

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Size of Sha2-256 hash output (in bytes)
pub const SHA256_HASH_SIZE: usize = 32;
/// Piece size in Subspace Network (in bytes)
pub const PIECE_SIZE: usize = 4096;

// TODO: Create new types out of these
/// Sha2-256 hash output
pub type Sha256Hash = [u8; SHA256_HASH_SIZE];
/// Piece size in Subspace Network
pub type Piece = [u8; PIECE_SIZE];

/// Root block for a specific segment
#[derive(Copy, Clone, PartialEq, Eq, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum RootBlock {
    /// V0 of the root block data structure
    #[codec(index = 0)]
    V0 {
        /// Segment index
        segment_index: u64,
        /// Merkle tree root of all pieces within segment
        merkle_tree_root: Sha256Hash,
        /// Hash of the root block of the previous segment
        prev_root_block_hash: Sha256Hash,
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
}
