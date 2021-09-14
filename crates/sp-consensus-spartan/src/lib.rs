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

//! Primitives for Spartan-based PoR.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod spartan;

use core::convert::TryInto;
use parity_scale_codec::Encode;
use sha2::{Digest, Sha256};
use sp_debug_derive::RuntimeDebug;

/// The length of the Randomness.
pub const RANDOMNESS_LENGTH: usize = 32;

/// Randomness value.
pub type Randomness = [u8; RANDOMNESS_LENGTH];

pub type Sha256Hash = [u8; 32];

/// Root block for a specific segment
#[derive(Encode, Copy, Clone, RuntimeDebug)]
pub enum RootBlock {
    // V0 of the root block data structure
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
        let mut hasher = Sha256::new();
        hasher.update(&self.encode());
        hasher.finalize()[..]
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
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
