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

//! Primitives for Subspace RPC.

use hex_buffer_serde::{Hex, HexForm};
use serde::{Deserialize, Serialize};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{Salt, Tag};

pub type SlotNumber = u64;

/// Encoded block with mapping of objects that it contains
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedBlockWithObjectMapping {
    /// Encoded block
    #[serde(with = "HexForm")]
    pub block: Vec<u8>,
    /// Mapping of objects inside of the block
    pub object_mapping: BlockObjectMapping,
}

/// Metadata necessary for farmer operation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerMetadata {
    /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
    /// to the client-dependent transaction confirmation depth `k`).
    pub confirmation_depth_k: u32,
    /// The size of data in one piece (in bytes).
    pub record_size: u32,
    /// Recorded history is encoded and plotted in segments of this size (in bytes).
    pub recorded_history_segment_size: u32,
    /// This constant defines the size (in bytes) of one pre-genesis object.
    pub pre_genesis_object_size: u32,
    /// This constant defines the number of a pre-genesis objects that will bootstrap the
    /// history.
    pub pre_genesis_object_count: u32,
    /// This constant defines the seed used for deriving pre-genesis objects that will bootstrap
    /// the history.
    pub pre_genesis_object_seed: Vec<u8>,
}

/// Information about new slot that just arrived
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Slot challenge
    pub challenge: [u8; 8],
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
    /// Acceptable solution range
    pub solution_range: u64,
}

/// Proposed proof of space consisting of solution and farmer's secret key for block signing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposedProofOfReplicationResponse {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Solution (if present) from farmer's plot corresponding to slot number above
    pub solution: Option<Solution>,
    /// Secret key, used for signing blocks on the client node
    pub secret_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Solution {
    pub public_key: [u8; 32],
    pub piece_index: u64,
    pub encoding: Vec<u8>,
    pub signature: Vec<u8>,
    pub tag: Tag,
}

impl Solution {
    pub fn new(
        public_key: [u8; 32],
        piece_index: u64,
        encoding: Vec<u8>,
        signature: Vec<u8>,
        tag: Tag,
    ) -> Self {
        Self {
            public_key,
            piece_index,
            encoding,
            signature,
            tag,
        }
    }
}
