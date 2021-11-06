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
