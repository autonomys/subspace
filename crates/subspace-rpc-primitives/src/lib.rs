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
use subspace_core_primitives::{Piece, PublicKey, Salt, Signature, Tag};

/// Type of a slot number.
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
#[serde(rename_all = "camelCase")]
pub struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Global slot challenge
    pub global_challenge: Tag,
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
    /// Acceptable solution range
    pub solution_range: u64,
}

/// Response of a slot challenge consisting of an optional solution and
/// the submitter(farmer)'s secret key for block signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionResponse {
    /// Slot number.
    pub slot_number: SlotNumber,
    /// Optional solution.
    ///
    /// Derived from the farmer's plot corresponding to `slot_number` above.
    pub maybe_solution: Option<Solution>,
    /// Secret key.
    ///
    /// Used by the farmer to sign blocks on the client node.
    pub secret_key: Vec<u8>,
}

// TODO: Deduplicate this type
/// Duplicate type of [sp_consensus_subspace::digests::Solution] as we'd like to
/// not pull in the Substrate libraries when it only related to the Subspace functionalities.
///
/// [sp_consensus_subspace::digests::Solution]: ../sp_consensus_subspace/digests/struct.Solution.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Solution {
    /// Public key of the farmer that created the solution
    pub public_key: PublicKey,
    /// Index of encoded piece
    pub piece_index: u64,
    /// Encoding
    pub encoding: Piece,
    /// Signature of the tag
    pub signature: Signature,
    /// Local challenge derived with farmer's identity
    pub local_challenge: Signature,
    /// Tag (hmac of encoding and salt)
    pub tag: Tag,
}
