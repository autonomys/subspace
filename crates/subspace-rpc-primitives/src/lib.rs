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
use subspace_core_primitives::{
    NPieces, PublicKey, RewardSignature, Salt, Sha256Hash, SlotNumber, Solution,
};

/// Metadata necessary for farmer operation
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerMetadata {
    /// The size of data in one piece (in bytes).
    pub record_size: u32,
    /// Recorded history is encoded and plotted in segments of this size (in bytes).
    pub recorded_history_segment_size: u32,
    /// Maximum number of pieces in each plot
    pub max_plot_size: NPieces,
    /// Total number of pieces stored on the network
    pub total_pieces: NPieces,
}

/// Information about new slot that just arrived
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Global slot challenge
    pub global_challenge: Sha256Hash,
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
    /// Acceptable solution range for block authoring
    pub solution_range: u64,
    /// Acceptable solution range for voting
    pub voting_solution_range: u64,
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
    pub maybe_solution: Option<Solution<PublicKey, PublicKey>>,
}

/// Reward info that needs to be signed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSigningInfo {
    /// Hash to be signed.
    #[serde(with = "HexForm")]
    pub hash: [u8; 32],
    /// Public key of the plot identity that should create signature.
    #[serde(with = "HexForm")]
    pub public_key: [u8; 32],
}

/// Signature in response to reward hash signing request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSignatureResponse {
    /// Hash that was signed.
    #[serde(with = "HexForm")]
    pub hash: [u8; 32],
    /// Pre-header or vote hash signature.
    pub signature: Option<RewardSignature>,
}
