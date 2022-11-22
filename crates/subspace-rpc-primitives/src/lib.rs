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

use serde::{Deserialize, Serialize};
use subspace_core_primitives::{
    Blake2b256Hash, PublicKey, RewardSignature, SlotNumber, Solution, SolutionRange,
};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::libp2p::Multiaddr;

/// Defines a limit for segment indexes array. It affects storage access on the runtime side.
pub const MAX_SEGMENT_INDEXES_PER_REQUEST: usize = 300;

/// Information necessary for farmer application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerAppInfo {
    /// Genesis hash of the chain
    #[serde(with = "hex::serde")]
    pub genesis_hash: [u8; 32],
    /// Bootstrap nodes for DSN.
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,
    /// Protocol info for farmer
    pub protocol_info: FarmerProtocolInfo,
}

/// Information about new slot that just arrived
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Global slot challenge
    pub global_challenge: Blake2b256Hash,
    /// Acceptable solution range for block authoring
    pub solution_range: SolutionRange,
    /// Acceptable solution range for voting
    pub voting_solution_range: SolutionRange,
}

/// Response of a slot challenge consisting of an optional solution and
/// the submitter(farmer)'s secret key for block signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionResponse {
    /// Slot number.
    pub slot_number: SlotNumber,
    /// Solution farmer has for the challenge.
    ///
    /// Corresponds to `slot_number` above.
    pub solutions: Vec<Solution<PublicKey, PublicKey>>,
}

/// Reward info that needs to be signed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSigningInfo {
    /// Hash to be signed.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// Public key of the plot identity that should create signature.
    #[serde(with = "hex::serde")]
    pub public_key: [u8; 32],
}

/// Signature in response to reward hash signing request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSignatureResponse {
    /// Hash that was signed.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// Pre-header or vote hash signature.
    pub signature: Option<RewardSignature>,
}
