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

use parity_scale_codec::{Decode, Encode, EncodeLike, Input, Output};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use subspace_core_primitives::{
    Blake3Hash, PublicKey, RewardSignature, SlotNumber, Solution, SolutionRange,
};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::libp2p::Multiaddr;

/// Defines a limit for number of segments that can be requested over RPC
pub const MAX_SEGMENT_HEADERS_PER_REQUEST: usize = 1000;

/// Information necessary for farmer application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerAppInfo {
    /// Genesis hash of the chain
    #[serde(with = "hex")]
    pub genesis_hash: [u8; 32],
    /// Bootstrap nodes for DSN
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,
    /// Whether node is syncing right now
    pub syncing: bool,
    /// How much time farmer has to audit sectors and generate a solution
    pub farming_timeout: Duration,
    /// Protocol info for farmer
    pub protocol_info: FarmerProtocolInfo,
}

impl Encode for FarmerAppInfo {
    fn size_hint(&self) -> usize {
        0_usize
            .saturating_add(Encode::size_hint(&self.genesis_hash))
            .saturating_add(Encode::size_hint(
                &self
                    .dsn_bootstrap_nodes
                    .iter()
                    .map(|addr| addr.as_ref())
                    .collect::<Vec<_>>(),
            ))
            .saturating_add(Encode::size_hint(&self.syncing))
            .saturating_add(Encode::size_hint(&self.farming_timeout))
            .saturating_add(Encode::size_hint(&self.protocol_info))
    }

    fn encode_to<O: Output + ?Sized>(&self, output: &mut O) {
        Encode::encode_to(&self.genesis_hash, output);
        Encode::encode_to(
            &self
                .dsn_bootstrap_nodes
                .iter()
                .map(|addr| addr.as_ref())
                .collect::<Vec<_>>(),
            output,
        );
        Encode::encode_to(&self.syncing, output);
        Encode::encode_to(&self.farming_timeout, output);
        Encode::encode_to(&self.protocol_info, output);
    }
}

impl EncodeLike for FarmerAppInfo {}

impl Decode for FarmerAppInfo {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        Ok(FarmerAppInfo {
            genesis_hash: <[u8; 32]>::decode(input)
                .map_err(|error| error.chain("Could not decode `FarmerAppInfo::genesis_hash`"))?,
            dsn_bootstrap_nodes: Vec::<Vec<u8>>::decode(input)
                .map_err(|error| {
                    error.chain("Could not decode `FarmerAppInfo::dsn_bootstrap_nodes`")
                })?
                .into_iter()
                .map(Multiaddr::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    parity_scale_codec::Error::from("Failed to decode bytes as Multiaddr")
                        .chain(error.to_string())
                        .chain("Could not decode `FarmerAppInfo::dsn_bootstrap_nodes`")
                })?,
            syncing: bool::decode(input)
                .map_err(|error| error.chain("Could not decode `FarmerAppInfo::syncing`"))?,
            farming_timeout: Duration::decode(input).map_err(|error| {
                error.chain("Could not decode `FarmerAppInfo::farming_timeout`")
            })?,
            protocol_info: FarmerProtocolInfo::decode(input)
                .map_err(|error| error.chain("Could not decode `FarmerAppInfo::protocol_info`"))?,
        })
    }
}

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Global slot challenge
    pub global_challenge: Blake3Hash,
    /// Acceptable solution range for block authoring
    pub solution_range: SolutionRange,
    /// Acceptable solution range for voting
    pub voting_solution_range: SolutionRange,
}

/// Response of a slot challenge consisting of an optional solution and
/// the submitter(farmer)'s secret key for block signing.
#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionResponse {
    /// Slot number.
    pub slot_number: SlotNumber,
    /// Solution farmer has for the challenge.
    ///
    /// Corresponds to `slot_number` above.
    pub solution: Solution<PublicKey, PublicKey>,
}

/// Reward info that needs to be signed.
#[derive(Clone, Copy, Debug, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSigningInfo {
    /// Hash to be signed.
    #[serde(with = "hex")]
    pub hash: [u8; 32],
    /// Public key of the plot identity that should create signature.
    #[serde(with = "hex")]
    pub public_key: [u8; 32],
}

/// Signature in response to reward hash signing request.
#[derive(Clone, Copy, Debug, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardSignatureResponse {
    /// Hash that was signed.
    #[serde(with = "hex")]
    pub hash: [u8; 32],
    /// Pre-header or vote hash signature.
    pub signature: Option<RewardSignature>,
}
