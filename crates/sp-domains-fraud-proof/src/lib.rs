// Copyright (C) 2022 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Subspace fraud proof primitives for consensus chain.
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(associated_type_bounds)]

#[cfg(feature = "std")]
mod host_functions;
mod runtime_interface;
pub mod verification;

use codec::{Decode, Encode};
#[cfg(feature = "std")]
pub use host_functions::{
    FraudProofExtension, FraudProofHostFunctions, FraudProofHostFunctionsImpl,
};
pub use runtime_interface::fraud_proof_runtime_interface;
#[cfg(feature = "std")]
pub use runtime_interface::fraud_proof_runtime_interface::HostFunctions;
use sp_api::scale_info::TypeInfo;
use sp_domains::DomainId;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use sp_std::vec::Vec;
use subspace_core_primitives::Randomness;

/// Request type to fetch required verification information for fraud proof through Host function.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProofVerificationInfoRequest {
    /// Block randomness at a given consensus block hash.
    BlockRandomness,
    /// Domain timestamp extrinsic using the timestamp at a given consensus block hash.
    DomainTimestampExtrinsic(DomainId),
    /// The body of domain bundle included in a given consensus block at a given index
    DomainBundleBody {
        domain_id: DomainId,
        bundle_index: u32,
    },
}

impl PassBy for FraudProofVerificationInfoRequest {
    type PassBy = pass_by::Codec<Self>;
}

/// Response holds required verification information for fraud proof from Host function.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProofVerificationInfoResponse {
    /// Block randomness fetched from consensus state at a specific block hash.
    BlockRandomness(Randomness),
    /// Encoded domain timestamp extrinsic using the timestamp from consensus state at a specific block hash.
    DomainTimestampExtrinsic(Vec<u8>),
    /// Domain block body fetch from a specific consensus block body
    DomainBundleBody(Vec<OpaqueExtrinsic>),
}

impl FraudProofVerificationInfoResponse {
    pub fn into_bundle_body(self) -> Option<Vec<OpaqueExtrinsic>> {
        match self {
            Self::DomainBundleBody(bb) => Some(bb),
            _ => None,
        }
    }
}
