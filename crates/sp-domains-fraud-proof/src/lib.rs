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
    /// The domain runtime code
    DomainRuntimeCode(DomainId),
    /// Domain set_code extrinsic if there is a runtime upgrade at a given consensus block hash.
    DomainSetCodeExtrinsic(DomainId),
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
    /// The domain runtime code
    DomainRuntimeCode(Vec<u8>),
    /// Encoded domain set_code extrinsic if there is a runtime upgrade at given consensus block hash.
    DomainSetCodeExtrinsic(Option<Vec<u8>>),
}

impl FraudProofVerificationInfoResponse {
    pub fn into_domain_runtime_code(self) -> Option<Vec<u8>> {
        match self {
            Self::DomainRuntimeCode(c) => Some(c),
            _ => None,
        }
    }

    pub fn into_domain_set_code_extrinsic(self) -> Option<Vec<u8>> {
        match self {
            FraudProofVerificationInfoResponse::DomainSetCodeExtrinsic(
                maybe_set_code_extrinsic,
            ) => maybe_set_code_extrinsic,
            _ => None,
        }
    }
}
