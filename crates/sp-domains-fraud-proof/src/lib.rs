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
pub mod bundle_equivocation;
#[cfg(feature = "std")]
pub mod execution_prover;
pub mod fraud_proof;
#[cfg(feature = "std")]
mod host_functions;
mod runtime_interface;
#[cfg(test)]
mod tests;
pub mod verification;

use crate::fraud_proof::FraudProof;
use codec::{Decode, Encode};
#[cfg(feature = "std")]
pub use host_functions::{
    FraudProofExtension, FraudProofHostFunctions, FraudProofHostFunctionsImpl,
};
pub use runtime_interface::fraud_proof_runtime_interface;
#[cfg(feature = "std")]
pub use runtime_interface::fraud_proof_runtime_interface::HostFunctions;
use sp_api::scale_info::TypeInfo;
use sp_api::HeaderT;
use sp_domains::DomainId;
use sp_runtime::traits::NumberFor;
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidity};
use sp_runtime::OpaqueExtrinsic;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use sp_std::vec::Vec;
use subspace_core_primitives::Randomness;

/// Custom invalid validity code for the extrinsics in pallet-domains.
#[repr(u8)]
pub enum InvalidTransactionCode {
    BundleEquivocation = 101,
    TransactionProof = 102,
    ExecutionReceipt = 103,
    Bundle = 104,
    FraudProof = 105,
}

impl From<InvalidTransactionCode> for InvalidTransaction {
    #[inline]
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8)
    }
}

impl From<InvalidTransactionCode> for TransactionValidity {
    #[inline]
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8).into()
    }
}

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
    /// The domain runtime code
    DomainRuntimeCode(DomainId),
    /// Domain set_code extrinsic if there is a runtime upgrade at a given consensus block hash.
    DomainSetCodeExtrinsic(DomainId),
    /// Request to check if particular extrinsic is in range for (domain, bundle) pair at given domain block
    TxRangeCheck {
        domain_id: DomainId,
        /// Index of the bundle in which the extrinsic exists
        bundle_index: u32,
        /// Extrinsic for which we need to check the range
        opaque_extrinsic: OpaqueExtrinsic,
    },
    /// Request to check if particular extrinsic is an inherent extrinsic
    InherentExtrinsicCheck {
        domain_id: DomainId,
        /// Extrinsic for which we need to if it is inherent or not.
        opaque_extrinsic: OpaqueExtrinsic,
    },
}

impl PassBy for FraudProofVerificationInfoRequest {
    type PassBy = pass_by::Codec<Self>;
}

/// Type that maybe holds an encoded set_code extrinsic with upgraded runtime
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum SetCodeExtrinsic {
    /// No runtime upgrade.
    None,
    /// Holds an encoded set_code extrinsic with an upgraded runtime.
    EncodedExtrinsic(Vec<u8>),
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
    /// The domain runtime code
    DomainRuntimeCode(Vec<u8>),
    /// Encoded domain set_code extrinsic if there is a runtime upgrade at given consensus block hash.
    DomainSetCodeExtrinsic(SetCodeExtrinsic),
    /// If particular extrinsic is in range for (domain, bundle) pair at given domain block
    TxRangeCheck(bool),
    /// If the particular extrinsic provided is either inherent or not.
    InherentExtrinsicCheck(bool),
}

impl FraudProofVerificationInfoResponse {
    pub fn into_block_randomness(self) -> Option<Randomness> {
        match self {
            Self::BlockRandomness(randomness) => Some(randomness),
            _ => None,
        }
    }

    pub fn into_domain_timestamp_extrinsic(self) -> Option<Vec<u8>> {
        match self {
            Self::DomainTimestampExtrinsic(timestamp_extrinsic) => Some(timestamp_extrinsic),
            _ => None,
        }
    }

    pub fn into_domain_runtime_code(self) -> Option<Vec<u8>> {
        match self {
            Self::DomainRuntimeCode(c) => Some(c),
            _ => None,
        }
    }

    pub fn into_domain_set_code_extrinsic(self) -> SetCodeExtrinsic {
        match self {
            FraudProofVerificationInfoResponse::DomainSetCodeExtrinsic(
                maybe_set_code_extrinsic,
            ) => maybe_set_code_extrinsic,
            _ => SetCodeExtrinsic::None,
        }
    }

    pub fn into_tx_range_check(self) -> Option<bool> {
        match self {
            FraudProofVerificationInfoResponse::TxRangeCheck(is_tx_in_range) => {
                Some(is_tx_in_range)
            }
            _ => None,
        }
    }

    pub fn into_bundle_body(self) -> Option<Vec<OpaqueExtrinsic>> {
        match self {
            Self::DomainBundleBody(bb) => Some(bb),
            _ => None,
        }
    }

    pub fn into_inherent_extrinsic_check(self) -> Option<bool> {
        match self {
            FraudProofVerificationInfoResponse::InherentExtrinsicCheck(is_inherent) => {
                Some(is_inherent)
            }
            _ => None,
        }
    }
}

sp_api::decl_runtime_apis! {
    pub trait FraudProofsApi<DomainHeader: HeaderT> {
        /// Submits the fraud proof via an unsigned extrinsic.
        fn submit_fraud_proof_unsigned(
            fraud_proof: FraudProof<NumberFor<Block>, Block::Hash, DomainHeader>,
        );
    }
}
