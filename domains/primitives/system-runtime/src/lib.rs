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

//! Primitives for system domain runtime.

#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use sp_domains::bundle_election::BundleElectionParams;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutorPublicKey};
use sp_runtime::traits::NumberFor;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    /// API necessary for system domain.
    pub trait SystemDomainApi<PNumber: Encode + Decode, PHash: Encode + Decode> {
        /// Wrap the core domain bundles into extrinsics.
        fn construct_submit_core_bundle_extrinsics(
            signed_opaque_bundles: Vec<u8>,
        ) -> Option<Vec<Vec<u8>>>;

        /// Returns the parameters for the bundle election.
        fn bundle_elections_params(domain_id: DomainId) -> BundleElectionParams;

        fn core_bundle_election_storage_keys(
            domain_id: DomainId,
            executor_public_key: ExecutorPublicKey,
        ) -> Option<Vec<Vec<u8>>>;

        fn head_receipt_number(domain_id: DomainId) -> NumberFor<Block>;

        fn oldest_receipt_number(domain_id: DomainId) -> NumberFor<Block>;

        fn maximum_receipt_drift() -> NumberFor<Block>;

        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof);
    }
}
