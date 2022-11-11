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
use sp_domains::{DomainId, SignedOpaqueBundle};
use sp_runtime::generic::UncheckedExtrinsic;
use sp_runtime::traits::{Block as BlockT, IdentifyAccount, NumberFor, Verify};
use sp_runtime::{MultiAddress, MultiSignature};
use sp_std::vec::Vec;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// The type we use to represent relayer id. This is same as account Id.
pub type RelayerId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Extracts the signer from an unchecked extrinsic.
///
/// Used by executor to extract the optional signer when shuffling the extrinsics.
pub trait Signer<AccountId, Lookup> {
    /// Returns the AccountId of signer.
    fn signer(&self, lookup: &Lookup) -> Option<AccountId>;
}

impl<Address, AccountId, Call, Signature, Extra, Lookup> Signer<AccountId, Lookup>
    for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
    Address: Clone,
    Extra: sp_runtime::traits::SignedExtension<AccountId = AccountId>,
    Lookup: sp_runtime::traits::Lookup<Source = Address, Target = AccountId>,
{
    fn signer(&self, lookup: &Lookup) -> Option<AccountId> {
        self.signature
            .as_ref()
            .and_then(|(signed, _, _)| lookup.lookup(signed.clone()).ok())
    }
}

sp_api::decl_runtime_apis! {
    /// API necessary for system domain.
    pub trait SystemDomainApi<PNumber: Encode + Decode, PHash: Encode + Decode> {
        /// Wrap the core domain bundles into extrinsics.
        fn construct_submit_core_bundle_extrinsics(
            signed_opaque_bundles: Vec<SignedOpaqueBundle<PNumber, PHash, <Block as BlockT>::Hash>>,
        ) -> Vec<Vec<u8>>;

        /// Returns the parameters for the bundle election.
        fn bundle_elections_params(domain_id: DomainId) -> BundleElectionParams;

        fn best_execution_chain_number(domain_id: DomainId) -> NumberFor<Block>;

        fn oldest_receipt_number(domain_id: DomainId) -> NumberFor<Block>;

        fn maximum_receipt_drift() -> NumberFor<Block>;
    }
}
