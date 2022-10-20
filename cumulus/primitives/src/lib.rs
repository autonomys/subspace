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

//! Primitives for executor pallet.

#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use sp_domains::BundleElectionParams;
use sp_runtime::generic::UncheckedExtrinsic;
use sp_runtime::traits::{Block as BlockT, IdentifyAccount, Verify};
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
    /// API necessary for secondary node.
    pub trait SecondaryApi<AccountId: Encode + Decode> {
        /// Extracts the optional signer per extrinsic.
        fn extract_signer(
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)>;

        /// Returns the intermediate storage roots in an encoded form.
        fn intermediate_roots() -> Vec<[u8; 32]>;

        /// Returns the storage root after initializing the block.
        fn initialize_block_with_post_state_root(header: &<Block as BlockT>::Header) -> Vec<u8>;

        /// Returns the storage root after applying the extrinsic.
        fn apply_extrinsic_with_post_state_root(extrinsic: <Block as BlockT>::Extrinsic) -> Vec<u8>;

        /// Returns an encoded extrinsic aiming to upgrade the runtime using given code.
        fn construct_set_code_extrinsic(code: Vec<u8>) -> Vec<u8>;

        /// Returns the parameters for the bundle election.
        fn bundle_elections_params() -> BundleElectionParams;
    }
}
