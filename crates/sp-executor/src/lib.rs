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
use scale_info::TypeInfo;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_std::vec::Vec;

pub type BundleHeader = Vec<u8>;

/// Transaction bundle
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Debug)]
pub struct Bundle {
    ///
    pub header: BundleHeader,
    /// Encoded `Vec<Extrinsic>`
    pub opaque_transactions: Vec<u8>,
}

impl Bundle {
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> sp_core::H256 {
        sp_runtime::traits::BlakeTwo256::hash(&self.header)
    }
}

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi {
        /// Submits the candidate receipt via an unsigned extrinsic.
        fn submit_candidate_receipt_unsigned(
            head_number: <<Block as BlockT>::Header as HeaderT>::Number,
            head_hash: <Block as BlockT>::Hash,
        ) -> Option<()>;

        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_transaction_bundle_unsigned(
            bundle: Bundle
        ) -> Option<()>;

        /// Returns the block hash given the block number.
        fn head_hash(
            number: <<Block as BlockT>::Header as HeaderT>::Number,
        ) -> Option<<Block as BlockT>::Hash>;

        /// Returns the latest block hash of executor chain.
        fn pending_head() -> Option<<Block as BlockT>::Hash>;
    }
}
