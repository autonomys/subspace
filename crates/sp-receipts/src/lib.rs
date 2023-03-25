// Copyright (C) 2023 Subspace Labs, Inc.
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

//! Primitives for Receipts.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_core::H256;
use sp_domains::DomainId;
use sp_runtime::traits::NumberFor;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait ReceiptsApi<DomainHash: Encode + Decode> {
        /// Returns the trace of given domain receipt hash.
        fn execution_trace(domain_id: DomainId, receipt_hash: H256) -> Vec<DomainHash>;

        /// Returns the state root of given domain block.
        fn state_root(
            domain_id: DomainId,
            domain_block_number: NumberFor<Block>,
            domain_block_hash: Block::Hash,
        ) -> Option<DomainHash>;
    }
}
