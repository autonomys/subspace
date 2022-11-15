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

use codec::{Decode, Encode};
use sp_core::sp_std;
use sp_domains::DomainId;
use sp_inherents::{InherentIdentifier, IsFatalError};
use sp_std::vec::Vec;

/// The identifier for the `domain-tracker` inherent.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"dmn-trkr";

#[derive(Encode)]
pub struct NoFatalError<E: codec::Encode>(E);
impl<E: codec::Encode> IsFatalError for NoFatalError<E> {
    fn is_fatal_error(&self) -> bool {
        false
    }
}

/// Inherent type provided by the domain-tracker.
#[derive(Encode, Decode)]
pub struct InherentType<StateRoot> {
    pub system_domain_state_root: StateRoot,
}

sp_api::decl_runtime_apis! {
    /// Api useful for relayers to fetch messages and submit transactions.
    pub trait DomainTrackerApi<BlockNumber>
    where
        BlockNumber: Encode + Decode
    {
        /// Returns the storage key for the state root at a block number for core domain
        /// as present on the system domain.
        /// Returns None if the block number is not confirmed yet.
        fn storage_key_for_core_domain_state_root(domain_id: DomainId, block_number: BlockNumber) -> Option<Vec<u8>>;
    }
}
