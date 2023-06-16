// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitives for Executor Registry.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_domains::ExecutorPublicKey;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;

/// Executor registry interface.
pub trait ExecutorRegistry<AccountId, Balance, StakeWeight> {
    /// Returns `Some(stake_amount)` if the given account is an executor, `None` if not.
    fn executor_stake(who: &AccountId) -> Option<Balance>;

    /// Returns `Some(executor_public_key)` if the given account is an executor, `None` if not.
    fn executor_public_key(who: &AccountId) -> Option<ExecutorPublicKey>;

    /// Return the storage key of `KeyOwner` entry in pallet-executor-registry.
    fn key_owner_storage_key(executor_public_key: &ExecutorPublicKey) -> Vec<u8>;

    /// Returns `Some(stake_weight)` if the given account is an authority.
    fn authority_stake_weight(who: &AccountId) -> Option<StakeWeight>;

    /// Register an executor without check, only use in benchmark.
    #[cfg(feature = "runtime-benchmarks")]
    fn unchecked_register(executor: AccountId, public_key: ExecutorPublicKey, stake: Balance);
}

impl<AccountId, Balance, StakeWeight> ExecutorRegistry<AccountId, Balance, StakeWeight> for () {
    fn executor_stake(_who: &AccountId) -> Option<Balance> {
        None
    }

    fn executor_public_key(_who: &AccountId) -> Option<ExecutorPublicKey> {
        None
    }

    fn key_owner_storage_key(_executor_public_key: &ExecutorPublicKey) -> Vec<u8> {
        Vec::new()
    }

    fn authority_stake_weight(_who: &AccountId) -> Option<StakeWeight> {
        None
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn unchecked_register(_executor: AccountId, _public_key: ExecutorPublicKey, _stake: Balance) {}
}

/// Hook invoked after the executor set is updated on each epoch.
pub trait OnNewEpoch<AccountId, StakeWeight> {
    /// Something that should happen after the executors rotation.
    fn on_new_epoch(executor_weights: BTreeMap<AccountId, StakeWeight>);
}

impl<AccountId, StakeWeight> OnNewEpoch<AccountId, StakeWeight> for () {
    fn on_new_epoch(_executor_weights: BTreeMap<AccountId, StakeWeight>) {}
}
