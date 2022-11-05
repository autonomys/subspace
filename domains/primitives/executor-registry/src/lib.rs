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

use sp_std::collections::btree_map::BTreeMap;

/// Executor registry interface.
pub trait ExecutorRegistry<AccountId, Balance> {
    /// Returns `Some(stake_amount)` if the given account is an executor, `None` if not an executor.
    fn executor_stake(who: &AccountId) -> Option<Balance>;
}

impl<AccountId, Balance> ExecutorRegistry<AccountId, Balance> for () {
    fn executor_stake(_who: &AccountId) -> Option<Balance> {
        None
    }
}

/// Hook invoked after the executor set is updated on each epoch.
pub trait OnNewEpoch<AccountId, StakeWeight> {
    /// Something that should happen after the executors rotation.
    fn on_new_epoch(executor_weights: BTreeMap<AccountId, StakeWeight>);
}

impl<AccountId, StakeWeight> OnNewEpoch<AccountId, StakeWeight> for () {
    fn on_new_epoch(_executor_weights: BTreeMap<AccountId, StakeWeight>) {}
}
