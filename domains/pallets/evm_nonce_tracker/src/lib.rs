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

//! Pallet EVM Account nonce tracker

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod check_nonce;
pub use check_nonce::CheckNonce;
pub use pallet::*;
use sp_core::U256;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::U256;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    /// Storage to hold evm account nonces.
    /// This is only used for pre_dispatch since EVM pre_dispatch does not
    /// increment account nonce.
    #[pallet::storage]
    pub(super) type AccountNonce<T: Config> =
        StorageMap<_, Identity, T::AccountId, U256, OptionQuery>;

    /// Pallet EVM account nonce tracker.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_now: BlockNumberFor<T>) {
            // clear the storage since we would start with updated nonce
            // during the pre_dispatch in next block
            let _ = AccountNonce::<T>::clear(u32::MAX, None);
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Returns current nonce for the given account.
    pub fn account_nonce(account: T::AccountId) -> Option<U256> {
        AccountNonce::<T>::get(account)
    }

    /// Set nonce to the account.
    pub fn set_account_nonce(account: T::AccountId, nonce: U256) {
        AccountNonce::<T>::set(account, Some(nonce))
    }
}
