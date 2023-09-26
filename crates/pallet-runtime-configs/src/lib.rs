// Copyright (C) 2022 Subspace Labs, Inc.
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

//! Pallet for tweaking the runtime configs for multiple network.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Zero;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Whether to disable the calls in pallet-domains.
    #[pallet::storage]
    #[pallet::getter(fn enable_domains)]
    pub type EnableDomains<T> = StorageValue<_, bool, ValueQuery>;

    /// Whether to disable the normal balances transfer calls.
    #[pallet::storage]
    #[pallet::getter(fn enable_balance_transfers)]
    pub type EnableBalanceTransfers<T> = StorageValue<_, bool, ValueQuery>;

    #[pallet::storage]
    pub type ConfirmationDepthK<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub enable_domains: bool,
        pub enable_balance_transfers: bool,
        pub confirmation_depth_k: BlockNumberFor<T>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        #[inline]
        fn default() -> Self {
            Self {
                enable_domains: false,
                enable_balance_transfers: false,
                confirmation_depth_k: BlockNumberFor::<T>::from(100u32),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let Self {
                enable_domains,
                enable_balance_transfers,
                confirmation_depth_k,
            } = self;

            assert!(
                !confirmation_depth_k.is_zero(),
                "ConfirmationDepthK can not be zero"
            );

            <EnableDomains<T>>::put(enable_domains);
            <EnableBalanceTransfers<T>>::put(enable_balance_transfers);
            <ConfirmationDepthK<T>>::put(confirmation_depth_k);
        }
    }
}
