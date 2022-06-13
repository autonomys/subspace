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

    #[pallet::pallet]
    #[pallet::generate_store(pub trait Store)]
    pub struct Pallet<T>(_);

    /// Sets this value to `true` to enable the signed extension `DisablePallets` which
    /// disallowes the Call from pallet-executor.
    #[pallet::storage]
    #[pallet::getter(fn enable_executor)]
    pub type EnableExecutor<T> = StorageValue<_, bool, ValueQuery>;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {
        pub enable_executor: bool,
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            let Self { enable_executor } = self;

            <EnableExecutor<T>>::put(enable_executor);
        }
    }
}
