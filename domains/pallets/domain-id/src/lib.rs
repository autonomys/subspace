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

//! Pallet Domain Id

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use sp_domains::DomainId;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::storage]
    pub(super) type SelfDomainId<T> = StorageValue<_, DomainId, OptionQuery>;

    /// Pallet domain-id to store self domain id.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[derive(Default)]
    #[pallet::genesis_config]
    pub struct GenesisConfig {
        pub domain_id: Option<DomainId>,
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            SelfDomainId::<T>::set(self.domain_id);
        }
    }
}
