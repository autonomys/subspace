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

#[cfg(test)]
mod tests;

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

    // TODO: Remove default once https://github.com/paritytech/polkadot-sdk/pull/1221 is in our fork
    #[derive(frame_support::DefaultNoBound)]
    #[pallet::genesis_config]
    pub struct GenesisConfig<T> {
        pub domain_id: Option<DomainId>,
        #[serde(skip)]
        pub phantom: PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // NOTE: the domain id of a domain instance is allocated during instantiation and can not
            // be known ahead of time, thus the value in the `RuntimeGenesisConfig` of chain spec can
            // be arbitrary and is ignored, it will be reset to the correct id during domain instantiation.
            SelfDomainId::<T>::set(self.domain_id);
        }
    }

    impl<T: Config> Pallet<T> {
        #[cfg(not(feature = "runtime-benchmarks"))]
        pub fn self_domain_id() -> DomainId {
            SelfDomainId::<T>::get().expect("Domain ID must be set during domain instantiation")
        }

        #[cfg(feature = "runtime-benchmarks")]
        pub fn self_domain_id() -> DomainId {
            SelfDomainId::<T>::get().unwrap_or(0.into())
        }
    }
}
