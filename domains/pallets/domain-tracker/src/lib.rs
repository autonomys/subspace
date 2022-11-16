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

//! Pallet domain tracker to track domain specific details like state root.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

pub use pallet::*;
use sp_runtime::traits::Hash;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub(crate) type StateRootOf<T> = <<T as frame_system::Config>::Hashing as Hash>::Output;

#[frame_support::pallet]
mod pallet {
    use crate::StateRootOf;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::storage::StorageKey;
    use sp_domain_digests::AsPredigest;
    use sp_domains::DomainId;
    use sp_messenger::DomainTracker;
    use sp_runtime::traits::{CheckedSub, One};
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Total number of confirmed state roots to store at a time.
        type StateRootsBound: Get<u32>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// All confirmed domain state roots bounded to the StateRootBound value.
    #[pallet::storage]
    #[pallet::getter(fn system_domain_state_roots)]
    pub(super) type SystemDomainStateRoots<T: Config> =
        StorageValue<_, Vec<StateRootOf<T>>, ValueQuery>;

    /// Latest Confirmed Core domain state roots bounded to the StateRootBound value.
    /// This is essentially used by relayer and updated by the system domain runtime when there is
    /// a new state root confirmed for a given core domain.
    #[pallet::storage]
    #[pallet::getter(fn core_domains_state_root)]
    pub(super) type CoreDomainsStateRoot<T: Config> = StorageDoubleMap<
        _,
        Identity,
        DomainId,
        Identity,
        T::BlockNumber,
        StateRootOf<T>,
        OptionQuery,
    >;

    /// Events emitted by pallet-domain-tracker.
    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            if let Some(state_root_update) = <frame_system::Pallet<T>>::digest()
                .logs
                .iter()
                .find_map(|s| {
                    s.as_system_domain_state_root_update::<T::BlockNumber, StateRootOf<T>>()
                })
            {
                Self::add_confirmed_system_domain_state_root(state_root_update.state_root);
            }

            Weight::zero()
        }
    }

    impl<T: Config> DomainTracker<T::BlockNumber, StateRootOf<T>> for Pallet<T> {
        fn system_domain_state_roots() -> Vec<StateRootOf<T>> {
            SystemDomainStateRoots::<T>::get()
        }

        fn storage_key_for_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
        ) -> StorageKey {
            StorageKey(CoreDomainsStateRoot::<T>::hashed_key_for(
                domain_id,
                block_number,
            ))
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn add_confirmed_system_domain_state_root(state_root: StateRootOf<T>) {
            SystemDomainStateRoots::<T>::mutate(|state_roots| {
                state_roots.push(state_root);
                if state_roots.len() > T::StateRootsBound::get() as usize {
                    let first_idx = state_roots.len() - T::StateRootsBound::get() as usize;
                    *state_roots = state_roots.split_off(first_idx);
                }
            });
        }

        /// Adds a new state root for the core domain mapped to domain_id.
        /// This is only called on system domain runtime by the domain registry.
        /// TODO(ved): ensure this is called when the core domain state roots are available.
        pub fn add_confirmed_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
            state_root: StateRootOf<T>,
        ) {
            CoreDomainsStateRoot::<T>::insert(domain_id, block_number, state_root);
            // ensure to bound the total state roots
            match block_number.checked_sub(&T::StateRootsBound::get().into()) {
                // nothing to clean up yet
                None => (),
                Some(mut from) => {
                    while CoreDomainsStateRoot::<T>::take(domain_id, from).is_some() {
                        from = match from.checked_sub(&One::one()) {
                            None => return,
                            Some(from) => from,
                        }
                    }
                }
            }
        }

        /// Returns storage key to generate storage proof for the relayer.
        /// If the domain is not core, or block number is not confirmed yet, then we return None.
        pub fn storage_key_for_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
        ) -> Option<Vec<u8>> {
            if !domain_id.is_core()
                || !CoreDomainsStateRoot::<T>::contains_key(domain_id, block_number)
            {
                return None;
            };

            Some(CoreDomainsStateRoot::<T>::hashed_key_for(
                domain_id,
                block_number,
            ))
        }
    }
}
