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
    use frame_system::ensure_none;
    use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
    use sp_core::storage::StorageKey;
    use sp_domain_tracker::{InherentType, NoFatalError, INHERENT_IDENTIFIER};
    use sp_domains::DomainId;
    use sp_messenger::DomainTracker;
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

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

    /// Flag to allow only one update per block through inherent.
    #[pallet::storage]
    #[pallet::getter(fn state_roots_updated)]
    pub(super) type StateRootsUpdated<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Events emitted by pallet-domain-tracker.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when state roots are updated.
        StateRootsUpdated,
    }

    /// Errors emitted by pallet-domain-tracker.
    #[pallet::error]
    pub enum Error<T> {
        /// Emits on second call to set state roots of the domain.
        StateRootsAlreadyUpdated,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Updates the state root of the system domain.
        /// Also ensures the state root count is bounded to the max limit for each domain.
        #[pallet::weight((10_000, Pays::No))]
        pub fn update_system_domain_state_root(
            origin: OriginFor<T>,
            state_root: StateRootOf<T>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            ensure!(
                !StateRootsUpdated::<T>::get(),
                Error::<T>::StateRootsAlreadyUpdated
            );

            Self::do_update_state_root(state_root);
            StateRootsUpdated::<T>::set(true);
            Self::deposit_event(Event::<T>::StateRootsUpdated);
            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = NoFatalError<()>;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType<StateRootOf<T>>>(&INHERENT_IDENTIFIER)
                .expect("Domain tracker inherent data is not correctly encoded")
                .expect("Domain tracker inherent data must be provided.");

            Some(Call::update_system_domain_state_root {
                state_root: inherent_data.system_domain_state_root,
            })
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::update_system_domain_state_root { .. })
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_n: BlockNumberFor<T>) {
            assert!(
                StateRootsUpdated::<T>::take(),
                "StateRoots must be updated once a block."
            );
        }
    }

    impl<T: Config> DomainTracker<StateRootOf<T>> for Pallet<T> {
        fn system_domain_state_roots() -> Vec<StateRootOf<T>> {
            SystemDomainStateRoots::<T>::get()
        }

        fn domain_state_root_storage_key(_domain_id: DomainId) -> StorageKey {
            // TODO(ved): return well know key once the storage item for domain registry is defined.
            todo!()
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn do_update_state_root(state_root: StateRootOf<T>) {
            SystemDomainStateRoots::<T>::mutate(|state_roots| {
                state_roots.push(state_root);
                if state_roots.len() > T::StateRootsBound::get() as usize {
                    let first_idx = state_roots.len() - T::StateRootsBound::get() as usize;
                    *state_roots = state_roots.split_off(first_idx);
                }
            });
        }
    }
}
