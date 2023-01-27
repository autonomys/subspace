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
    use sp_domains::state_root_tracker::CoreDomainTracker;
    use sp_domains::DomainId;
    use sp_messenger::DomainTracker;
    use sp_runtime::traits::{CheckedAdd, CheckedSub, One};
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type for this pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Total number of confirmed state roots to store at a time.
        type ConfirmedStateRootsBound: Get<u32>;

        /// K depth confirmation for relayers to relay messages.
        type RelayerConfirmationDepth: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// All confirmed domain state roots bounded to the StateRootBound value.
    /// Max number of state roots per domain is bound to StateRootBound.
    #[pallet::storage]
    #[pallet::getter(fn confirmed_domain_state_roots)]
    pub(super) type ConfirmedDomainStateRoots<T: Config> = StorageDoubleMap<
        _,
        Identity,
        DomainId,
        Identity,
        T::BlockNumber,
        StateRootOf<T>,
        OptionQuery,
    >;

    /// All unconfirmed domain state roots.
    #[pallet::storage]
    #[pallet::getter(fn unconfirmed_domain_state_roots)]
    pub(super) type UnconfirmedDomainStateRoots<T: Config> = StorageDoubleMap<
        _,
        Identity,
        DomainId,
        Identity,
        T::BlockNumber,
        StateRootOf<T>,
        OptionQuery,
    >;

    /// Latest block number of the domain.
    #[pallet::storage]
    #[pallet::getter(fn latest_domain_block_number)]
    pub(super) type LatestDomainBlockNumber<T: Config> =
        StorageMap<_, Identity, DomainId, T::BlockNumber, OptionQuery>;

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
                Self::add_system_domain_state_root(
                    state_root_update.number,
                    state_root_update.state_root,
                );
            }

            Weight::zero()
        }
    }

    impl<T: Config> DomainTracker<T::BlockNumber, StateRootOf<T>> for Pallet<T> {
        fn storage_key_for_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
        ) -> StorageKey {
            StorageKey(ConfirmedDomainStateRoots::<T>::hashed_key_for(
                domain_id,
                block_number,
            ))
        }
    }

    impl<T: Config> CoreDomainTracker<T::BlockNumber, StateRootOf<T>> for Pallet<T> {
        fn add_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
            state_root: StateRootOf<T>,
        ) {
            let _ = Self::add_and_confirm_domain_state_root(domain_id, block_number, state_root);
        }
    }

    impl<T: Config> Pallet<T> {
        /// Adds new state root at a given block.
        /// Also, confirms block state root at confirmation depth.
        /// Also, prunes confirmed state roots beyond StateRootBound.
        pub fn add_system_domain_state_root(
            block_number: T::BlockNumber,
            state_root: StateRootOf<T>,
        ) {
            let _ =
                Self::add_and_confirm_domain_state_root(DomainId::SYSTEM, block_number, state_root);
        }

        fn add_and_confirm_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
            state_root: StateRootOf<T>,
        ) -> Option<()> {
            if let Some(latest_block_number) = LatestDomainBlockNumber::<T>::get(domain_id) {
                if block_number <= latest_block_number {
                    // remove all the blocks that are pruned due to fork
                    let mut prune_block_above = block_number;
                    while UnconfirmedDomainStateRoots::<T>::take(domain_id, prune_block_above)
                        .is_some()
                    {
                        prune_block_above = prune_block_above.checked_add(&One::one())?;
                    }
                }
            }

            UnconfirmedDomainStateRoots::<T>::insert(domain_id, block_number, state_root);
            LatestDomainBlockNumber::<T>::insert(domain_id, block_number);
            // confirm state root at relayer confirmation depth
            let confirmed_block = block_number.checked_sub(&T::RelayerConfirmationDepth::get())?;
            let confirmed_state_root =
                UnconfirmedDomainStateRoots::<T>::take(domain_id, confirmed_block)?;
            ConfirmedDomainStateRoots::<T>::insert(
                domain_id,
                confirmed_block,
                confirmed_state_root,
            );

            // prune confirmed state roots that are below StateRootBound
            let mut prune_from_and_below = confirmed_block
                .checked_sub(&T::BlockNumber::from(T::ConfirmedStateRootsBound::get()))?;
            while ConfirmedDomainStateRoots::<T>::take(domain_id, prune_from_and_below).is_some() {
                prune_from_and_below = prune_from_and_below.checked_sub(&One::one())?
            }

            Some(())
        }

        /// Returns storage key to generate storage proof for the relayer.
        /// If the domain is not core, or block number is not confirmed yet, then we return None.
        pub fn storage_key_for_core_domain_state_root(
            domain_id: DomainId,
            block_number: T::BlockNumber,
        ) -> Option<Vec<u8>> {
            if !domain_id.is_core()
                || !ConfirmedDomainStateRoots::<T>::contains_key(domain_id, block_number)
            {
                return None;
            };

            Some(ConfirmedDomainStateRoots::<T>::hashed_key_for(
                domain_id,
                block_number,
            ))
        }
    }
}
