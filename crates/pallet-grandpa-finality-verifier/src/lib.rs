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

//! Substrate GRANDPA finality verifier
//!
//! This pallet is an on-chain GRANDPA finality verifier for Substrate based chains.
//!
//! The pallet is responsible for tracking GRANDPA validator set hand-offs. We only accept headers
//! with justifications signed by the current validator set we know of. The header is inspected for
//! a `ScheduledChanges` digest item, which is then used to update to next validator set.
//!
//! Since this pallet only tracks finalized headers it does not deal with forks. Forks can only
//! occur if the GRANDPA validator set on the bridged chain is either colluding or there is a severe
//! bug causing resulting in an equivocation. Such events are outside the scope of this pallet.
//! Shall the fork occur on the bridged chain governance intervention will be required to
//! re-initialize the bridge and track the right fork.

#![cfg_attr(not(feature = "std"), no_std)]

mod grandpa;

#[cfg(test)]
mod tests;

use frame_system::RawOrigin;
use sp_runtime::traits::BadOrigin;
use sp_std::fmt::Debug;

// Re-export in crate namespace for `construct_runtime!`
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        // Chain ID uniquely identifies a substrate based chain
        type ChainId: Parameter + Member + MaybeSerializeDeserialize + Debug + Default + Copy;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(PhantomData<T>);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Change `PalletOwner`.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
        pub fn set_owner(
            origin: OriginFor<T>,
            new_owner: Option<T::AccountId>,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;
            match new_owner {
                Some(new_owner) => {
                    PalletOwner::<T>::put(&new_owner);
                    log::info!(target: "runtime::grandpa-finality-verifier", "Setting pallet Owner to: {:?}", new_owner);
                }
                None => {
                    PalletOwner::<T>::kill();
                    log::info!(target: "runtime::grandpa-finality-verifier", "Removed Owner of pallet.");
                }
            }

            Ok(().into())
        }

        /// Halt or resume all pallet operations.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
        pub fn set_operational(
            origin: OriginFor<T>,
            chain_id: T::ChainId,
            operational: bool,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;
            <IsHalted<T>>::insert(chain_id, !operational);

            if operational {
                log::info!(target: "runtime::grandpa-finality-verifier", "Resuming pallet operations.");
            } else {
                log::warn!(target: "runtime::grandpa-finality-verifier", "Stopping pallet operations.");
            }

            Ok(().into())
        }
    }

    /// Optional pallet owner.
    ///
    /// Pallet owner has a right to halt all pallet operations and then resume it. If it is
    /// `None`, then there are no direct ways to halt/resume pallet operations, but other
    /// runtime methods may still be used to do that (i.e. democracy::referendum to update halt
    /// flag directly or call the `halt_operations`).
    #[pallet::storage]
    pub type PalletOwner<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// If true, all pallet transactions are failed immediately.
    #[pallet::storage]
    pub(super) type IsHalted<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ChainId, bool, ValueQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// All feed operations are halted.
        Halted,
    }

    /// Ensure that the origin is either root, or `PalletOwner`.
    fn ensure_owner_or_root<T: Config>(origin: T::Origin) -> Result<(), BadOrigin> {
        match origin.into() {
            Ok(RawOrigin::Root) => Ok(()),
            Ok(RawOrigin::Signed(ref signer))
                if Some(signer) == <PalletOwner<T>>::get().as_ref() =>
            {
                Ok(())
            }
            _ => Err(BadOrigin),
        }
    }

    /// Ensure that the pallet is in operational mode (not halted).
    fn ensure_operational<T: Config>(chain_id: T::ChainId) -> Result<(), Error<T>> {
        if <IsHalted<T>>::get(chain_id) {
            Err(Error::<T>::Halted)
        } else {
            Ok(())
        }
    }
}
