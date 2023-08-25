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

//! Pallet Domain Transaction Fees

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    use codec::{Codec, MaxEncodedLen};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;
    use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Saturating, Zero};
    use sp_runtime::FixedPointOperand;
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The balance of an account.
        type Balance: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Codec
            + Default
            + Copy
            + MaybeSerializeDeserialize
            + Debug
            + MaxEncodedLen
            + TypeInfo
            + FixedPointOperand;
    }

    /// The accumulated rewards of the current block
    ///
    /// Currently, the only source of rewards is the transaction fees, in the furture it
    /// will include the XDM reward.
    #[pallet::storage]
    #[pallet::getter(fn block_transaction_fee)]
    pub(super) type BlockRewards<T: Config> = StorageValue<_, T::Balance, ValueQuery>;

    /// Pallet operator-rewards to store the accumulated rewards of the current block
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            BlockRewards::<T>::set(Zero::zero());
            T::DbWeight::get().writes(1)
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn note_operator_rewards(rewards: T::Balance) {
            let next_block_rewards = BlockRewards::<T>::get().saturating_add(rewards);
            BlockRewards::<T>::set(next_block_rewards);
        }
    }
}
