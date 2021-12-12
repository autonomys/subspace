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

//! Pallet for charging and re-distributing transaction fees.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

mod default_weights;

use frame_support::traits::{Currency, Get};
use frame_support::weights::Weight;
pub use pallet::*;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub trait WeightInfo {
    fn on_initialize() -> Weight;
}

#[frame_support::pallet]
mod pallet {
    use super::{BalanceOf, WeightInfo};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-transaction-fees` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Minimum desired number of replicas of the blockchain to be stored by the network,
        /// impacts storage fees.
        #[pallet::constant]
        type MinReplicationFactor: Get<u16>;

        /// How many credits there is in circulation.
        #[pallet::constant]
        type CreditSupply: Get<BalanceOf<Self>>;

        /// How much space there is on the network.
        #[pallet::constant]
        type TotalSpacePledged: Get<u64>;

        /// How big is the history of the blockchain in archived state (thus includes erasure
        /// coding, but not replication).
        #[pallet::constant]
        type BlockchainHistorySize: Get<u64>;

        type Currency: Currency<Self::AccountId>;

        type WeightInfo: WeightInfo;
    }

    /// Temporary value (cleared at block finalization) which contains cached value of
    /// `TransactionByteFee` for current block.
    #[pallet::storage]
    pub(super) type TransactionByteFee<T> = StorageValue<_, BalanceOf<T>>;

    /// Pallet rewards for issuing rewards to block producers.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// `pallet-transaction-fees` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_n: BlockNumberFor<T>) {
            TransactionByteFee::<T>::take();
        }
    }
}

impl<T: Config> Pallet<T>
where
    BalanceOf<T>: From<u64>,
{
    pub fn transaction_byte_fee() -> BalanceOf<T> {
        if let Some(transaction_byte_fee) = TransactionByteFee::<T>::get() {
            return transaction_byte_fee;
        }

        let credit_supply = T::CreditSupply::get();

        let transaction_byte_fee = match T::TotalSpacePledged::get().checked_sub(
            T::BlockchainHistorySize::get() * u64::from(T::MinReplicationFactor::get()),
        ) {
            Some(free_space) if free_space > 0 => credit_supply / BalanceOf::<T>::from(free_space),
            _ => credit_supply,
        };

        // Cache value for this block.
        TransactionByteFee::<T>::put(transaction_byte_fee);

        transaction_byte_fee
    }

    pub fn distribute_transaction_fees(
        storage_fee: BalanceOf<T>,
        compute_fee: BalanceOf<T>,
        tip: BalanceOf<T>,
    ) {
        // TODO
    }
}
