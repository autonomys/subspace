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

use codec::{Codec, Decode, Encode};
use frame_support::sp_runtime::traits::Zero;
use frame_support::traits::{Currency, Get};
use frame_support::weights::Weight;
pub use pallet::*;
use scale_info::TypeInfo;
use subspace_runtime_primitives::FindBlockRewardsAddress;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub trait WeightInfo {
    fn on_initialize() -> Weight;
}

#[derive(Encode, Decode, TypeInfo)]
struct CollectedFees<Balance: Codec> {
    storage: Balance,
    compute: Balance,
    // TODO: Split tips for storage and compute proportionally?
    tips: Balance,
}

#[frame_support::pallet]
mod pallet {
    use super::{BalanceOf, CollectedFees, WeightInfo};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;
    use subspace_runtime_primitives::FindBlockRewardsAddress;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-transaction-fees` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Minimum desired number of replicas of the blockchain to be stored by the network,
        /// impacts storage fees.
        #[pallet::constant]
        type MinReplicationFactor: Get<u16>;

        /// How much (ratio) of storage fees escrow should be given to farmer each block as a
        /// reward.
        #[pallet::constant]
        type StorageFeesEscrowBlockReward: Get<(u64, u64)>;

        /// How much (ratio) of storage fees collected in a block should be put into storage fees
        /// escrow (with remaining issued to farmer immediately).
        #[pallet::constant]
        type StorageFeesEscrowBlockTax: Get<(u64, u64)>;

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

        type FindBlockRewardsAddress: FindBlockRewardsAddress<Self::AccountId>;

        type WeightInfo: WeightInfo;
    }

    /// Escrow of storage fees, a portion of it is released to the block author on every block
    /// and portion of storage fees goes back into this pot.
    #[pallet::storage]
    #[pallet::getter(fn storage_fees_escrow)]
    pub(super) type CollectedStorageFeesEscrow<T> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Temporary value (cleared at block finalization) which contains cached value of
    /// `TransactionByteFee` for current block.
    #[pallet::storage]
    pub(super) type TransactionByteFee<T> = StorageValue<_, BalanceOf<T>>;

    /// Temporary value (cleared at block finalization) which contains current block author, so we
    /// can issue rewards during block finalization.
    #[pallet::storage]
    pub(super) type BlockAuthor<T: Config> = StorageValue<_, T::AccountId>;

    /// Temporary value (cleared at block finalization) which contains current block fees, so we can
    /// issue rewards during block finalization.
    #[pallet::storage]
    pub(super) type CollectedBlockFees<T: Config> = StorageValue<_, CollectedFees<BalanceOf<T>>>;

    /// Pallet rewards for issuing rewards to block producers.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// `pallet-transaction-fees` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Storage fees escrow change.
        StorageFeesEscrowChange {
            /// State of storage fees escrow before block execution.
            before: BalanceOf<T>,
            /// State of storage fees escrow after block execution.
            after: BalanceOf<T>,
        },
        /// Storage fees.
        StorageFeesReward {
            /// Receiver of the storage fees.
            who: T::AccountId,
            /// Amount of collected storage fees.
            amount: BalanceOf<T>,
        },
        /// Compute fees.
        ComputeFeesReward {
            /// Receiver of the compute fees.
            who: T::AccountId,
            /// Amount of collected compute fees.
            amount: BalanceOf<T>,
        },
        /// Tips.
        TipsReward {
            /// Receiver of the tip.
            who: T::AccountId,
            /// Amount of collected tips.
            amount: BalanceOf<T>,
        },
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        BalanceOf<T>: From<u8> + From<u64>,
    {
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            Self::do_initialize(now);
            T::WeightInfo::on_initialize()
        }

        fn on_finalize(now: BlockNumberFor<T>) {
            Self::do_finalize(now);
        }
    }
}

impl<T: Config> Pallet<T>
where
    BalanceOf<T>: From<u64>,
{
    fn do_initialize(_n: T::BlockNumber) {
        let block_author = T::FindBlockRewardsAddress::find_block_rewards_address(
            frame_system::Pallet::<T>::digest()
                .logs
                .iter()
                .filter_map(|d| d.as_pre_runtime()),
        )
        .expect("Block author must always be present; qed");

        BlockAuthor::<T>::put(block_author);

        CollectedBlockFees::<T>::put(CollectedFees {
            storage: BalanceOf::<T>::zero(),
            compute: BalanceOf::<T>::zero(),
            tips: BalanceOf::<T>::zero(),
        });
    }

    // TODO: Fees will be split between farmers and executors in the future
    fn do_finalize(_n: T::BlockNumber) {
        TransactionByteFee::<T>::take();

        let block_author =
            BlockAuthor::<T>::take().expect("`BlockAuthor` was set in `on_initialize`; qed");

        let original_storage_fees_escrow = CollectedStorageFeesEscrow::<T>::get();
        let collected_fees = CollectedBlockFees::<T>::take()
            .expect("`CollectedBlockFees` was set in `on_initialize`; qed");

        let mut storage_fees_escrow = original_storage_fees_escrow;

        // Take a portion of storage fees escrow as a farmer reward.
        let storage_fees_escrow_reward = storage_fees_escrow
            / T::StorageFeesEscrowBlockReward::get().1.into()
            * T::StorageFeesEscrowBlockReward::get().0.into();
        storage_fees_escrow -= storage_fees_escrow_reward;

        // Take a portion of storage fees collected in this block as a farmer reward.
        let collected_storage_fees_reward = collected_fees.storage
            / T::StorageFeesEscrowBlockTax::get().1.into()
            * (T::StorageFeesEscrowBlockTax::get().1 - T::StorageFeesEscrowBlockTax::get().0)
                .into();
        storage_fees_escrow += collected_fees.storage - collected_storage_fees_reward;

        // Update storage fees escrow.
        if storage_fees_escrow != original_storage_fees_escrow {
            CollectedStorageFeesEscrow::<T>::put(storage_fees_escrow);
            Self::deposit_event(Event::<T>::StorageFeesEscrowChange {
                before: original_storage_fees_escrow,
                after: storage_fees_escrow,
            });
        }

        // Issue storage fees reward.
        let storage_fees_reward = storage_fees_escrow_reward + collected_storage_fees_reward;
        if !storage_fees_reward.is_zero() {
            T::Currency::deposit_into_existing(&block_author, storage_fees_reward).expect(
                "Farmer account must have already received the block reward before fees are \
                collected; qed",
            );
            Self::deposit_event(Event::<T>::StorageFeesReward {
                who: block_author.clone(),
                amount: storage_fees_reward,
            });
        }

        // Issue compute fees reward.
        if !collected_fees.compute.is_zero() {
            T::Currency::deposit_into_existing(&block_author, collected_fees.compute)
                .expect("Executor account must already exist before they execute the block; qed");
            Self::deposit_event(Event::<T>::ComputeFeesReward {
                who: block_author.clone(),
                amount: collected_fees.compute,
            });
        }

        // Issue tips reward.
        if !collected_fees.tips.is_zero() {
            T::Currency::deposit_into_existing(&block_author, collected_fees.tips)
                .expect("Executor account must already exist before they execute the block; qed");
            Self::deposit_event(Event::<T>::TipsReward {
                who: block_author,
                amount: collected_fees.tips,
            });
        }
    }

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

    pub fn note_transaction_fees(
        storage_fee: BalanceOf<T>,
        compute_fee: BalanceOf<T>,
        tip: BalanceOf<T>,
    ) {
        CollectedBlockFees::<T>::mutate(|collected_block_fees| {
            let collected_block_fees = collected_block_fees
                .as_mut()
                .expect("`CollectedBlockFees` was set in `on_initialize`; qed");
            collected_block_fees.storage += storage_fee;
            collected_block_fees.compute += compute_fee;
            collected_block_fees.tips += tip;
        });
    }
}
