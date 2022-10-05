// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
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

//! # Executor Registry Module

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use frame_support::traits::{Currency, LockIdentifier, LockableCurrency, WithdrawReasons};
pub use pallet::*;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

const EXECUTOR_LOCK_ID: LockIdentifier = *b"executor";

#[frame_support::pallet]
mod pallet {
    use super::BalanceOf;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, LockableCurrency};
    use frame_system::pallet_prelude::*;
    use sp_executor::ExecutorId;
    use sp_runtime::traits::{BlockNumberProvider, Saturating, Zero};

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;

        /// Minimum SSC required to be an executor.
        type MinExecutorStake: Get<BalanceOf<Self>>;

        /// Maximum SSC that can be staked by a single executor.
        type MaxExecutorStake: Get<BalanceOf<Self>>;

        /// Minimum number of executors
        type MinExecutorCount: Get<u32>;

        /// Maximum number of executors.
        ///
        /// Increase this number gradually as the network grows.
        type MaxExecutorCount: Get<u32>;

        /// Maximum number of ongoing unlocking items per executor.
        type MaxUnlockingCount: Get<u32>;

        /// Number of blocks the withdrawn stake has to remain locked before it can become free.
        ///
        /// Typically should be the same with fraud proof challenge period, like one week for arbitrum.
        ///
        /// TODO: Use Slot instead of BlockNumber, which is closer to the actual elapsed time.
        type UnlockingDuration: Get<Self::BlockNumber>;

        /// The amount of time each epoch should last in blocks.
        ///
        /// The executor set for the bundle election is scheduled to rotate on each new epoch.
        type EpochDuration: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Represents the inactive stake of an executor after calling `unlock_stake`.
    ///
    /// An executor called `unlock_stake` to withdraw some stakes, which
    /// have to wait for another lock-up period before making it transferrable again.
    #[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
    pub struct Unlocking<Balance, BlockNumber> {
        /// Amount of the unlocking balance.
        pub amount: Balance,
        /// Block number after which the balance can be really unlocked.
        pub locked_until: BlockNumber,
    }

    /// Executor configuration.
    #[derive(DebugNoBound, Encode, Decode, TypeInfo, CloneNoBound, PartialEqNoBound, EqNoBound)]
    #[scale_info(skip_type_params(T))]
    pub struct ExecutorConfig<T: Config> {
        /// Executor's signing key.
        pub public_key: ExecutorId,

        /// Address for receiving the execution reward.
        pub reward_address: T::AccountId,

        /// Whether the executor is actively participating in the bundle election.
        pub is_active: bool,

        /// Amount of balance at stake.
        ///
        /// Only the `stake` is used for in the forthcoming bundle election.
        pub stake: BalanceOf<T>,

        /// Inactive stake still being frozen, which can be freed up once mature.
        pub unlockings: BoundedVec<Unlocking<BalanceOf<T>, T::BlockNumber>, T::MaxUnlockingCount>,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register the origin account as an executor.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn register(
            origin: OriginFor<T>,
            executor_config: ExecutorConfig<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                executor_config.stake >= T::MinExecutorStake::get(),
                Error::<T>::StakeTooSmall
            );
            ensure!(
                executor_config.stake <= T::MaxExecutorStake::get(),
                Error::<T>::StakeTooLarge
            );
            ensure!(
                !Executors::<T>::contains_key(&who),
                Error::<T>::AlreadyExecutor
            );
            ensure!(
                Executors::<T>::count() <= T::MaxExecutorCount::get(),
                Error::<T>::TooManyExecutors
            );
            ensure!(
                T::Currency::free_balance(&who) >= executor_config.stake,
                Error::<T>::InsufficientBalance
            );
            // TODO: executor_config.public_key sanity check.

            Self::lock_fund(&who, executor_config.stake);

            // Make the unlockings right forcibly.
            let executor_config = ExecutorConfig {
                unlockings: BoundedVec::default(),
                ..executor_config
            };
            Executors::<T>::insert(&who, &executor_config);

            if executor_config.is_active {
                TotalActiveStake::<T>::mutate(|total| {
                    *total += executor_config.stake;
                });
                TotalActiveExecutors::<T>::mutate(|total| {
                    *total += 1;
                });
            }

            Self::deposit_event(Event::<T>::NewExecutor {
                who,
                executor_config,
            });

            Ok(())
        }

        /// Declare no desire to be an executor and remove the registration.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn deregister(origin: OriginFor<T>) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // TODO:
            // Ensure the number of remaining executors can't be lower than T::MinExecutorCount.
            // Ensure the executor has no funds locked in this pallet(deposits and pending_withdrawals).
            // Remove the corresponding entry from the Executors.
            // Deposit an event Deregistered.

            Ok(())
        }

        /// Increase the executor's stake by locking some more balance.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn stake_extra(origin: OriginFor<T>, extra: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if !extra.is_zero() {
                ensure!(
                    T::Currency::free_balance(&who) >= extra,
                    Error::<T>::InsufficientBalance
                );

                Executors::<T>::try_mutate(&who, |maybe_executor_config| {
                    let executor_config = maybe_executor_config
                        .as_mut()
                        .ok_or(Error::<T>::NotExecutor)?;

                    executor_config.stake = executor_config.stake.saturating_add(extra);

                    if executor_config.stake > T::MaxExecutorStake::get() {
                        return Err(Error::<T>::StakeTooLarge);
                    }

                    Self::lock_fund(&who, executor_config.stake);

                    if executor_config.is_active {
                        TotalActiveStake::<T>::mutate(|total| {
                            *total += extra;
                        });
                    }

                    Ok(())
                })?;

                Self::deposit_event(Event::<T>::Staked { who, extra });
            }

            Ok(())
        }

        /// Decrease the executor stake by unlocking some balance.
        ///
        /// The reduced stake will be held locked for a while until it
        /// can be withdrawn to be transferrable.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn unlock_stake(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if !amount.is_zero() {
                Executors::<T>::try_mutate(&who, |maybe_executor_config| {
                    let executor_config = maybe_executor_config
                        .as_mut()
                        .ok_or(Error::<T>::NotExecutor)?;

                    executor_config.stake = executor_config.stake.saturating_sub(amount);

                    if executor_config.stake < T::MinExecutorStake::get() {
                        return Err(Error::<T>::InsufficientStake);
                    }

                    let new_unlocking = Unlocking {
                        amount,
                        locked_until: frame_system::Pallet::<T>::current_block_number()
                            + T::UnlockingDuration::get(),
                    };

                    executor_config
                        .unlockings
                        .try_push(new_unlocking)
                        .map_err(|_| Error::<T>::TooManyUnlockings)?;

                    if executor_config.is_active {
                        TotalActiveStake::<T>::mutate(|total| {
                            *total -= amount;
                        });
                    }

                    Ok(())
                })?;

                Self::deposit_event(Event::<T>::UnlockStakeInitiated { who, amount });
            }

            Ok(())
        }

        /// Remove the item at given index which is due in the unlocking queue.
        ///
        /// The balance being locked will become free on success.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn withdraw_unlocked_stake(
            origin: OriginFor<T>,
            unlocking_index: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if unlocking_index as usize >= executor_config.unlockings.len() {
                    return Err(Error::<T>::InvalidUnlockingIndex.into());
                }

                let Unlocking {
                    amount,
                    locked_until,
                } = executor_config
                    .unlockings
                    .swap_remove(unlocking_index as usize);

                let current_block_number = frame_system::Pallet::<T>::current_block_number();

                if current_block_number <= locked_until {
                    return Err(Error::<T>::PrematureWithdrawal.into());
                }

                let inactive_stake = executor_config
                    .unlockings
                    .iter()
                    .fold(Zero::zero(), |acc, x| acc + x.amount);

                let new_total = executor_config.stake + inactive_stake;

                Self::lock_fund(&who, new_total);

                Self::deposit_event(Event::<T>::WithdrawalCompleted {
                    who: who.clone(),
                    withdrawn: amount,
                });

                Ok(())
            })
        }

        /// Stop participating in the bundle election temporarily.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn pause_execution(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if executor_config.is_active {
                    if TotalActiveExecutors::<T>::get() as usize == 1 {
                        return Err(Error::<T>::EmptyActiveExecutors.into());
                    }

                    executor_config.is_active = false;

                    TotalActiveStake::<T>::mutate(|total| {
                        *total -= executor_config.stake;
                    });
                    TotalActiveExecutors::<T>::mutate(|total| {
                        *total -= 1;
                    });

                    Self::deposit_event(Event::<T>::Paused { who: who.clone() });
                }

                Ok(())
            })
        }

        /// Participate in the bundle election again.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn resume_execution(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if !executor_config.is_active {
                    executor_config.is_active = true;

                    TotalActiveStake::<T>::mutate(|total| {
                        *total += executor_config.stake;
                    });
                    TotalActiveExecutors::<T>::mutate(|total| {
                        *total += 1;
                    });

                    Self::deposit_event(Event::<T>::Resumed { who: who.clone() });
                }

                Ok(())
            })
        }

        /// Set a new executor public key.
        ///
        /// It won't take effect until next epoch.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn update_public_key(origin: OriginFor<T>, _new: ExecutorId) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            Ok(())
        }

        /// Set a new reward address.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn update_reward_address(origin: OriginFor<T>, new: T::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if executor_config.reward_address != new {
                    executor_config.reward_address = new.clone();

                    Self::deposit_event(Event::<T>::RewardAddressUpdated {
                        who: who.clone(),
                        new,
                    });
                }

                Ok(())
            })
        }
    }

    type GenesisExecutorInfo<T> = (
        <T as frame_system::Config>::AccountId,
        BalanceOf<T>,
        <T as frame_system::Config>::AccountId,
        ExecutorId,
    );

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub executors: Vec<GenesisExecutorInfo<T>>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                executors: Vec::new(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for (executor, initial_stake, reward_address, executor_id) in self.executors.clone() {
                assert!(
                    initial_stake >= T::MinExecutorStake::get()
                        && initial_stake <= T::MaxExecutorStake::get(),
                    "Initial stake can not be too small or too large"
                );
                assert!(
                    T::Currency::free_balance(&executor) >= initial_stake,
                    "Genesis executor does not have enough balance to stake."
                );
                Pallet::<T>::lock_fund(&executor, initial_stake);
                Executors::<T>::insert(
                    executor,
                    ExecutorConfig {
                        public_key: executor_id,
                        reward_address,
                        is_active: true,
                        stake: initial_stake,
                        unlockings: BoundedVec::default(),
                    },
                );
                TotalActiveStake::<T>::mutate(|total| {
                    *total += initial_stake;
                });
                TotalActiveExecutors::<T>::mutate(|total| {
                    *total += 1;
                });
            }
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The amount of deposit is smaller than the `T::MinExecutorStake` bound.
        StakeTooSmall,

        /// The amount of deposit is larger than the `T::MaxExecutorStake` bound.
        StakeTooLarge,

        /// An account is already an executor.
        AlreadyExecutor,

        /// The number of executors exceeds the `T::MaxExecutorCount` bound.
        TooManyExecutors,

        /// An account does not have enough balance.
        InsufficientBalance,

        /// The user is not an executor.
        NotExecutor,

        /// Can not continue as the stake would be lower than the `T::MinExecutorStake` bound.
        ///
        /// If you want to withdraw all the stake, use `deregister` instead.
        InsufficientStake,

        /// The unlocking queue size reached the upper bound.
        TooManyUnlockings,

        /// The unlocking entry does not exist for the given index.
        InvalidUnlockingIndex,

        /// The unlocking entry is still undue.
        PrematureWithdrawal,

        /// Active executors can not be empty.
        EmptyActiveExecutors,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new executor.
        NewExecutor {
            who: T::AccountId,
            executor_config: ExecutorConfig<T>,
        },

        /// An executor deposited this account.
        Staked {
            who: T::AccountId,
            extra: BalanceOf<T>,
        },

        /// An executor requested to unstake this account.
        UnlockStakeInitiated {
            who: T::AccountId,
            amount: BalanceOf<T>,
        },

        /// The funds locked as inactive stake became free.
        WithdrawalCompleted {
            who: T::AccountId,
            withdrawn: BalanceOf<T>,
        },

        /// An executor paused the execution.
        Paused { who: T::AccountId },

        /// An executor resumed the execution.
        Resumed { who: T::AccountId },

        /// An executor updated its public key.
        PublicKeyUpdated { who: T::AccountId, new: ExecutorId },

        /// An executor updated its reward address.
        RewardAddressUpdated {
            who: T::AccountId,
            new: T::AccountId,
        },
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            if (block_number % T::EpochDuration::get()).is_zero() {
                // TODO: Enact the epoch change.
            }
            Weight::zero()
        }

        fn on_idle(_n: T::BlockNumber, _remaining_weight: Weight) -> Weight {
            // TODO: Release the mature withdrawal automatically so that users do not have to call
            // `withdraw_unlocked_deposit` manually.
            Weight::zero()
        }
    }

    /// A map tracking all the executors.
    #[pallet::storage]
    pub(super) type Executors<T: Config> =
        CountedStorageMap<_, Twox64Concat, T::AccountId, ExecutorConfig<T>, OptionQuery>;

    /// Total amount of active stake in the system.
    ///
    /// Sum of the `stake` of each active executor.
    #[pallet::storage]
    pub(super) type TotalActiveStake<T> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Total number of active executors.
    #[pallet::storage]
    pub(super) type TotalActiveExecutors<T> = StorageValue<_, u32, ValueQuery>;
}

impl<T: Config> Pallet<T> {
    #[inline]
    fn lock_fund(who: &T::AccountId, value: BalanceOf<T>) {
        T::Currency::set_lock(EXECUTOR_LOCK_ID, who, value, WithdrawReasons::all());
    }
}
