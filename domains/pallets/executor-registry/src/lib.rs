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

//! # Executor Registry Module

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use frame_support::traits::{Currency, LockIdentifier, LockableCurrency, WithdrawReasons};
pub use pallet::*;
use sp_arithmetic::Percent;
use sp_domains::ExecutorPublicKey;
use sp_executor_registry::ExecutorRegistry;
use sp_runtime::traits::{CheckedAdd, CheckedSub};
use sp_runtime::BoundedVec;
use sp_std::vec::Vec;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

const EXECUTOR_LOCK_ID: LockIdentifier = *b"executor";

const MIN_ACTIVE_EXECUTORS_FACTOR: Percent = Percent::from_percent(75);

#[frame_support::pallet]
mod pallet {
    use super::{BalanceOf, MIN_ACTIVE_EXECUTORS_FACTOR};
    use codec::Codec;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, LockableCurrency};
    use frame_system::pallet_prelude::*;
    use sp_arithmetic::traits::{BaseArithmetic, Unsigned};
    use sp_domains::ExecutorPublicKey;
    use sp_executor_registry::OnNewEpoch;
    use sp_runtime::traits::{
        BlockNumberProvider, CheckedAdd, CheckedSub, MaybeSerializeDeserialize, Zero,
    };
    use sp_runtime::FixedPointOperand;
    use sp_std::collections::btree_map::BTreeMap;
    use sp_std::fmt::Debug;
    use sp_std::vec::Vec;

    /// Same sematic as `AtLeast32Bit` but requires at least `u128`.
    pub trait AtLeast128Bit:
        BaseArithmetic + From<u16> + From<u32> + From<u64> + From<u128>
    {
    }

    impl<T: BaseArithmetic + From<u16> + From<u32> + From<u64> + From<u128>> AtLeast128Bit for T {}

    /// Same as `AtLeast128Bit` but bounded to be unsigned.
    pub trait AtLeast128BitUnsigned: AtLeast128Bit + Unsigned {}

    impl<T: AtLeast128Bit + Unsigned> AtLeast128BitUnsigned for T {}

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;

        /// The stake weight of an executor.
        type StakeWeight: Parameter
            + Member
            + AtLeast128BitUnsigned
            + Codec
            + Default
            + Copy
            + MaybeSerializeDeserialize
            + Debug
            + MaxEncodedLen
            + TypeInfo
            + FixedPointOperand
            + From<BalanceOf<Self>>;

        /// Minimum SSC required to be an executor.
        #[pallet::constant]
        type MinExecutorStake: Get<BalanceOf<Self>>;

        /// Maximum SSC that can be staked by a single executor.
        #[pallet::constant]
        type MaxExecutorStake: Get<BalanceOf<Self>>;

        /// Minimum number of executors.
        ///
        /// The minimum number of active executors is also constrained by this parameter with
        /// `MIN_ACTIVE_EXECUTORS_FACTOR`.
        #[pallet::constant]
        type MinExecutors: Get<u32>;

        /// Maximum number of executors.
        ///
        /// Increase this number gradually as the network grows.
        #[pallet::constant]
        type MaxExecutors: Get<u32>;

        /// Maximum number of ongoing unlocking items per executor.
        #[pallet::constant]
        type MaxWithdrawals: Get<u32>;

        /// Number of blocks the withdrawn stake has to remain locked before it can become free.
        ///
        /// Typically should be the same with fraud proof challenge period, like one week for arbitrum.
        ///
        /// TODO: Use Slot instead of BlockNumber, which is closer to the actual elapsed time.
        #[pallet::constant]
        type WithdrawalDuration: Get<Self::BlockNumber>;

        /// The amount of time each epoch should last in blocks.
        ///
        /// The executor set for the bundle election is scheduled to rotate on each new epoch.
        #[pallet::constant]
        type EpochDuration: Get<Self::BlockNumber>;

        /// What to do on epoch changes.
        type OnNewEpoch: OnNewEpoch<Self::AccountId, Self::StakeWeight>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Represents the inactive stake of an executor after calling `decrease_stake`.
    ///
    /// An executor called `decrease_stake` to withdraw some stakes, which
    /// have to wait for another lock-up period before making it transferrable again.
    #[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
    pub struct Withdrawal<Balance, BlockNumber> {
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
        pub public_key: ExecutorPublicKey,

        /// Address for receiving the execution reward.
        pub reward_address: T::AccountId,

        /// Whether the executor is actively participating in the bundle election.
        pub is_active: bool,

        /// Amount of balance at stake.
        ///
        /// Only the `stake` is used for in the forthcoming bundle election.
        pub stake: BalanceOf<T>,

        /// Inactive stake still being frozen, which can be freed up once mature.
        pub withdrawals: BoundedVec<Withdrawal<BalanceOf<T>, T::BlockNumber>, T::MaxWithdrawals>,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register the origin account as an executor.
        // TODO: proper weight
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn register(
            origin: OriginFor<T>,
            public_key: ExecutorPublicKey,
            reward_address: T::AccountId,
            is_active: bool,
            stake: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                stake >= T::MinExecutorStake::get(),
                Error::<T>::StakeTooSmall
            );
            ensure!(
                stake <= T::MaxExecutorStake::get(),
                Error::<T>::StakeTooLarge
            );
            ensure!(
                !Executors::<T>::contains_key(&who),
                Error::<T>::AlreadyExecutor
            );
            ensure!(
                Executors::<T>::count() <= T::MaxExecutors::get(),
                Error::<T>::TooManyExecutors
            );
            ensure!(
                T::Currency::free_balance(&who) >= stake,
                Error::<T>::InsufficientBalance
            );
            ensure!(
                KeyOwner::<T>::get(&public_key).is_none(),
                Error::<T>::DuplicatedKey
            );

            let executor_config =
                Self::apply_register(&who, public_key, reward_address, is_active, stake)?;

            Self::deposit_event(Event::<T>::NewExecutor {
                who,
                executor_config,
            });

            Ok(())
        }

        /// Declare no desire to be an executor and remove the registration.
        // TODO: proper weight
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn deregister(origin: OriginFor<T>) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // TODO:
            // Ensure the number of remaining executors can't be lower than T::MinExecutors.
            // Ensure the executor has no funds locked in this pallet(deposits and pending_withdrawals).
            // Remove the corresponding entry from the Executors.
            // Remove the corresponding entry from the KeyOwner.
            // Deposit an event Deregistered.

            Ok(())
        }

        /// Increase the executor's stake by locking some more balance.
        // TODO: proper weight
        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn increase_stake(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if !amount.is_zero() {
                ensure!(
                    T::Currency::free_balance(&who) >= amount,
                    Error::<T>::InsufficientBalance
                );

                Executors::<T>::try_mutate(&who, |maybe_executor_config| {
                    let executor_config = maybe_executor_config
                        .as_mut()
                        .ok_or(Error::<T>::NotExecutor)?;

                    let new_stake = executor_config
                        .stake
                        .checked_add(&amount)
                        .ok_or(Error::<T>::StakeTooLarge)?;

                    if new_stake > T::MaxExecutorStake::get() {
                        return Err(Error::<T>::StakeTooLarge);
                    }

                    executor_config.stake = new_stake;

                    Self::lock_fund(&who, executor_config.stake);

                    if executor_config.is_active {
                        Self::increase_total_active_stake(amount)?;
                    }

                    Ok(())
                })?;

                Self::deposit_event(Event::<T>::StakeIncreased { who, amount });
            }

            Ok(())
        }

        /// Decrease the executor stake by unlocking some balance.
        ///
        /// The reduced stake will be held locked for a while until it
        /// can be withdrawn to be transferrable.
        // TODO: proper weight
        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn decrease_stake(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if !amount.is_zero() {
                Executors::<T>::try_mutate(&who, |maybe_executor_config| {
                    let executor_config = maybe_executor_config
                        .as_mut()
                        .ok_or(Error::<T>::NotExecutor)?;

                    let new_stake = executor_config
                        .stake
                        .checked_sub(&amount)
                        .ok_or(Error::<T>::InsufficientStake)?;

                    if new_stake < T::MinExecutorStake::get() {
                        return Err(Error::<T>::InsufficientStake);
                    }

                    executor_config.stake = new_stake;

                    let new_withdrawal = Withdrawal {
                        amount,
                        locked_until: frame_system::Pallet::<T>::current_block_number()
                            + T::WithdrawalDuration::get(),
                    };

                    executor_config
                        .withdrawals
                        .try_push(new_withdrawal)
                        .map_err(|_| Error::<T>::TooManyWithdrawals)?;

                    if executor_config.is_active {
                        Self::decrease_total_active_stake(amount)?;
                    }

                    Ok(())
                })?;

                Self::deposit_event(Event::<T>::StakeDecreasedAndWithdrawalInitiated {
                    who,
                    amount,
                });
            }

            Ok(())
        }

        /// Remove the item at given index which is due in the unlocking queue.
        ///
        /// The balance being locked will become free on success.
        // TODO: proper weight
        #[pallet::call_index(4)]
        #[pallet::weight(10_000)]
        pub fn withdraw_decreased_stake(
            origin: OriginFor<T>,
            withdrawal_index: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if withdrawal_index as usize >= executor_config.withdrawals.len() {
                    return Err(Error::<T>::InvalidWithdrawalIndex.into());
                }

                let Withdrawal {
                    amount,
                    locked_until,
                } = executor_config
                    .withdrawals
                    .swap_remove(withdrawal_index as usize);

                let current_block_number = frame_system::Pallet::<T>::current_block_number();

                if current_block_number <= locked_until {
                    return Err(Error::<T>::PrematureWithdrawal.into());
                }

                let inactive_stake = executor_config
                    .withdrawals
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
        #[pallet::call_index(5)]
        #[pallet::weight(10_000)]
        pub fn pause_execution(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if executor_config.is_active {
                    let min_active_executors =
                        MIN_ACTIVE_EXECUTORS_FACTOR.mul_ceil(T::MinExecutors::get());

                    if TotalActiveExecutors::<T>::get() == min_active_executors {
                        return Err(Error::<T>::TooFewActiveExecutors.into());
                    }

                    executor_config.is_active = false;

                    Self::decrease_total_active_stake(executor_config.stake)?;
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
        #[pallet::call_index(6)]
        #[pallet::weight(10_000)]
        pub fn resume_execution(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Executors::<T>::try_mutate(&who, |maybe_executor_config| -> DispatchResult {
                let executor_config = maybe_executor_config
                    .as_mut()
                    .ok_or(Error::<T>::NotExecutor)?;

                if !executor_config.is_active {
                    executor_config.is_active = true;

                    Self::increase_total_active_stake(executor_config.stake)?;
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
        #[pallet::call_index(7)]
        #[pallet::weight(10_000)]
        pub fn update_public_key(
            origin: OriginFor<T>,
            next_key: ExecutorPublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                KeyOwner::<T>::get(&next_key).is_none(),
                Error::<T>::DuplicatedKey
            );

            ensure!(Executors::<T>::contains_key(&who), Error::<T>::NotExecutor);

            NextKey::<T>::insert(&who, &next_key);
            KeyOwner::<T>::insert(&next_key, &who);

            Self::deposit_event(Event::<T>::PublicKeyUpdated { who, next_key });

            Ok(())
        }

        /// Set a new reward address.
        // TODO: proper weight
        #[pallet::call_index(8)]
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

    #[cfg(feature = "std")]
    type GenesisExecutorInfo<T> = (
        <T as frame_system::Config>::AccountId,
        BalanceOf<T>,
        <T as frame_system::Config>::AccountId,
        ExecutorPublicKey,
    );

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub executors: Vec<GenesisExecutorInfo<T>>,
        pub slot_probability: (u64, u64),
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                executors: Vec::new(),
                slot_probability: (1u64, 1u64),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            assert!(
                self.executors.len() >= T::MinExecutors::get() as usize,
                "Too few genesis executors"
            );
            assert!(
                self.executors.len() <= T::MaxExecutors::get() as usize,
                "Too many genesis executors"
            );

            let mut authorities = Vec::new();
            for (executor, initial_stake, reward_address, public_key) in self.executors.clone() {
                assert!(
                    initial_stake >= T::MinExecutorStake::get()
                        && initial_stake <= T::MaxExecutorStake::get(),
                    "Initial stake can not be too small or too large"
                );
                assert!(
                    T::Currency::free_balance(&executor) >= initial_stake,
                    "Genesis executor does not have enough balance to stake."
                );

                Pallet::<T>::apply_register(
                    &executor,
                    public_key.clone(),
                    reward_address,
                    true,
                    initial_stake,
                )
                .expect("Initial executor register can not fail");

                let stake_weight: T::StakeWeight = initial_stake.into();
                authorities.push((public_key, stake_weight));
            }

            let bounded_authorities = BoundedVec::<_, T::MaxExecutors>::try_from(authorities)
                .expect("T::MaxExecutors bound is checked above; qed");
            Authorities::<T>::put(bounded_authorities);

            let total_stake_weight: T::StakeWeight = TotalActiveStake::<T>::get().into();
            TotalStakeWeight::<T>::put(total_stake_weight);

            SlotProbability::<T>::put(self.slot_probability);
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

        /// The number of executors exceeds the `T::MaxExecutors` bound.
        TooManyExecutors,

        /// An account does not have enough balance.
        InsufficientBalance,

        /// The user is not an executor.
        NotExecutor,

        /// Can not continue as the stake would be lower than the `T::MinExecutorStake` bound.
        ///
        /// If you want to withdraw all the stake, use `deregister` instead.
        InsufficientStake,

        /// The withdrawal queue size reached the upper bound.
        TooManyWithdrawals,

        /// The withdrawal entry does not exist for the given index.
        InvalidWithdrawalIndex,

        /// The withdrawal entry is still undue.
        PrematureWithdrawal,

        /// Too few active executors.
        TooFewActiveExecutors,

        /// Executor public key is already occupied.
        DuplicatedKey,

        /// An arithmetic overflow error.
        ArithmeticOverflow,

        /// An arithmetic underflow error.
        ArithmeticUnderflow,
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
        StakeIncreased {
            who: T::AccountId,
            amount: BalanceOf<T>,
        },

        /// An executor requested to unstake this account.
        StakeDecreasedAndWithdrawalInitiated {
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
        PublicKeyUpdated {
            who: T::AccountId,
            next_key: ExecutorPublicKey,
        },

        /// An executor updated its reward address.
        RewardAddressUpdated {
            who: T::AccountId,
            new: T::AccountId,
        },
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            // Enact the epoch change:
            // 1. Snapshot the latest state of active executors.
            // 2. Activate the new executor public key if any.
            if (block_number % T::EpochDuration::get()).is_zero() {
                let mut executor_weights = BTreeMap::new();

                // TODO: currently, we are iterating the Executors map, figure out how many executors
                // we can support with this approach and optimize it when it does not satisfy our requirement.
                let authorities = Executors::<T>::iter()
                    .filter(|(_who, executor_config)| executor_config.is_active)
                    .map(|(who, executor_config)| {
                        let public_key = match NextKey::<T>::take(&who) {
                            Some(new_key) => {
                                // It's okay to update a field while iterating the storage map.
                                //
                                // TODO: add a test that the public_key can be updated and the key_owner
                                // will be deleted as expected.
                                Executors::<T>::mutate(&who, |maybe_executor_config| {
                                    let executor_config = maybe_executor_config
                                        .as_mut()
                                        .expect("Executor config must exist; qed");

                                    // Clear the old key owner.
                                    KeyOwner::<T>::remove(&executor_config.public_key);

                                    executor_config.public_key = new_key.clone();
                                });

                                new_key
                            }
                            None => executor_config.public_key,
                        };

                        let stake_weight: T::StakeWeight = executor_config.stake.into();

                        executor_weights.insert(who, stake_weight);

                        (public_key, stake_weight)
                    })
                    .collect::<Vec<_>>();

                let bounded_authorities = BoundedVec::<_, T::MaxExecutors>::try_from(authorities)
                    .expect(
                        "T::MaxExecutors bound is ensured while registering a new executor; qed",
                    );
                Authorities::<T>::put(bounded_authorities);

                let total_stake_weight: T::StakeWeight = TotalActiveStake::<T>::get().into();
                TotalStakeWeight::<T>::put(total_stake_weight);

                T::OnNewEpoch::on_new_epoch(executor_weights);
            }

            // TODO: proper weight
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

    /// Pending executor public key for the next epoch.
    #[pallet::storage]
    pub(super) type NextKey<T: Config> =
        StorageMap<_, Twox64Concat, T::AccountId, ExecutorPublicKey, OptionQuery>;

    /// A map tracking the owner of current and next key of each executor.
    #[pallet::storage]
    #[pallet::getter(fn key_owner)]
    pub(super) type KeyOwner<T: Config> =
        StorageMap<_, Twox64Concat, ExecutorPublicKey, T::AccountId, OptionQuery>;

    /// Current epoch executor authorities.
    #[pallet::storage]
    #[pallet::getter(fn authorities)]
    pub(super) type Authorities<T: Config> = StorageValue<
        _,
        BoundedVec<(ExecutorPublicKey, T::StakeWeight), T::MaxExecutors>,
        ValueQuery,
    >;

    /// Total stake weight of authorities.
    #[pallet::storage]
    #[pallet::getter(fn total_stake_weight)]
    pub(super) type TotalStakeWeight<T: Config> = StorageValue<_, T::StakeWeight, ValueQuery>;

    /// How many bundles on average in a number of slots.
    ///
    /// TODO: Add a root call to update the slot probability.
    #[pallet::storage]
    #[pallet::getter(fn slot_probability)]
    pub(super) type SlotProbability<T> = StorageValue<_, (u64, u64), ValueQuery>;
}

impl<T: Config> ExecutorRegistry<T::AccountId, BalanceOf<T>, T::StakeWeight> for Pallet<T> {
    fn executor_stake(who: &T::AccountId) -> Option<BalanceOf<T>> {
        Executors::<T>::get(who).map(|executor| executor.stake)
    }

    fn executor_public_key(who: &T::AccountId) -> Option<ExecutorPublicKey> {
        Executors::<T>::get(who).map(|executor_config| executor_config.public_key)
    }

    fn key_owner_storage_key(executor_public_key: &ExecutorPublicKey) -> Vec<u8> {
        Self::key_owner_hashed_key_for(executor_public_key)
    }

    #[cfg(feature = "std")]
    fn authority_stake_weight(who: &T::AccountId) -> Option<T::StakeWeight> {
        Executors::<T>::get(who).and_then(|executor_config| {
            Authorities::<T>::get()
                .iter()
                .find_map(|(authority, stake_weight)| {
                    if *authority == executor_config.public_key {
                        Some(*stake_weight)
                    } else {
                        None
                    }
                })
        })
    }
}

impl<T: Config> Pallet<T> {
    pub fn key_owner_hashed_key_for(executor_public_key: &ExecutorPublicKey) -> Vec<u8> {
        KeyOwner::<T>::hashed_key_for(executor_public_key)
    }

    fn lock_fund(who: &T::AccountId, value: BalanceOf<T>) {
        T::Currency::set_lock(EXECUTOR_LOCK_ID, who, value, WithdrawReasons::all());
    }

    fn apply_register(
        who: &T::AccountId,
        public_key: ExecutorPublicKey,
        reward_address: T::AccountId,
        is_active: bool,
        stake: BalanceOf<T>,
    ) -> Result<ExecutorConfig<T>, Error<T>> {
        Self::lock_fund(who, stake);

        KeyOwner::<T>::insert(&public_key, who);

        let executor_config = ExecutorConfig {
            public_key,
            reward_address,
            is_active,
            stake,
            withdrawals: BoundedVec::default(),
        };
        Executors::<T>::insert(who, &executor_config);

        if is_active {
            Self::increase_total_active_stake(stake)?;
            TotalActiveExecutors::<T>::mutate(|total| {
                *total += 1;
            });
        }

        Ok(executor_config)
    }

    fn increase_total_active_stake(value: BalanceOf<T>) -> Result<(), Error<T>> {
        let old = TotalActiveStake::<T>::get();
        let new = old
            .checked_add(&value)
            .ok_or(Error::<T>::ArithmeticOverflow)?;
        TotalActiveStake::<T>::put(new);
        Ok(())
    }

    fn decrease_total_active_stake(value: BalanceOf<T>) -> Result<(), Error<T>> {
        let old = TotalActiveStake::<T>::get();
        let new = old
            .checked_sub(&value)
            .ok_or(Error::<T>::ArithmeticUnderflow)?;
        TotalActiveStake::<T>::put(new);
        Ok(())
    }
}
