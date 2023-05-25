//! Benchmarking for `pallet-executor-registry`.

// Only enable this module for benchmarking.
#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as ExecutorRegistry;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::Get;
use frame_system::{Pallet as System, RawOrigin};
use sp_core::crypto::ByteArray;
use sp_domains::ExecutorPublicKey;
use sp_executor_registry::ExecutorRegistry as ExecutorRegistryT;
use sp_runtime::Saturating;

const SEED: u32 = 0;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn register() {
        let stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, stake);
        let public_key = ExecutorPublicKey::from_slice(&[1; 32]).unwrap();

        #[extrinsic_call]
        _(
            RawOrigin::Signed(executor.clone()),
            public_key.clone(),
            executor.clone(),
            true,
            stake,
        );

        assert_eq!(
            ExecutorRegistry::<T>::executor_stake(&executor),
            Some(stake)
        );
        assert_eq!(
            ExecutorRegistry::<T>::executor_public_key(&executor),
            Some(public_key)
        );
    }

    #[benchmark]
    fn increase_stake() {
        let init_stake = T::MinExecutorStake::get();
        let increasing_stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, init_stake + increasing_stake);

        registry_executor::<T>(executor.clone(), init_stake, true);

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()), increasing_stake);

        assert_eq!(
            ExecutorRegistry::<T>::executor_stake(&executor),
            Some(init_stake + increasing_stake)
        );
    }

    #[benchmark]
    fn decrease_stake() {
        let init_stake = T::MinExecutorStake::get().saturating_mul(2u32.into());
        let decreasing_stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, init_stake);

        registry_executor::<T>(executor.clone(), init_stake, true);

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()), decreasing_stake);

        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert_eq!(executor_config.stake, init_stake - decreasing_stake);
        assert_eq!(executor_config.withdrawals.len(), 1);
    }

    #[benchmark]
    fn withdraw_stake() {
        let init_stake = T::MinExecutorStake::get().saturating_mul(2u32.into());
        let decreasing_stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, init_stake);

        // Register an executor and create a withdrawal
        registry_executor::<T>(executor.clone(), init_stake, true);
        assert_ok!(ExecutorRegistry::<T>::decrease_stake(
            RawOrigin::Signed(executor.clone()).into(),
            decreasing_stake,
        ));
        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert_eq!(executor_config.stake, init_stake - decreasing_stake);
        assert_eq!(executor_config.withdrawals.len(), 1);

        // Going through the withdraw duration period
        let current_block = System::<T>::block_number();
        System::<T>::set_block_number(current_block + T::WithdrawalDuration::get() + 1u32.into());

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()), 0);

        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert!(executor_config.withdrawals.is_empty());
    }

    #[benchmark]
    fn pause_execution() {
        let stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, stake);

        registry_executor::<T>(executor.clone(), stake, true);
        let total_active_executor = TotalActiveExecutors::<T>::get();

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()));

        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert!(!executor_config.is_active);
        assert_eq!(TotalActiveExecutors::<T>::get(), total_active_executor - 1);
    }

    #[benchmark]
    fn resume_execution() {
        let stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, stake);

        // Register an inactive executor
        registry_executor::<T>(executor.clone(), stake, false);
        let total_active_executor = TotalActiveExecutors::<T>::get();

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()));

        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert!(executor_config.is_active);
        assert_eq!(TotalActiveExecutors::<T>::get(), total_active_executor + 1);
    }

    #[benchmark]
    fn update_public_key() {
        let stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, stake);

        registry_executor::<T>(executor.clone(), stake, true);

        let new_public_key = ExecutorPublicKey::from_slice(&[2; 32]).unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(executor.clone()), new_public_key.clone());

        assert_eq!(NextKey::<T>::get(&executor), Some(new_public_key.clone()));
        assert_eq!(KeyOwner::<T>::get(&new_public_key), Some(executor));
    }

    #[benchmark]
    fn update_reward_address() {
        let stake = T::MinExecutorStake::get();
        let executor = funded_account::<T>("executor", 1, stake);

        registry_executor::<T>(executor.clone(), stake, true);

        let new_reward_address: T::AccountId = account("new_reward_address", 2, SEED);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(executor.clone()),
            new_reward_address.clone(),
        );

        let executor_config =
            Executors::<T>::get(&executor).expect("Should be able to get the executor config");
        assert_eq!(executor_config.reward_address, new_reward_address);
    }

    // Create an account with the given fund plus the `ExistentialDeposit`
    fn funded_account<T: Config>(
        name: &'static str,
        index: u32,
        fund: BalanceOf<T>,
    ) -> T::AccountId {
        let account = account(name, index, SEED);
        T::Currency::make_free_balance_be(&account, fund + T::Currency::minimum_balance());
        account
    }

    // Registry an executor for later operations
    fn registry_executor<T: Config>(executor: T::AccountId, stake: BalanceOf<T>, is_active: bool) {
        let public_key = ExecutorPublicKey::from_slice(&[1; 32]).unwrap();

        assert_ok!(ExecutorRegistry::<T>::register(
            RawOrigin::Signed(executor.clone()).into(),
            public_key.clone(),
            executor.clone(),
            is_active,
            stake,
        ));

        assert_eq!(
            ExecutorRegistry::<T>::executor_stake(&executor),
            Some(stake)
        );
        assert_eq!(
            ExecutorRegistry::<T>::executor_public_key(&executor),
            Some(public_key)
        );
    }

    impl_benchmark_test_suite!(
        ExecutorRegistry,
        crate::tests::new_test_ext(),
        crate::tests::Test
    );
}
