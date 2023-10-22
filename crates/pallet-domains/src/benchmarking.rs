//! Benchmarking for `pallet-domains`.

use super::*;
use crate::alloc::borrow::ToOwned;
use crate::domain_registry::DomainConfig;
use crate::staking::{do_reward_operators, OperatorConfig, OperatorStatus, Withdraw};
use crate::staking_epoch::{do_finalize_domain_current_epoch, do_finalize_domain_staking};
use crate::Pallet as Domains;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::fungible::Mutate;
use frame_support::traits::Hooks;
use frame_support::weights::Weight;
use frame_system::{Pallet as System, RawOrigin};
use sp_core::crypto::UncheckedFrom;
use sp_domains::{
    dummy_opaque_bundle, DomainId, ExecutionReceipt, OperatorAllowList, OperatorId,
    OperatorPublicKey, RuntimeType,
};
use sp_runtime::traits::{BlockNumberProvider, CheckedAdd, One, SaturatedConversion};

const SEED: u32 = 0;

#[benchmarks]
mod benchmarks {
    use super::*;
    use sp_std::vec;

    /// Benchmark `submit_bundle` extrinsic with the worst possible conditions:
    /// - The bundle is the first bundle of the consensus block
    /// - The bundle contains receipt that will prune the block tree
    #[benchmark]
    fn submit_bundle() {
        let block_tree_pruning_depth = T::BlockTreePruningDepth::get().saturated_into::<u32>();
        let domain_id = register_domain::<T>();
        let (_, operator_id) =
            register_helper_operator::<T>(domain_id, T::Currency::minimum_balance());

        let mut receipt =
            BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero())
                .first()
                .and_then(BlockTreeNodes::<T>::get)
                .expect("genesis receipt must exist")
                .execution_receipt;
        for i in 1..=(block_tree_pruning_depth + 1) {
            let consensus_block_number = i.into();
            let domain_block_number = i.into();

            // Run to `block_number`
            run_to_block::<T>(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number - One::one()),
            );

            // Submit a bundle with the receipt of the last block
            let bundle = dummy_opaque_bundle(domain_id, operator_id, receipt);
            assert_ok!(Domains::<T>::submit_bundle(RawOrigin::None.into(), bundle));

            // Create ER for the above bundle
            let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);
            let parent_domain_block_receipt = BlockTree::<T>::get(domain_id, head_receipt_number)
                .first()
                .cloned()
                .expect("parent receipt must exist");
            receipt = ExecutionReceipt::dummy(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number),
                domain_block_number,
                parent_domain_block_receipt,
            );
        }
        assert_eq!(
            Domains::<T>::head_receipt_number(domain_id),
            (block_tree_pruning_depth).into()
        );

        // Construct bundle that will prune the block tree
        let block_number = (block_tree_pruning_depth + 2).into();
        run_to_block::<T>(
            block_number,
            frame_system::Pallet::<T>::block_hash(block_number - One::one()),
        );
        let bundle = dummy_opaque_bundle(domain_id, operator_id, receipt);

        #[extrinsic_call]
        submit_bundle(RawOrigin::None, bundle);

        assert_eq!(
            Domains::<T>::head_receipt_number(domain_id),
            (block_tree_pruning_depth + 1).into()
        );
        assert_eq!(Domains::<T>::oldest_receipt_number(domain_id), 1u32.into());
    }

    /// Benchmark pending staking operation with the worst possible conditions:
    /// - There are `MaxPendingStakingOperation` number of pending staking operation
    /// - All pending staking operation are withdrawal that withdraw partial stake
    #[benchmark]
    fn pending_staking_operation() {
        let max_pending_staking_op = T::MaxPendingStakingOperation::get();
        let epoch_duration = T::StakeEpochDuration::get();
        let minimum_nominator_stake = T::Currency::minimum_balance();
        let withdraw_amount = T::MinOperatorStake::get();
        let operator_rewards =
            T::Currency::minimum_balance().saturating_mul(BalanceOf::<T>::from(100u32));

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);
        do_finalize_domain_current_epoch::<T>(domain_id, 0u32.into())
            .expect("finalize domain staking should success");

        for i in 0..max_pending_staking_op {
            let nominator = account("nominator", i, SEED);
            T::Currency::set_balance(
                &nominator,
                withdraw_amount * 2u32.into() + T::Currency::minimum_balance(),
            );
            assert_ok!(Domains::<T>::nominate_operator(
                RawOrigin::Signed(nominator).into(),
                operator_id,
                withdraw_amount * 2u32.into(),
            ));
        }
        do_finalize_domain_current_epoch::<T>(domain_id, epoch_duration)
            .expect("finalize domain staking should success");
        assert_eq!(PendingStakingOperationCount::<T>::get(domain_id), 0);

        for i in 0..max_pending_staking_op {
            let nominator = account("nominator", i, SEED);
            assert_ok!(Domains::<T>::withdraw_stake(
                RawOrigin::Signed(nominator).into(),
                operator_id,
                Withdraw::Some(withdraw_amount),
            ));
        }
        assert_eq!(
            PendingStakingOperationCount::<T>::get(domain_id) as u32,
            max_pending_staking_op
        );
        assert_eq!(
            PendingWithdrawals::<T>::iter_prefix_values(operator_id).count() as u32,
            max_pending_staking_op
        );

        #[block]
        {
            do_reward_operators::<T>(domain_id, vec![operator_id].into_iter(), operator_rewards)
                .expect("reward operator should success");

            do_finalize_domain_current_epoch::<T>(domain_id, epoch_duration * 2u32.into())
                .expect("finalize domain staking should success");
        }

        assert_eq!(PendingStakingOperationCount::<T>::get(domain_id), 0);
        assert_eq!(
            PendingWithdrawals::<T>::iter_prefix_values(operator_id).count(),
            0
        );
    }

    #[benchmark]
    fn register_domain_runtime() {
        let runtime_blob =
            include_bytes!("../res/evm_domain_test_runtime.compact.compressed.wasm").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();
        let runtime_hash = T::Hashing::hash(&runtime_blob);

        #[extrinsic_call]
        _(
            RawOrigin::Root,
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            runtime_blob,
        );

        let runtime_obj = RuntimeRegistry::<T>::get(runtime_id).expect("runtime object must exist");
        assert_eq!(runtime_obj.runtime_name, "evm-domain".to_owned());
        assert_eq!(runtime_obj.runtime_type, RuntimeType::Evm);
        assert_eq!(runtime_obj.hash, runtime_hash);
        assert_eq!(NextRuntimeId::<T>::get(), runtime_id + 1);
    }

    #[benchmark]
    fn upgrade_domain_runtime() {
        let runtime_blob =
            include_bytes!("../res/evm_domain_test_runtime.compact.compressed.wasm").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();

        // The `runtime_blob` have `spec_version = 1` thus we need to modify the runtime object
        // version to 0 to bypass the `can_upgrade_code` check when calling `upgrade_domain_runtime`
        assert_ok!(Domains::<T>::register_domain_runtime(
            RawOrigin::Root.into(),
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            runtime_blob.clone()
        ));
        RuntimeRegistry::<T>::mutate(runtime_id, |maybe_runtime_object| {
            let runtime_obj = maybe_runtime_object
                .as_mut()
                .expect("Runtime object must exist");
            runtime_obj.version.spec_version = 0;
        });

        #[extrinsic_call]
        _(RawOrigin::Root, runtime_id, runtime_blob.clone());

        let scheduled_at = frame_system::Pallet::<T>::current_block_number()
            .checked_add(&T::DomainRuntimeUpgradeDelay::get())
            .expect("must not overflow");
        let scheduled_upgrade = ScheduledRuntimeUpgrades::<T>::get(scheduled_at, runtime_id)
            .expect("scheduled upgrade must exist");
        assert_eq!(scheduled_upgrade.version.spec_version, 1);
        assert_eq!(
            scheduled_upgrade.raw_genesis.get_runtime_code().unwrap(),
            runtime_blob
        );
    }

    #[benchmark]
    fn instantiate_domain() {
        let creator = account("creator", 1, SEED);
        T::Currency::set_balance(
            &creator,
            T::DomainInstantiationDeposit::get() + T::Currency::minimum_balance(),
        );

        let runtime_id = register_runtime::<T>();
        let domain_id = NextDomainId::<T>::get();
        let domain_config = DomainConfig {
            domain_name: "evm-domain".to_owned(),
            runtime_id,
            max_block_size: 1024,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 10,
            operator_allow_list: OperatorAllowList::Anyone,
        };

        #[extrinsic_call]
        _(RawOrigin::Signed(creator.clone()), domain_config.clone());

        let domain_obj = DomainRegistry::<T>::get(domain_id).expect("domain object must exist");
        assert_eq!(domain_obj.domain_config, domain_config);
        assert_eq!(domain_obj.owner_account_id, creator);
        assert!(DomainStakingSummary::<T>::get(domain_id).is_some());
        assert_eq!(
            BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero()).len(),
            1
        );
        assert_eq!(NextDomainId::<T>::get(), domain_id + 1.into());
    }

    #[benchmark]
    fn register_operator() {
        let operator_account = account("operator", 1, SEED);
        T::Currency::set_balance(
            &operator_account,
            T::MinOperatorStake::get() + T::Currency::minimum_balance(),
        );

        let domain_id = register_domain::<T>();
        let operator_id = NextOperatorId::<T>::get();
        let operator_config = OperatorConfig {
            signing_key: OperatorPublicKey::unchecked_from([1u8; 32]),
            minimum_nominator_stake: T::Currency::minimum_balance(),
            nomination_tax: Default::default(),
        };

        #[extrinsic_call]
        _(
            RawOrigin::Signed(operator_account.clone()),
            domain_id,
            T::MinOperatorStake::get(),
            operator_config.clone(),
        );

        assert_eq!(NextOperatorId::<T>::get(), operator_id + 1);
        assert_eq!(
            OperatorIdOwner::<T>::get(operator_id),
            Some(operator_account.clone())
        );

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(operator.signing_key, operator_config.signing_key);

        let staking_summary =
            DomainStakingSummary::<T>::get(domain_id).expect("staking summary must exist");
        assert!(staking_summary.next_operators.contains(&operator_id));

        assert_eq!(
            PendingDeposits::<T>::get(operator_id, operator_account),
            Some(T::MinOperatorStake::get())
        );
    }

    /// Benchmark `nominate_operator` extrinsic with the worst possible conditions:
    /// - There is already a pending deposit of the nominator
    #[benchmark]
    fn nominate_operator() {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::Currency::minimum_balance();
        T::Currency::set_balance(
            &nominator,
            minimum_nominator_stake * 2u32.into() + T::Currency::minimum_balance(),
        );

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);

        // Add one more pending deposit
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            minimum_nominator_stake,
        ));

        #[extrinsic_call]
        _(
            RawOrigin::Signed(nominator.clone()),
            operator_id,
            minimum_nominator_stake,
        );

        assert_eq!(
            PendingDeposits::<T>::get(operator_id, nominator),
            Some(minimum_nominator_stake * 2u32.into())
        );
    }

    #[benchmark]
    fn switch_domain() {
        let domain1_id = register_domain::<T>();
        let domain2_id = register_domain::<T>();

        let (operator_owner, operator_id) =
            register_helper_operator::<T>(domain1_id, T::Currency::minimum_balance());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(operator_owner.clone()),
            operator_id,
            domain2_id,
        );

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(operator.next_domain_id, domain2_id);

        let pending_switch =
            PendingOperatorSwitches::<T>::get(domain1_id).expect("pending switch must exist");
        assert!(pending_switch.contains(&operator_id));
    }

    #[benchmark]
    fn deregister_operator() {
        let domain_id = register_domain::<T>();

        let (operator_owner, operator_id) =
            register_helper_operator::<T>(domain_id, T::Currency::minimum_balance());

        #[extrinsic_call]
        _(RawOrigin::Signed(operator_owner.clone()), operator_id);

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(operator.status, OperatorStatus::Deregistered);

        let pending_deregistration = PendingOperatorDeregistrations::<T>::get(domain_id)
            .expect("pending deregistration must exist");
        assert!(pending_deregistration.contains(&operator_id));
    }

    /// Benchmark `withdraw_stake` extrinsic with the worst possible conditions:
    /// - There is unmint reward of the nominator
    /// - There is already a pending withdrawal of the nominator
    /// - Only withdraw partial of the nominator's stake
    #[benchmark]
    fn withdraw_stake() {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::Currency::minimum_balance();
        let withdraw_amount = T::MinOperatorStake::get();
        T::Currency::set_balance(
            &nominator,
            withdraw_amount * 3u32.into() + T::Currency::minimum_balance(),
        );

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            withdraw_amount * 3u32.into(),
        ));
        do_finalize_domain_staking::<T>(domain_id, 1u32.into())
            .expect("finalize domain staking should success");

        // Add reward to the operator
        let _ = DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_stake_summary| {
            let stake_summary = maybe_stake_summary
                .as_mut()
                .expect("staking summary must exist");
            stake_summary
                .current_epoch_rewards
                .insert(operator_id, T::MinOperatorStake::get());
            Ok::<_, ()>(())
        });

        // Add one more withdraw
        assert_ok!(Domains::<T>::withdraw_stake(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            Withdraw::Some(withdraw_amount),
        ));

        #[extrinsic_call]
        _(
            RawOrigin::Signed(nominator.clone()),
            operator_id,
            Withdraw::Some(withdraw_amount),
        );

        assert_eq!(
            PendingWithdrawals::<T>::get(operator_id, nominator),
            Some(Withdraw::Some(withdraw_amount * 2u32.into()))
        );
    }

    #[benchmark]
    fn auto_stake_block_rewards() {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::Currency::minimum_balance();
        T::Currency::set_balance(
            &nominator,
            minimum_nominator_stake + T::Currency::minimum_balance(),
        );

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            minimum_nominator_stake,
        ));
        do_finalize_domain_staking::<T>(domain_id, 1u32.into())
            .expect("finalize domain staking should success");

        #[extrinsic_call]
        _(RawOrigin::Signed(nominator.clone()), operator_id);

        assert_eq!(PreferredOperator::<T>::get(nominator), Some(operator_id));
    }

    fn register_runtime<T: Config>() -> RuntimeId {
        let runtime_blob =
            include_bytes!("../res/evm_domain_test_runtime.compact.compressed.wasm").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();
        let runtime_hash = T::Hashing::hash(&runtime_blob);

        assert_ok!(Domains::<T>::register_domain_runtime(
            RawOrigin::Root.into(),
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            runtime_blob,
        ));

        let runtime_obj = RuntimeRegistry::<T>::get(runtime_id).expect("runtime object must exist");
        assert_eq!(runtime_obj.hash, runtime_hash);
        assert_eq!(NextRuntimeId::<T>::get(), runtime_id + 1);

        runtime_id
    }

    fn register_domain<T: Config>() -> DomainId {
        let creator = account("creator", 1, SEED);
        T::Currency::set_balance(
            &creator,
            T::DomainInstantiationDeposit::get() + T::Currency::minimum_balance(),
        );

        let runtime_id = register_runtime::<T>();
        let domain_id = NextDomainId::<T>::get();
        let domain_config = DomainConfig {
            domain_name: "evm-domain".to_owned(),
            runtime_id,
            max_block_size: 1024,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 10,
            operator_allow_list: OperatorAllowList::Anyone,
        };

        assert_ok!(Domains::<T>::instantiate_domain(
            RawOrigin::Signed(creator.clone()).into(),
            domain_config.clone(),
        ));

        let domain_obj = DomainRegistry::<T>::get(domain_id).expect("domain object must exist");
        assert_eq!(domain_obj.domain_config, domain_config);
        assert_eq!(domain_obj.owner_account_id, creator);

        domain_id
    }

    fn register_helper_operator<T: Config>(
        domain_id: DomainId,
        minimum_nominator_stake: BalanceOf<T>,
    ) -> (T::AccountId, OperatorId) {
        let operator_account = account("operator", 1, SEED);
        T::Currency::set_balance(
            &operator_account,
            T::MinOperatorStake::get() + T::Currency::minimum_balance(),
        );

        let operator_id = NextOperatorId::<T>::get();
        let operator_config = OperatorConfig {
            signing_key: OperatorPublicKey::unchecked_from([1u8; 32]),
            minimum_nominator_stake,
            nomination_tax: Default::default(),
        };

        assert_ok!(Domains::<T>::register_operator(
            RawOrigin::Signed(operator_account.clone()).into(),
            domain_id,
            T::MinOperatorStake::get(),
            operator_config.clone(),
        ));

        assert_eq!(
            OperatorIdOwner::<T>::get(operator_id),
            Some(operator_account.clone())
        );
        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(operator.signing_key, operator_config.signing_key);

        (operator_account, operator_id)
    }

    fn run_to_block<T: Config>(block_number: BlockNumberFor<T>, parent_hash: T::Hash) {
        System::<T>::set_block_number(block_number);
        System::<T>::initialize(&block_number, &parent_hash, &Default::default());
        <Domains<T> as Hooks<BlockNumberFor<T>>>::on_initialize(block_number);
        System::<T>::finalize();
    }

    // TODO: currently benchmark tests are running in one single function within the same `TExternalities`
    // (thus the storage state may be polluted by previously test) instead of one function per bench case,
    // wait for https://github.com/paritytech/substrate/issues/13738 to resolve this issue.
    impl_benchmark_test_suite!(
        Domains,
        crate::tests::new_test_ext_with_extensions(),
        crate::tests::Test
    );
}
