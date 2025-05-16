//! Benchmarking for `pallet-domains`.

extern crate alloc;

use super::*;
use crate::block_tree::{prune_receipt, BlockTreeNode};
use crate::bundle_storage_fund::refund_storage_fee;
use crate::domain_registry::{into_domain_config, DomainConfigParams};
use crate::runtime_registry::DomainRuntimeUpgradeEntry;
use crate::staking::{
    do_convert_previous_epoch_withdrawal, do_mark_operators_as_slashed, do_reward_operators,
    Error as StakingError, OperatorConfig, OperatorStatus, WithdrawStake,
};
use crate::staking_epoch::{
    do_finalize_domain_current_epoch, do_finalize_domain_epoch_staking, do_slash_operator,
    operator_take_reward_tax_and_stake,
};
use crate::{
    DomainBlockNumberFor, ExecutionReceiptOf, Pallet as Domains, RawOrigin as DomainOrigin,
    MAX_NOMINATORS_TO_SLASH,
};
#[cfg(not(feature = "std"))]
use alloc::borrow::ToOwned;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::fungible::{Inspect, Mutate};
use frame_support::traits::Hooks;
use frame_system::{Pallet as System, RawOrigin};
use hex_literal::hex;
use sp_consensus_slots::Slot;
use sp_core::crypto::{Ss58Codec, UncheckedFrom};
use sp_core::sr25519::vrf::{VrfPreOutput, VrfProof, VrfSignature};
use sp_core::H256;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{
    dummy_opaque_bundle, BundleHeader, DomainId, ExecutionReceipt, OpaqueBundle, OperatorAllowList,
    OperatorId, OperatorPublicKey, OperatorRewardSource, OperatorSignature,
    PermissionedActionAllowedBy, ProofOfElection, RuntimeType, SealedBundleHeader,
    SealedSingletonReceipt, SingletonReceipt, EMPTY_EXTRINSIC_ROOT,
};
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_runtime::traits::{CheckedAdd, One, Zero};
use sp_std::collections::btree_set::BTreeSet;
use subspace_core_primitives::pot::PotOutput;

const SEED: u32 = 0;
const MAX_NOMINATORS_TO_SLASH_WITHOUT_OPERATOR: u32 = MAX_NOMINATORS_TO_SLASH - 1;

#[benchmarks(where <RuntimeCallFor<T> as sp_runtime::traits::Dispatchable>::RuntimeOrigin: From<DomainOrigin>)]
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
            register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());

        let mut receipt =
            BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero())
                .and_then(BlockTreeNodes::<T>::get)
                .expect("genesis receipt must exist")
                .execution_receipt;
        for i in [1, 2, 3, block_tree_pruning_depth] {
            let consensus_block_number = i.into();
            let domain_block_number = i.into();

            // Run to `block_number`
            run_to_block::<T>(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number - One::one()),
            );

            if i != block_tree_pruning_depth {
                // Submit a bundle with the receipt of the last block
                let bundle = dummy_opaque_bundle(domain_id, operator_id, receipt);
                assert_ok!(Domains::<T>::submit_bundle(
                    DomainOrigin::ValidatedUnsigned.into(),
                    bundle
                ));
            } else {
                // Since the challenge period is set to 1 day we don't want to fill up all the ERs
                // (i.e. 14_400 number of ERs) which seems take forever to finish, thus we instead
                // manually insert the last ER into the state.
                let receipt_block_number = domain_block_number - One::one();
                let receipt = ExecutionReceipt::dummy::<DomainHashingFor<T>>(
                    consensus_block_number - One::one(),
                    frame_system::Pallet::<T>::block_hash(consensus_block_number - One::one()),
                    receipt_block_number,
                    Default::default(),
                );
                let receipt_hash = receipt.hash::<DomainHashingFor<T>>();
                HeadReceiptNumber::<T>::set(domain_id, receipt_block_number);
                BlockTree::<T>::insert(domain_id, receipt_block_number, receipt_hash);
                BlockTreeNodes::<T>::insert(
                    receipt_hash,
                    BlockTreeNode {
                        execution_receipt: receipt,
                        operator_ids: sp_std::vec![operator_id],
                    },
                );
            }

            // Create ER for the above bundle
            let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);
            let parent_domain_block_receipt = BlockTree::<T>::get(domain_id, head_receipt_number)
                .expect("parent receipt must exist");
            receipt = ExecutionReceipt::dummy::<DomainHashingFor<T>>(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number),
                domain_block_number,
                parent_domain_block_receipt,
            );
        }
        assert_eq!(
            Domains::<T>::head_receipt_number(domain_id),
            (block_tree_pruning_depth - 1).into()
        );

        // Construct bundle that will prune the block tree
        let block_number = (block_tree_pruning_depth + 1).into();
        run_to_block::<T>(
            block_number,
            frame_system::Pallet::<T>::block_hash(block_number - One::one()),
        );
        let bundle = dummy_opaque_bundle(domain_id, operator_id, receipt);

        #[extrinsic_call]
        submit_bundle(DomainOrigin::ValidatedUnsigned, bundle);

        assert_eq!(
            Domains::<T>::head_receipt_number(domain_id),
            block_tree_pruning_depth.into()
        );
        assert_eq!(
            Domains::<T>::oldest_unconfirmed_receipt_number(domain_id),
            Some(1u32.into())
        );
    }

    #[benchmark]
    fn submit_fraud_proof() {
        let domain_id = register_domain::<T>();
        let (_, operator_id) =
            register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());

        let mut target_receipt_hash = None;
        let mut receipt =
            BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero())
                .and_then(BlockTreeNodes::<T>::get)
                .expect("genesis receipt must exist")
                .execution_receipt;
        for i in 1u32..=3u32 {
            let consensus_block_number = i.into();
            let domain_block_number = i.into();

            // Run to `block_number`
            run_to_block::<T>(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number - One::one()),
            );

            // Submit a bundle with the receipt of the last block
            let bundle = dummy_opaque_bundle(domain_id, operator_id, receipt);
            assert_ok!(Domains::<T>::submit_bundle(
                DomainOrigin::ValidatedUnsigned.into(),
                bundle
            ));

            // Create ER for the above bundle
            let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);
            let parent_domain_block_receipt = BlockTree::<T>::get(domain_id, head_receipt_number)
                .expect("parent receipt must exist");
            receipt = ExecutionReceipt::dummy::<DomainHashingFor<T>>(
                consensus_block_number,
                frame_system::Pallet::<T>::block_hash(consensus_block_number),
                domain_block_number,
                parent_domain_block_receipt,
            );
            if i == 1 {
                target_receipt_hash.replace(receipt.hash::<DomainHashingFor<T>>());
            }
        }
        assert_eq!(Domains::<T>::head_receipt_number(domain_id), 2u32.into());

        // Construct fraud proof that target the ER at block #1
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, target_receipt_hash.unwrap());

        #[extrinsic_call]
        submit_fraud_proof(DomainOrigin::ValidatedUnsigned, Box::new(fraud_proof));

        assert_eq!(Domains::<T>::head_receipt_number(domain_id), 0u32.into());
        assert_eq!(
            Domains::<T>::oldest_unconfirmed_receipt_number(domain_id),
            None,
        );
    }

    /// Benchmark prune bad ER and slash the submitter based on the number of submitter
    #[benchmark]
    fn handle_bad_receipt(n: Linear<1, MAX_BUNDLE_PER_BLOCK>) {
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let domain_id = register_domain::<T>();
        let mut operator_ids = Vec::new();
        for i in 0..n {
            let (_, operator_id) =
                register_operator_with_seed::<T>(domain_id, i + 1, minimum_nominator_stake);
            operator_ids.push(operator_id);
        }
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Construct a bad ER ar block #1 and inject it in to the block tree
        let receipt_number = 1u32.into();
        let receipt = ExecutionReceipt::dummy::<DomainHashingFor<T>>(
            1u32.into(),
            frame_system::Pallet::<T>::block_hash::<BlockNumberFor<T>>(1u32.into()),
            receipt_number,
            Default::default(),
        );
        let receipt_hash = receipt.hash::<DomainHashingFor<T>>();
        HeadReceiptNumber::<T>::set(domain_id, receipt_number);
        BlockTree::<T>::insert(domain_id, receipt_number, receipt_hash);
        BlockTreeNodes::<T>::insert(
            receipt_hash,
            BlockTreeNode {
                execution_receipt: receipt,
                operator_ids,
            },
        );

        #[block]
        {
            let block_tree_node = prune_receipt::<T>(domain_id, receipt_number)
                .expect("prune bad receipt should success")
                .expect("block tree node must exist");

            do_mark_operators_as_slashed::<T>(
                block_tree_node.operator_ids.into_iter(),
                SlashedReason::BadExecutionReceipt(receipt_hash),
            )
            .expect("slash operator should success");
        }

        assert_eq!(
            PendingSlashes::<T>::get(domain_id)
                .expect("pending slash must exist")
                .len(),
            n as usize
        );
        assert!(BlockTree::<T>::get(domain_id, receipt_number).is_none());
    }

    /// Benchmark confirm domain block based on the number of valid and invalid bundles have submitted
    /// in this block
    #[benchmark]
    fn confirm_domain_block(
        n: Linear<1, MAX_BUNDLE_PER_BLOCK>,
        s: Linear<0, MAX_BUNDLE_PER_BLOCK>,
    ) {
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let operator_rewards =
            T::Currency::minimum_balance().saturating_mul(BalanceOf::<T>::from(1000u32));
        let total_storage_fee =
            T::Currency::minimum_balance().saturating_mul(BalanceOf::<T>::from(1000u32));

        // Ensure the treasury account is above ED
        T::Currency::set_balance(
            &T::TreasuryAccount::get(),
            T::Currency::minimum_balance() + 1u32.into(),
        );

        let domain_id = register_domain::<T>();
        let mut operator_ids = Vec::new();
        for i in 0..(n + s) {
            let (_, operator_id) =
                register_operator_with_seed::<T>(domain_id, i + 1, minimum_nominator_stake);
            operator_ids.push(operator_id);
        }
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        #[allow(clippy::unnecessary_to_owned)]
        #[block]
        {
            refund_storage_fee::<T>(
                total_storage_fee,
                operator_ids
                    .iter()
                    .take(n as usize)
                    .map(|id| (*id, 1u32))
                    .collect(),
            )
            .expect("refund storage fee should success");

            do_reward_operators::<T>(
                domain_id,
                OperatorRewardSource::Dummy,
                operator_ids[..n as usize].to_vec().into_iter(),
                operator_rewards,
            )
            .expect("reward operator should success");

            do_mark_operators_as_slashed::<T>(
                operator_ids[n as usize..].to_vec().into_iter(),
                SlashedReason::InvalidBundle(1u32.into()),
            )
            .expect("slash operator should success");
        }

        let staking_summary =
            DomainStakingSummary::<T>::get(domain_id).expect("staking summary must exist");
        assert!(!staking_summary.current_epoch_rewards.is_empty());
        if s != 0 {
            assert_eq!(
                PendingSlashes::<T>::get(domain_id)
                    .expect("pending slash must exist")
                    .len(),
                s as usize
            );
        }
    }

    /// Benchmark `operator_take_reward_tax_and_stake` based on the number of operator who has reward
    /// in the current epoch
    #[benchmark]
    fn operator_reward_tax_and_restake(n: Linear<1, MAX_BUNDLE_PER_BLOCK>) {
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let operator_rewards =
            T::Currency::minimum_balance().saturating_mul(BalanceOf::<T>::from(1000u32));

        // Ensure the treasury account is above ED
        T::Currency::set_balance(
            &T::TreasuryAccount::get(),
            T::Currency::minimum_balance() + 1u32.into(),
        );

        let domain_id = register_domain::<T>();
        let mut operator_ids = Vec::new();
        for i in 0..n {
            let (_, operator_id) =
                register_operator_with_seed::<T>(domain_id, i + 1, minimum_nominator_stake);
            operator_ids.push(operator_id);
        }
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        do_reward_operators::<T>(
            domain_id,
            OperatorRewardSource::Dummy,
            operator_ids.clone().into_iter(),
            operator_rewards,
        )
        .expect("reward operator should success");

        let staking_summary =
            DomainStakingSummary::<T>::get(domain_id).expect("staking summary must exist");
        assert_eq!(staking_summary.current_epoch_rewards.len(), n as usize);

        #[block]
        {
            operator_take_reward_tax_and_stake::<T>(domain_id)
                .expect("operator take reward tax and restake should success");
        }

        let staking_summary =
            DomainStakingSummary::<T>::get(domain_id).expect("staking summary must exist");
        assert!(staking_summary.current_epoch_rewards.is_empty());
    }

    /// Benchmark `do_slash_operator` based on the number of their
    // nominators
    #[benchmark]
    fn slash_operator(n: Linear<0, MAX_NOMINATORS_TO_SLASH_WITHOUT_OPERATOR>) {
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let domain_id = register_domain::<T>();

        let operator_count = 1;
        let nominator_per_operator = n;

        let (_, operator_id) =
            register_operator_with_seed::<T>(domain_id, 1, minimum_nominator_stake);

        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Ensure the treasury account is above ED
        T::Currency::set_balance(
            &T::TreasuryAccount::get(),
            T::Currency::minimum_balance() + 1u32.into(),
        );

        for j in 0..nominator_per_operator {
            let nominator = account("nominator", 0, j);
            T::Currency::set_balance(&nominator, minimum_nominator_stake * 2u32.into());
            assert_ok!(Domains::<T>::nominate_operator(
                RawOrigin::Signed(nominator).into(),
                operator_id,
                minimum_nominator_stake,
            ));
        }
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Slash operator
        do_mark_operators_as_slashed::<T>(
            vec![operator_id].into_iter(),
            SlashedReason::InvalidBundle(1u32.into()),
        )
        .expect("slash operator should success");

        assert_eq!(
            PendingSlashes::<T>::get(domain_id)
                .expect("pending slash must exist")
                .len(),
            operator_count as usize
        );

        #[block]
        {
            do_slash_operator::<T>(domain_id, MAX_NOMINATORS_TO_SLASH)
                .expect("finalize slash should success");
        }

        assert!(PendingSlashes::<T>::get(domain_id).is_none());
    }

    /// Benchmark `do_finalize_domain_epoch_staking` based on the number of operator who has deposit/withdraw/reward
    /// happen in the current epoch
    #[benchmark]
    fn finalize_domain_epoch_staking(p: Linear<0, { T::MaxPendingStakingOperation::get() }>) {
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let operator_rewards =
            T::Currency::minimum_balance().saturating_mul(BalanceOf::<T>::from(1000u32));

        // Ensure the treasury account is above ED
        T::Currency::set_balance(
            &T::TreasuryAccount::get(),
            T::Currency::minimum_balance() + 1u32.into(),
        );

        let domain_id = register_domain::<T>();
        let mut operator_ids = Vec::new();
        for i in 0..T::MaxPendingStakingOperation::get() {
            let (_, operator_id) =
                register_operator_with_seed::<T>(domain_id, i + 1, minimum_nominator_stake);
            operator_ids.push(operator_id);
        }
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        for (i, operator_id) in operator_ids.iter().enumerate().take(p as usize) {
            let nominator = account("nominator", i as u32, SEED);
            T::Currency::set_balance(&nominator, minimum_nominator_stake * 2u32.into());
            assert_ok!(Domains::<T>::nominate_operator(
                RawOrigin::Signed(nominator).into(),
                *operator_id,
                minimum_nominator_stake,
            ));
        }
        assert_eq!(PendingStakingOperationCount::<T>::get(domain_id), p);

        do_reward_operators::<T>(
            domain_id,
            OperatorRewardSource::Dummy,
            operator_ids.into_iter(),
            operator_rewards,
        )
        .expect("reward operator should success");

        let epoch_index = DomainStakingSummary::<T>::get(domain_id)
            .expect("staking summary must exist")
            .current_epoch_index;

        #[block]
        {
            do_finalize_domain_epoch_staking::<T>(domain_id)
                .expect("finalize domain staking should success");
        }

        let staking_summary =
            DomainStakingSummary::<T>::get(domain_id).expect("staking summary must exist");
        assert_eq!(staking_summary.current_epoch_index, epoch_index + 1u32);
    }

    #[benchmark]
    fn register_domain_runtime() {
        let genesis_storage = include_bytes!("../res/evm-domain-genesis-storage").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();

        #[extrinsic_call]
        _(
            RawOrigin::Root,
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            genesis_storage,
        );

        let runtime_obj = RuntimeRegistry::<T>::get(runtime_id).expect("runtime object must exist");
        assert_eq!(runtime_obj.runtime_name, "evm-domain".to_owned());
        assert_eq!(runtime_obj.runtime_type, RuntimeType::Evm);
        assert_eq!(NextRuntimeId::<T>::get(), runtime_id + 1);
    }

    #[benchmark]
    fn upgrade_domain_runtime() {
        let genesis_storage = include_bytes!("../res/evm-domain-genesis-storage").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();

        // The `genesis_storage` have `spec_version = 1` thus we need to modify the runtime object
        // version to 0 to bypass the `can_upgrade_code` check when calling `upgrade_domain_runtime`
        assert_ok!(Domains::<T>::register_domain_runtime(
            RawOrigin::Root.into(),
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            genesis_storage.clone()
        ));
        RuntimeRegistry::<T>::mutate(runtime_id, |maybe_runtime_object| {
            let runtime_obj = maybe_runtime_object
                .as_mut()
                .expect("Runtime object must exist");
            runtime_obj.version.spec_version = 0;
        });

        #[extrinsic_call]
        _(RawOrigin::Root, runtime_id, genesis_storage.clone());

        let scheduled_at = frame_system::Pallet::<T>::current_block_number()
            .checked_add(&BlockNumberFor::<T>::from(1u32))
            .expect("must not overflow");
        let scheduled_upgrade = ScheduledRuntimeUpgrades::<T>::get(scheduled_at, runtime_id)
            .expect("scheduled upgrade must exist");
        assert_eq!(scheduled_upgrade.version.spec_version, 1);
    }

    #[benchmark]
    fn instantiate_domain() {
        let creator = account("domain_creator", 1, SEED);
        T::Currency::set_balance(
            &creator,
            T::DomainInstantiationDeposit::get() + T::MinNominatorStake::get(),
        );

        let runtime_id = register_runtime::<T>();
        let domain_id = NextDomainId::<T>::get();
        let domain_config_params = DomainConfigParams {
            domain_name: "evm-domain".to_owned(),
            runtime_id,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
            domain_runtime_config: Default::default(),
        };

        assert_ok!(Domains::<T>::set_permissioned_action_allowed_by(
            RawOrigin::Root.into(),
            PermissionedActionAllowedBy::Anyone,
        ));

        #[extrinsic_call]
        _(
            RawOrigin::Signed(creator.clone()),
            domain_config_params.clone(),
        );

        let domain_obj = DomainRegistry::<T>::get(domain_id).expect("domain object must exist");
        assert_eq!(
            domain_obj.domain_config,
            into_domain_config::<T>(domain_config_params).expect("Must success")
        );
        assert_eq!(domain_obj.owner_account_id, creator);
        assert!(DomainStakingSummary::<T>::get(domain_id).is_some());
        assert!(
            BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero()).is_some(),
        );
        assert_eq!(NextDomainId::<T>::get(), domain_id + 1.into());
    }

    #[benchmark]
    fn register_operator() {
        let operator_account = account("operator", 1, SEED);
        T::Currency::set_balance(
            &operator_account,
            T::MinOperatorStake::get() + T::MinNominatorStake::get(),
        );

        let domain_id = register_domain::<T>();
        let operator_id = NextOperatorId::<T>::get();
        let key =
            OperatorPublicKey::from_ss58check("5Gv1Uopoqo1k7125oDtFSCmxH4DzuCiBU7HBKu2bF1GZFsEb")
                .unwrap();
        let operator_config = OperatorConfig {
            signing_key: key,
            minimum_nominator_stake: T::MinNominatorStake::get(),
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
    }

    /// Benchmark `nominate_operator` extrinsic with the worst possible conditions:
    /// - There is already a pending deposit of the nominator from the previous epoch
    ///   that need to convert into share
    #[benchmark]
    fn nominate_operator() {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::MinNominatorStake::get();
        T::Currency::set_balance(
            &nominator,
            minimum_nominator_stake * 2u32.into() + T::MinNominatorStake::get(),
        );

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);

        // Add one more pending deposit
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            minimum_nominator_stake,
        ));
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(nominator.clone()),
            operator_id,
            minimum_nominator_stake,
        );

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert!(!operator.deposits_in_epoch.is_zero());
    }

    #[benchmark]
    fn deregister_operator() {
        let domain_id = register_domain::<T>();

        let (operator_owner, operator_id) =
            register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());

        do_finalize_domain_epoch_staking::<T>(domain_id)
            .expect("finalize domain staking should success");

        #[extrinsic_call]
        _(RawOrigin::Signed(operator_owner.clone()), operator_id);

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(
            *operator.status::<T>(operator_id),
            OperatorStatus::Deregistered(
                (domain_id, 1u32, T::StakeWithdrawalLockingPeriod::get()).into()
            ),
        );
    }

    /// Benchmark `withdraw_stake` extrinsic with the worst possible conditions:
    /// - There is a pending withdrawal and a pending deposit from the previous epoch that
    ///   need to convert into balance/share
    /// - Only withdraw partial of the nominator's stake
    #[benchmark]
    fn withdraw_stake() {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let withdraw_amount = T::MinOperatorStake::get();
        T::Currency::set_balance(
            &nominator,
            withdraw_amount * 4u32.into() + T::MinNominatorStake::get(),
        );

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            withdraw_amount * 3u32.into(),
        ));
        do_finalize_domain_epoch_staking::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Add one more withdraw and deposit to the previous epoch
        assert_ok!(Domains::<T>::withdraw_stake(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            WithdrawStake::Share(withdraw_amount.into()),
        ));
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            withdraw_amount,
        ));
        do_finalize_domain_epoch_staking::<T>(domain_id)
            .expect("finalize domain staking should success");

        #[extrinsic_call]
        _(
            RawOrigin::Signed(nominator.clone()),
            operator_id,
            WithdrawStake::Share(withdraw_amount.into()),
        );

        let operator = Operators::<T>::get(operator_id).expect("operator must exist");
        assert_eq!(operator.withdrawals_in_epoch, withdraw_amount.into());
    }

    /// Benchmark `unlock_funds` extrinsic with the worst possible conditions:
    /// - Unlock a full withdrawal which also remove the deposit storage for the nominator
    #[benchmark]
    fn unlock_funds(w: Linear<1, { T::WithdrawalLimit::get() }>) {
        let nominator = account("nominator", 1, SEED);
        let minimum_nominator_stake = T::MinNominatorStake::get();
        let staking_amount = T::MinOperatorStake::get() * 3u32.into();
        T::Currency::set_balance(&nominator, staking_amount + T::MinNominatorStake::get());

        let domain_id = register_domain::<T>();
        let (_, operator_id) = register_helper_operator::<T>(domain_id, minimum_nominator_stake);
        assert_ok!(Domains::<T>::nominate_operator(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            staking_amount,
        ));
        do_finalize_domain_epoch_staking::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Request `w` number of withdrawal in different epoch and withdraw all the stake in the last one
        for _ in 1..w {
            assert_ok!(Domains::<T>::withdraw_stake(
                RawOrigin::Signed(nominator.clone()).into(),
                operator_id,
                WithdrawStake::Stake(T::MinOperatorStake::get() / w.into()),
            ));
            do_finalize_domain_epoch_staking::<T>(domain_id)
                .expect("finalize domain staking should success");
        }
        assert_ok!(Domains::<T>::withdraw_stake(
            RawOrigin::Signed(nominator.clone()).into(),
            operator_id,
            WithdrawStake::All,
        ));
        do_finalize_domain_epoch_staking::<T>(domain_id)
            .expect("finalize domain staking should success");

        let current_domain_epoch_index = DomainStakingSummary::<T>::get(domain_id)
            .expect("domain must initialized")
            .current_epoch_index;
        Withdrawals::<T>::try_mutate(operator_id, nominator.clone(), |maybe_withdrawal| {
            let withdrawal = maybe_withdrawal.as_mut().unwrap();
            do_convert_previous_epoch_withdrawal::<T>(
                operator_id,
                withdrawal,
                current_domain_epoch_index,
            )?;
            assert_eq!(withdrawal.withdrawals.len() as u32, w);
            Ok::<(), StakingError>(())
        })
        .unwrap();

        // Update the `HeadDomainNumber` so unlock can success
        let next_head_domain_number = HeadDomainNumber::<T>::get(domain_id)
            + T::StakeWithdrawalLockingPeriod::get()
            + One::one();
        HeadDomainNumber::<T>::set(domain_id, next_head_domain_number);

        #[extrinsic_call]
        _(RawOrigin::Signed(nominator.clone()), operator_id);

        assert!(Withdrawals::<T>::get(operator_id, nominator.clone()).is_none());
        assert!(Deposits::<T>::get(operator_id, nominator).is_none());
    }

    /// Benchmark `unlock_nominator` extrinsic for a given de-registered operator
    #[benchmark]
    fn unlock_nominator() {
        let domain_id = register_domain::<T>();
        let (operator_owner, operator_id) =
            register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        // Ensure the treasury account is above ED
        T::Currency::set_balance(
            &T::TreasuryAccount::get(),
            T::Currency::minimum_balance() + 1u32.into(),
        );

        // Deregister operator
        assert_ok!(Domains::<T>::deregister_operator(
            RawOrigin::Signed(operator_owner.clone()).into(),
            operator_id,
        ));

        // Update the `HeadDomainNumber` so unlock can success
        let next_head_domain_number = HeadDomainNumber::<T>::get(domain_id)
            + T::StakeWithdrawalLockingPeriod::get()
            + One::one();
        HeadDomainNumber::<T>::set(domain_id, next_head_domain_number);

        #[extrinsic_call]
        _(RawOrigin::Signed(operator_owner), operator_id);

        assert!(OperatorIdOwner::<T>::get(operator_id).is_none());
    }

    #[benchmark]
    fn update_domain_operator_allow_list() {
        let domain_id = register_domain::<T>();
        let _ = register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        let domain_owner = DomainRegistry::<T>::get(domain_id)
            .expect("domain object must exist")
            .owner_account_id;
        let new_allow_list = OperatorAllowList::Operators(BTreeSet::from_iter(vec![account(
            "allowed-account",
            0,
            SEED,
        )]));

        #[extrinsic_call]
        _(
            RawOrigin::Signed(domain_owner),
            domain_id,
            new_allow_list.clone(),
        );

        let domain_obj = DomainRegistry::<T>::get(domain_id).expect("domain object must exist");
        assert_eq!(domain_obj.domain_config.operator_allow_list, new_allow_list);
    }

    #[benchmark]
    fn transfer_treasury_funds() {
        // Ensure the treasury account has balance
        let treasury_amount = 5000u32.into();
        let transfer_amount = 500u32.into();
        let account = account("slashed_account", 1, SEED);
        assert_eq!(T::Currency::balance(&account), 0u32.into());
        T::Currency::set_balance(&T::TreasuryAccount::get(), treasury_amount);
        #[extrinsic_call]
        _(RawOrigin::Root, account.clone(), transfer_amount);
        assert_eq!(T::Currency::balance(&account), transfer_amount);
        assert_eq!(
            T::Currency::balance(&T::TreasuryAccount::get()),
            treasury_amount - transfer_amount
        );
    }

    #[benchmark]
    fn submit_receipt() {
        let domain_id = register_domain::<T>();
        let (_, operator_id) =
            register_helper_operator::<T>(domain_id, T::MinNominatorStake::get());

        assert_eq!(Domains::<T>::head_receipt_number(domain_id), 0u32.into());

        let receipt = {
            let mut er = BlockTree::<T>::get::<_, DomainBlockNumberFor<T>>(domain_id, Zero::zero())
                .and_then(BlockTreeNodes::<T>::get)
                .expect("genesis receipt must exist")
                .execution_receipt;
            er.domain_block_number = One::one();
            er
        };
        let sealed_singleton_receipt = SealedSingletonReceipt {
            singleton_receipt: SingletonReceipt {
                proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
                receipt,
            },
            signature: OperatorSignature::unchecked_from([0u8; 64]),
        };

        #[extrinsic_call]
        submit_receipt(DomainOrigin::ValidatedUnsigned, sealed_singleton_receipt);

        assert_eq!(Domains::<T>::head_receipt_number(domain_id), 1u32.into());
    }

    #[benchmark]
    fn validate_submit_bundle() {
        let domain_id = register_domain::<T>();

        // Use `Alice` as signing key
        let signing_key =
            OperatorPublicKey::from_ss58check("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
                .unwrap();
        let (_, operator_id) = register_operator_with_key::<T>(
            domain_id,
            1u32,
            signing_key,
            T::MinNominatorStake::get(),
        );
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        let proof_of_election = mock_constant_proof_of_election(domain_id, operator_id);
        let receipt = mock_constant_receipt::<T>(domain_id);

        // Instead of inserting consensus hash into `ConsensusBlockHash` for the receipt check
        // insert `DomainRuntimeUpgradeRecords` to routed to a worse path
        DomainRuntimeUpgradeRecords::<T>::mutate(
            Domains::<T>::runtime_id(domain_id).unwrap(),
            |upgrade_record| {
                upgrade_record.insert(
                    receipt.consensus_block_number,
                    DomainRuntimeUpgradeEntry {
                        at_hash: receipt.consensus_block_hash,
                        reference_count: 1,
                    },
                )
            },
        );

        let header = BundleHeader {
            proof_of_election,
            receipt,
            estimated_bundle_weight: Default::default(),
            bundle_extrinsics_root: EMPTY_EXTRINSIC_ROOT.into(),
        };

        // Hardcoded signature of the constant bundle header, signed by `Alice`
        // NOTE: we can't sign in no-std because it requires randomness
        let signature = OperatorSignature::unchecked_from([
            212, 250, 46, 171, 239, 93, 105, 105, 36, 78, 32, 229, 166, 253, 168, 142, 109, 123,
            213, 159, 210, 106, 192, 62, 54, 82, 64, 64, 19, 27, 136, 33, 19, 241, 58, 116, 252,
            133, 147, 129, 32, 182, 201, 18, 47, 80, 117, 124, 136, 186, 168, 15, 193, 71, 236,
            201, 155, 176, 188, 254, 114, 173, 96, 134,
        ]);

        let opaque_bundle = OpaqueBundle {
            sealed_header: SealedBundleHeader::new(header, signature),
            extrinsics: Vec::new(),
        };

        #[block]
        {
            assert_ok!(Domains::<T>::validate_submit_bundle(&opaque_bundle, true));
        }
    }

    #[benchmark]
    fn validate_singleton_receipt() {
        let domain_id = register_domain::<T>();

        // Use `Alice` as signing key
        let signing_key =
            OperatorPublicKey::from_ss58check("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
                .unwrap();
        let (_, operator_id) = register_operator_with_key::<T>(
            domain_id,
            1u32,
            signing_key,
            T::MinNominatorStake::get(),
        );
        do_finalize_domain_current_epoch::<T>(domain_id)
            .expect("finalize domain staking should success");

        let proof_of_election = mock_constant_proof_of_election(domain_id, operator_id);
        let receipt = mock_constant_receipt::<T>(domain_id);

        // Instead of inserting consensus hash into `ConsensusBlockHash` for the receipt check
        // insert `DomainRuntimeUpgradeRecords` to routed to a worse path
        DomainRuntimeUpgradeRecords::<T>::mutate(
            Domains::<T>::runtime_id(domain_id).unwrap(),
            |upgrade_record| {
                upgrade_record.insert(
                    receipt.consensus_block_number,
                    DomainRuntimeUpgradeEntry {
                        at_hash: receipt.consensus_block_hash,
                        reference_count: 1,
                    },
                )
            },
        );

        let singleton_receipt: SingletonReceipt<_, _, T::DomainHeader, _> = SingletonReceipt {
            proof_of_election,
            receipt,
        };

        // Hardcoded signature of the constant singleton receipt, signed by `Alice`
        // NOTE: we can't sign in no-std because it requires randomness
        let signature = OperatorSignature::unchecked_from([
            10, 180, 139, 94, 205, 225, 15, 19, 141, 141, 133, 23, 32, 66, 177, 60, 131, 89, 91,
            110, 161, 218, 6, 228, 214, 118, 106, 108, 217, 36, 108, 40, 85, 150, 165, 177, 40, 9,
            98, 82, 203, 27, 32, 98, 122, 123, 78, 221, 229, 50, 118, 153, 61, 111, 95, 51, 130,
            195, 94, 212, 225, 14, 184, 141,
        ]);

        let sealed_singleton_receipt = SealedSingletonReceipt {
            singleton_receipt,
            signature,
        };

        HeadDomainNumber::<T>::set(domain_id, 10u32.into());

        #[block]
        {
            assert_ok!(Domains::<T>::validate_singleton_receipt(
                &sealed_singleton_receipt,
                true
            ));
        }
    }

    fn register_runtime<T: Config>() -> RuntimeId {
        let genesis_storage = include_bytes!("../res/evm-domain-genesis-storage").to_vec();
        let runtime_id = NextRuntimeId::<T>::get();

        assert_ok!(Domains::<T>::register_domain_runtime(
            RawOrigin::Root.into(),
            "evm-domain".to_owned(),
            RuntimeType::Evm,
            genesis_storage,
        ));

        assert_eq!(NextRuntimeId::<T>::get(), runtime_id + 1);

        runtime_id
    }

    fn register_domain<T: Config>() -> DomainId {
        let creator = account("domain_creator", 1, SEED);
        T::Currency::set_balance(
            &creator,
            T::DomainInstantiationDeposit::get() + T::MinNominatorStake::get(),
        );

        let runtime_id = register_runtime::<T>();
        let domain_id = NextDomainId::<T>::get();
        let domain_config_params = DomainConfigParams {
            domain_name: "evm-domain".to_owned(),
            runtime_id,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
            domain_runtime_config: Default::default(),
        };

        assert_ok!(Domains::<T>::set_permissioned_action_allowed_by(
            RawOrigin::Root.into(),
            PermissionedActionAllowedBy::Anyone,
        ));

        assert_ok!(Domains::<T>::instantiate_domain(
            RawOrigin::Signed(creator.clone()).into(),
            domain_config_params.clone(),
        ));

        let domain_obj = DomainRegistry::<T>::get(domain_id).expect("domain object must exist");
        assert_eq!(
            domain_obj.domain_config,
            into_domain_config::<T>(domain_config_params).expect("Must success")
        );
        assert_eq!(domain_obj.owner_account_id, creator);

        domain_id
    }

    fn register_helper_operator<T: Config>(
        domain_id: DomainId,
        minimum_nominator_stake: BalanceOf<T>,
    ) -> (T::AccountId, OperatorId) {
        register_operator_with_seed::<T>(domain_id, 1u32, minimum_nominator_stake)
    }

    fn register_operator_with_seed<T: Config>(
        domain_id: DomainId,
        operator_seed: u32,
        minimum_nominator_stake: BalanceOf<T>,
    ) -> (T::AccountId, OperatorId) {
        let key = {
            let mut k = [0u8; 32];
            (k[..4]).copy_from_slice(&operator_seed.to_be_bytes()[..]);
            k
        };
        let signing_key = OperatorPublicKey::unchecked_from(key);
        register_operator_with_key::<T>(
            domain_id,
            operator_seed,
            signing_key,
            minimum_nominator_stake,
        )
    }

    fn register_operator_with_key<T: Config>(
        domain_id: DomainId,
        operator_seed: u32,
        signing_key: OperatorPublicKey,
        minimum_nominator_stake: BalanceOf<T>,
    ) -> (T::AccountId, OperatorId) {
        let operator_account = account("operator", operator_seed, SEED);
        T::Currency::set_balance(
            &operator_account,
            T::MinOperatorStake::get() * 100u32.into() + T::MinNominatorStake::get(),
        );

        let operator_id = NextOperatorId::<T>::get();
        let operator_config = OperatorConfig {
            signing_key,
            minimum_nominator_stake,
            nomination_tax: Default::default(),
        };

        assert_ok!(crate::do_register_operator::<T>(
            operator_account.clone(),
            domain_id,
            T::MinOperatorStake::get() * 50u32.into(),
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

    // Return a mock `proof_of_election` which should be a constant value, otherwise,
    // it won't match with the hardcoded signature
    fn mock_constant_proof_of_election(
        domain_id: DomainId,
        operator_id: OperatorId,
    ) -> ProofOfElection {
        let (proof_of_time, slot) = (PotOutput::default(), Slot::from(1));

        // VRF signature generated by signing:
        // ```
        // let global_challenge = proof_of_time
        //     .derive_global_randomness()
        //     .derive_global_challenge(slot.into());
        // let vrf_sign_data = make_transcript(domain_id, &global_challenge).into_sign_data();
        // ```
        // with the key `Alice`
        let vrf_signature = VrfSignature {
            pre_output: VrfPreOutput(
                schnorrkel::vrf::VRFPreOut::from_bytes(&[
                    248, 47, 99, 253, 224, 36, 127, 251, 30, 132, 220, 112, 51, 251, 195, 246, 140,
                    97, 153, 49, 166, 36, 114, 142, 73, 214, 185, 156, 2, 142, 180, 57,
                ])
                .unwrap(),
            ),
            proof: VrfProof(
                schnorrkel::vrf::VRFProof::from_bytes(&[
                    28, 138, 214, 43, 79, 128, 75, 106, 98, 232, 188, 139, 101, 206, 174, 146, 138,
                    210, 101, 72, 184, 227, 115, 72, 37, 246, 182, 247, 102, 34, 11, 3, 22, 106,
                    116, 209, 34, 220, 216, 20, 93, 101, 182, 130, 15, 71, 73, 27, 51, 126, 100,
                    43, 80, 253, 101, 132, 222, 234, 196, 167, 19, 126, 16, 8,
                ])
                .unwrap(),
            ),
        };
        ProofOfElection {
            domain_id,
            slot_number: slot.into(),
            proof_of_time,
            vrf_signature,
            operator_id,
        }
    }

    // Return a mock `receipt` which should be a constant value, otherwise, it won't match
    // with the hardcoded signature
    fn mock_constant_receipt<T: Config>(domain_id: DomainId) -> ExecutionReceiptOf<T> {
        // The genesis ER will changed as the runtime code changed, thus using a mock genesis
        // ER hash to ensure the return ER is constant
        let mock_genesis_er_hash = H256::from_slice(
            hex!("5207cc85cfd1f53e11f4b9e85bf2d0a4f33e24d0f0f18b818b935a6aa47d3930").as_slice(),
        );
        BlockTree::<T>::insert::<_, DomainBlockNumberFor<T>, <T as Config>::DomainHash>(
            domain_id,
            Zero::zero(),
            mock_genesis_er_hash.into(),
        );

        let trace: Vec<<T as Config>::DomainHash> = vec![
            H256::repeat_byte(1).into(),
            H256::repeat_byte(2).into(),
            H256::repeat_byte(3).into(),
        ];
        let execution_trace_root = {
            let trace: Vec<_> = trace
                .iter()
                .map(|t| t.encode().try_into().unwrap())
                .collect();
            MerkleTree::from_leaves(trace.as_slice())
                .root()
                .unwrap()
                .into()
        };
        ExecutionReceipt {
            domain_block_number: One::one(),
            domain_block_hash: H256::repeat_byte(7).into(),
            domain_block_extrinsic_root: EMPTY_EXTRINSIC_ROOT.into(),
            parent_domain_block_receipt_hash: mock_genesis_er_hash.into(),
            consensus_block_number: One::one(),
            consensus_block_hash: H256::repeat_byte(9).into(),
            inboxed_bundles: vec![],
            final_state_root: trace[2],
            execution_trace: trace,
            execution_trace_root,
            block_fees: Default::default(),
            transfers: Default::default(),
        }
    }

    fn run_to_block<T: Config>(block_number: BlockNumberFor<T>, parent_hash: T::Hash) {
        if let Some(parent_block_number) = block_number.checked_sub(&One::one()) {
            Domains::<T>::on_finalize(parent_block_number);
        }
        System::<T>::set_block_number(block_number);
        System::<T>::initialize(&block_number, &parent_hash, &Default::default());
        Domains::<T>::on_initialize(block_number);
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
