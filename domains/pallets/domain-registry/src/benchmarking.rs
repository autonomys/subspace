//! Benchmarking for `pallet-domain-registry`.

// Only enable this module for benchmarking.
#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as DomainRegistry;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::Hooks;
use frame_system::{Pallet as System, RawOrigin};
use sp_core::crypto::ByteArray;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{dummy_invalid_state_transition_proof, FraudProof};
use sp_domains::{create_dummy_bundle_with_receipts_generic, ExecutionReceipt, ExecutorPublicKey};
use sp_runtime::traits::SaturatedConversion;
use sp_runtime::{Digest, DigestItem, Percent};

const SEED: u32 = 0;
const TEST_CORE_DOMAIN_ID: DomainId = DomainId::CORE_PAYMENTS;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn create_domain() {
        let domain_deposit = T::MinDomainDeposit::get();
        let creator = funded_account::<T>("creator", 1, domain_deposit);

        let domain_id = NextDomainId::<T>::get();
        let domain_config = sp_domains::DomainConfig {
            wasm_runtime_hash: Default::default(),
            max_bundle_size: 1024 * 1024,
            bundle_slot_probability: (1, 1),
            max_bundle_weight: Weight::MAX,
            min_operator_stake: T::MinDomainOperatorStake::get(),
        };

        #[extrinsic_call]
        _(
            RawOrigin::Signed(creator.clone()),
            domain_deposit,
            domain_config.clone(),
        );

        assert_eq!(NextDomainId::<T>::get(), domain_id + 1);
        assert_eq!(Domains::<T>::get(domain_id), Some(domain_config));
        assert_eq!(
            DomainCreators::<T>::get(domain_id, creator),
            Some(domain_deposit)
        );
    }

    #[benchmark]
    fn register_domain_operator() {
        let operator_stake = T::MinDomainOperatorStake::get();
        let domain_deposit = T::MinDomainDeposit::get();
        let operator = funded_account::<T>("operator", 1, operator_stake + domain_deposit);

        let domain_id = create_helper_domain::<T>(operator.clone(), domain_deposit);
        registry_executor::<T>(operator.clone(), T::MinDomainOperatorStake::get());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(operator.clone()),
            domain_id,
            Percent::one(),
        );

        assert_eq!(
            DomainOperators::<T>::get(operator, domain_id),
            Some(Percent::one())
        );
    }

    #[benchmark]
    fn deregister_domain_operator() {
        let operator_stake = T::MinDomainOperatorStake::get();
        let domain_deposit = T::MinDomainDeposit::get();
        let operator = funded_account::<T>("operator", 1, operator_stake + domain_deposit);

        let domain_id = create_helper_domain::<T>(operator.clone(), domain_deposit);
        registry_executor::<T>(operator.clone(), T::MinDomainOperatorStake::get());

        // register the domain operator first
        assert_ok!(DomainRegistry::<T>::do_domain_stake_update(
            operator.clone(),
            domain_id,
            Percent::one()
        ));
        assert_eq!(
            DomainOperators::<T>::get(&operator, domain_id),
            Some(Percent::one())
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(operator.clone()), domain_id);

        assert!(DomainOperators::<T>::get(operator, domain_id).is_none());
    }

    // TODO: pick https://github.com/paritytech/substrate/pull/13919 to support generic argument:
    // Linear<1, { T::ReceiptsPruningDepth::get() }>
    /// Benchmark `submit_core_bundle` extrinsic with the worst possible conditions:
    /// - All receipts are new and will prune the same number of expired receipts
    #[benchmark]
    fn submit_core_bundle(x: Linear<1, 256>) {
        let receipts_pruning_depth = T::ReceiptsPruningDepth::get().saturated_into::<u32>();

        // Import `ReceiptsPruningDepth` number of receipts which will be pruned later
        run_to_block::<T>(1, receipts_pruning_depth);
        let receipts: Vec<_> = (0..receipts_pruning_depth)
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            TEST_CORE_DOMAIN_ID,
            receipts_pruning_depth.into(),
            Default::default(),
            receipts,
        );
        assert_ok!(DomainRegistry::<T>::submit_core_bundle(
            RawOrigin::None.into(),
            bundle
        ));
        assert_eq!(
            DomainRegistry::<T>::head_receipt_number(TEST_CORE_DOMAIN_ID),
            (receipts_pruning_depth - 1).into()
        );

        // Construct a bundle that contain `x` number of new receipts
        run_to_block::<T>(receipts_pruning_depth + 1, receipts_pruning_depth + x);
        let receipts: Vec<_> = (receipts_pruning_depth..(receipts_pruning_depth + x))
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            TEST_CORE_DOMAIN_ID,
            x.into(),
            Default::default(),
            receipts,
        );

        #[extrinsic_call]
        _(RawOrigin::None, bundle);

        assert_eq!(
            DomainRegistry::<T>::head_receipt_number(TEST_CORE_DOMAIN_ID),
            ((receipts_pruning_depth + x) - 1).into()
        );
        assert_eq!(
            DomainRegistry::<T>::oldest_receipt_number(TEST_CORE_DOMAIN_ID),
            x.into()
        );
    }

    /// Benchmark `submit_fraud_proof` extrinsic with the worst possible conditions:
    /// - Submit a core domain invalid state transition proof
    /// - The fraud proof will revert the maximal possible number of receipts
    #[benchmark]
    fn submit_fraud_proof() {
        let receipts_pruning_depth = T::ReceiptsPruningDepth::get().saturated_into::<u32>();

        // Import `ReceiptsPruningDepth` number of receipts which will be revert later
        run_to_block::<T>(1, receipts_pruning_depth);
        let receipts: Vec<_> = (0..receipts_pruning_depth)
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            TEST_CORE_DOMAIN_ID,
            receipts_pruning_depth.into(),
            Default::default(),
            receipts,
        );
        assert_ok!(DomainRegistry::<T>::submit_core_bundle(
            RawOrigin::None.into(),
            bundle
        ));
        assert_eq!(
            DomainRegistry::<T>::head_receipt_number(TEST_CORE_DOMAIN_ID),
            (receipts_pruning_depth - 1).into()
        );

        // Construct a fraud proof that will revert `ReceiptsPruningDepth` number of receipts
        let proof: FraudProof<T::BlockNumber, T::Hash> = FraudProof::InvalidStateTransition(
            dummy_invalid_state_transition_proof(TEST_CORE_DOMAIN_ID, 0),
        );

        #[extrinsic_call]
        _(RawOrigin::None, proof);

        assert_eq!(
            DomainRegistry::<T>::head_receipt_number(TEST_CORE_DOMAIN_ID),
            0u32.into()
        );
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

    // Create a helper domain for later operations
    fn create_helper_domain<T: Config>(creator: T::AccountId, deposit: BalanceOf<T>) -> DomainId {
        let domain_id = NextDomainId::<T>::get();
        let domain_config = sp_domains::DomainConfig {
            wasm_runtime_hash: Default::default(),
            max_bundle_size: 1024 * 1024,
            bundle_slot_probability: (1, 1),
            max_bundle_weight: Weight::MAX,
            min_operator_stake: T::MinDomainOperatorStake::get(),
        };

        DomainRegistry::<T>::apply_create_domain(&creator, deposit, &domain_config);
        assert_eq!(NextDomainId::<T>::get(), domain_id + 1);
        assert_eq!(Domains::<T>::get(domain_id), Some(domain_config));
        assert_eq!(DomainCreators::<T>::get(domain_id, creator), Some(deposit));

        domain_id
    }

    // Registry an executor for later operations
    fn registry_executor<T: Config>(executor: T::AccountId, stake: BalanceOf<T>) {
        let public_key = ExecutorPublicKey::from_slice(&[1; 32]).unwrap();
        T::ExecutorRegistry::unchecked_register(executor.clone(), public_key.clone(), stake);

        assert_eq!(T::ExecutorRegistry::executor_stake(&executor), Some(stake));
        assert_eq!(
            T::ExecutorRegistry::executor_public_key(&executor),
            Some(public_key)
        );
    }

    fn block_hash_n<T: Config>(n: u32) -> T::Hash {
        let mut h = T::Hash::default();
        h.as_mut()
            .iter_mut()
            .zip(u32::to_be_bytes(n).as_slice().iter())
            .for_each(|(h, n)| *h = *n);
        h
    }

    fn run_to_block<T: Config>(from: u32, to: u32) {
        assert!(from > 0);
        for b in from..=to {
            let block_number = b.into();
            let hash = block_hash_n::<T>(b - 1);
            let digest = {
                let mut d = Digest::default();
                if b == 1 {
                    d.push(DigestItem::primary_block_info::<T::BlockNumber, _>((
                        0u32.into(),
                        block_hash_n::<T>(b),
                    )));
                }
                d.push(DigestItem::primary_block_info((block_number, hash)));
                d
            };
            System::<T>::set_block_number(block_number);
            System::<T>::initialize(&block_number, &hash, &digest);
            <DomainRegistry<T> as Hooks<T::BlockNumber>>::on_initialize(block_number);
            System::<T>::finalize();
        }
    }

    impl_benchmark_test_suite!(
        DomainRegistry,
        crate::tests::new_test_ext(),
        crate::tests::Test
    );
}
