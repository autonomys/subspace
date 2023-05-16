//! Benchmarking for `pallet-domains`.

// Only enable this module for benchmarking.
#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as Domains;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::Hooks;
use frame_system::{Pallet as System, RawOrigin};
use sp_domains::fraud_proof::{dummy_invalid_state_transition_proof, FraudProof};
use sp_domains::{create_dummy_bundle_with_receipts_generic, DomainId, ExecutionReceipt};
use sp_runtime::traits::SaturatedConversion;

#[benchmarks]
mod benchmarks {
    use super::*;

    // TODO: pick https://github.com/paritytech/substrate/pull/13919 to support generic argument:
    // Linear<1, { T::ReceiptsPruningDepth::get() }>
    /// Benchmark `submit_bundle` extrinsic with the worst possible conditions:
    /// - Submit a system domain bundle
    /// - All receipts are new and will prune the same number of expired receipts
    #[benchmark]
    fn submit_system_bundle(x: Linear<1, 256>) {
        let receipts_pruning_depth = T::ReceiptsPruningDepth::get().saturated_into::<u32>();

        // Import `ReceiptsPruningDepth` number of receipts which will be pruned later
        run_to_block::<T>(1, receipts_pruning_depth);
        let receipts: Vec<_> = (0..receipts_pruning_depth)
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            DomainId::SYSTEM,
            receipts_pruning_depth.into(),
            Default::default(),
            receipts,
        );
        assert_ok!(Domains::<T>::submit_bundle(RawOrigin::None.into(), bundle));
        assert_eq!(
            Domains::<T>::head_receipt_number(),
            (receipts_pruning_depth - 1).into()
        );

        // Construct a bundle that contain `x` number of new receipts
        run_to_block::<T>(receipts_pruning_depth + 1, receipts_pruning_depth + x);
        let receipts: Vec<_> = (receipts_pruning_depth..(receipts_pruning_depth + x))
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            DomainId::SYSTEM,
            x.into(),
            Default::default(),
            receipts,
        );

        #[extrinsic_call]
        submit_bundle(RawOrigin::None, bundle);

        assert_eq!(
            Domains::<T>::head_receipt_number(),
            ((receipts_pruning_depth + x) - 1).into()
        );
        assert_eq!(Domains::<T>::oldest_receipt_number(), x.into());
    }

    #[benchmark]
    fn submit_core_bundle() {
        let bundle = create_dummy_bundle_with_receipts_generic(
            DomainId::CORE_PAYMENTS,
            2u32.into(),
            Default::default(),
            vec![ExecutionReceipt::dummy(1u32.into(), block_hash_n::<T>(1))],
        );

        #[extrinsic_call]
        submit_bundle(RawOrigin::None, bundle);
    }

    /// Benchmark `submit_fraud_proof` extrinsic with the worst possible conditions:
    /// - Submit a system domain invalid state transition proof
    /// - The fraud proof will revert the maximal possible number of receipts
    #[benchmark]
    fn submit_system_domain_invalid_state_transition_proof() {
        let receipts_pruning_depth = T::ReceiptsPruningDepth::get().saturated_into::<u32>();

        // Import `ReceiptsPruningDepth` number of receipts which will be revert later
        run_to_block::<T>(1, receipts_pruning_depth);
        let receipts: Vec<_> = (0..receipts_pruning_depth)
            .map(|i| ExecutionReceipt::dummy(i.into(), block_hash_n::<T>(i)))
            .collect();
        let bundle = create_dummy_bundle_with_receipts_generic(
            DomainId::SYSTEM,
            receipts_pruning_depth.into(),
            Default::default(),
            receipts,
        );
        assert_ok!(Domains::<T>::submit_bundle(RawOrigin::None.into(), bundle));
        assert_eq!(
            Domains::<T>::head_receipt_number(),
            (receipts_pruning_depth - 1).into()
        );

        // Construct a fraud proof that will revert `ReceiptsPruningDepth` number of receipts
        let proof: FraudProof<T::BlockNumber, T::Hash> = FraudProof::InvalidStateTransition(
            dummy_invalid_state_transition_proof(DomainId::SYSTEM, 0),
        );

        #[extrinsic_call]
        submit_fraud_proof(RawOrigin::None, proof);

        assert_eq!(Domains::<T>::head_receipt_number(), 0u32.into());
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
            System::<T>::set_block_number(block_number);
            System::<T>::initialize(
                &block_number,
                &block_hash_n::<T>(b - 1),
                &Default::default(),
            );
            <Domains<T> as Hooks<T::BlockNumber>>::on_initialize(block_number);
            System::<T>::finalize();
        }
    }

    // TODO: currently benchmark tests are running in one single function within the same `TestExternalities`
    // (thus the storage state may be polluted by previously test) instead of one function per bench case,
    // wait for https://github.com/paritytech/substrate/issues/13738 to resolve this issue.
    impl_benchmark_test_suite!(Domains, crate::tests::new_test_ext(), crate::tests::Test);
}
