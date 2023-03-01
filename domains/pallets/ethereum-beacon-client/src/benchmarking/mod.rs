use super::*;

use crate::Pallet as EthereumBeaconClient;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;

mod data;

benchmarks! {
    sync_committee_period_update {
        let caller: T::AccountId = whitelisted_caller();

        let initial_sync_data = data::initial_sync();
        EthereumBeaconClient::<T>::initial_sync(initial_sync_data.clone()).unwrap();

        let update = data::sync_committee_update();

    }: sync_committee_period_update(RawOrigin::Signed(caller.clone()), update.clone())
    verify {
        assert!(<SyncCommittees<T>>::get(update.sync_committee_period+1).pubkeys.len() > 0);
    }

    import_finalized_header {
        let caller: T::AccountId = whitelisted_caller();

        EthereumBeaconClient::<T>::initial_sync(data::initial_sync()).unwrap();

        let sync_update: SyncCommitteePeriodUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize> = data::sync_committee_update();
        SyncCommittees::<T>::set(sync_update.sync_committee_period+1, sync_update.next_sync_committee);

        let finalized_header = data::finalized_header_update();

    }: _(RawOrigin::Signed(caller.clone()), finalized_header.clone())
    verify {
        let header_hash_bytes = merkleization::hash_tree_root_beacon_header(finalized_header.finalized_header).unwrap();

        let header_hash: H256 = header_hash_bytes.into();

        <FinalizedBeaconHeaders<T>>::get(header_hash).unwrap();
    }

    import_execution_header {
        let caller: T::AccountId = whitelisted_caller();

        EthereumBeaconClient::<T>::initial_sync(data::initial_sync()).unwrap();

        let sync_update: SyncCommitteePeriodUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize> = data::sync_committee_update();
        SyncCommittees::<T>::set(sync_update.sync_committee_period+1, sync_update.next_sync_committee);

        let block_update = data::block_update();

        LatestFinalizedHeaderState::<T>::set(FinalizedHeaderState{
            beacon_block_root: H256::default(),
            beacon_slot: block_update.block.slot,
            import_time: 0,
        });
    }: _(RawOrigin::Signed(caller.clone()), block_update.clone())
    verify {
        let block_hash: H256 = block_update.block.body.execution_payload.block_hash;

        <ExecutionHeaders<T>>::get(block_hash).unwrap();
    }
}

impl_benchmark_test_suite!(
    EthereumBeaconClient,
    crate::mock::new_tester::<crate::mock::mock_mainnet::Test>(),
    crate::mock::mock_mainnet::Test,
);
