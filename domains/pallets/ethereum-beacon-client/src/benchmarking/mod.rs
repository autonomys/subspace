use super::*;
use crate::{config, Pallet as EthereumBeaconClient};
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;

mod data;

benchmarks! {
    light_client_update {
        let caller: T::AccountId = whitelisted_caller();

        let initial_sync_data = data::initial_sync();
        EthereumBeaconClient::<T>::initial_sync(initial_sync_data).expect("Benchmarking setup cannot fail");

        let update = data::light_client_update();

    }: _(RawOrigin::Signed(caller.clone()), update.clone())
    verify {
        assert!(<SyncCommittees<T>>::get(update.sync_committee_period+1).pubkeys.len() > 0);
    }

    import_execution_header {
        let caller: T::AccountId = whitelisted_caller();

        EthereumBeaconClient::<T>::initial_sync(data::initial_sync()).expect("Benchmarking setup cannot fail");

        let update: LightClientUpdate<config::SignatureSize, config::MaxProofBranchSize, config::SyncCommitteeSize> = data::light_client_update();
        SyncCommittees::<T>::set(update.sync_committee_period+1, update.next_sync_committee);

        let block_update = data::block_update();

        LatestFinalizedHeaderState::<T>::set(FinalizedHeaderState{
            beacon_block_root: H256::default(),
            beacon_slot: block_update.block.slot,
            import_time: 0,
            beacon_block_header: update.finalized_header
        });
    }: _(RawOrigin::Signed(caller.clone()), block_update.clone())
    verify {
        let block_hash: H256 = block_update.block.body.execution_payload.block_hash;

        <ExecutionHeaders<T>>::get(block_hash).expect("Benchmarking verification cannot fail");
    }


}

impl_benchmark_test_suite!(
    EthereumBeaconClient,
    crate::mock::new_tester::<crate::mock::mock_goerli_testnet::Test>(),
    crate::mock::mock_goerli_testnet::Test,
);
