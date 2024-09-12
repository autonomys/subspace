//! Benchmarking for the pallet-history-seeding

use super::*;
use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use super::*;
    use crate::Pallet;
    use frame_support::pallet_prelude::*;
    use frame_system::RawOrigin;
    use sp_std::vec;

    #[benchmark]
    fn seed_history(
        b: Linear<0, { *T::BlockLength::get().max.get(DispatchClass::Normal) }>,
    ) -> Result<(), BenchmarkError> {
        let remark_message = vec![1; b as usize];
        let seeder: T::AccountId = account("HistorySeeder", 1, 0);

        Pallet::<T>::set_history_seeder(RawOrigin::Root.into(), seeder.clone()).unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(seeder), remark_message);

        Ok(())
    }

    #[benchmark]
    fn set_history_seeder() {
        let seeder = account("HistorySeeder", 1, 0);
        #[extrinsic_call]
        _(RawOrigin::Root, seeder);
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
