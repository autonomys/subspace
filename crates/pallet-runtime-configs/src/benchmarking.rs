//! Benchmarking for `pallet-runtime-configs`.

use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use crate::{Call, Config, Pallet};
    use frame_system::RawOrigin;

    #[benchmark]
    fn set_enable_domains() {
        #[extrinsic_call]
        _(RawOrigin::Root, true);

        assert!(Pallet::<T>::enable_domains());
    }

    #[benchmark]
    fn set_enable_dynamic_cost_of_storage() {
        #[extrinsic_call]
        _(RawOrigin::Root, true);

        assert!(Pallet::<T>::enable_dynamic_cost_of_storage());
    }

    #[benchmark]
    fn set_enable_balance_transfers() {
        #[extrinsic_call]
        _(RawOrigin::Root, true);

        assert!(Pallet::<T>::enable_balance_transfers());
    }
}
