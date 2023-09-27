//! Benchmarking for `pallet-subspace`.

use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use crate::{Call, Config, Pallet};
    use frame_system::RawOrigin;
    use sp_std::vec;

    #[benchmark]
    fn set_enable_domains() {
        #[extrinsic_call]
        _(RawOrigin::Root, true);

        assert!(Pallet::<T>::enable_domains());
    }

    #[benchmark]
    fn set_enable_balance_transfers() {
        #[extrinsic_call]
        _(RawOrigin::Root, true);

        assert!(Pallet::<T>::enable_balance_transfers());
    }
}
