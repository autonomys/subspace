//! Benchmarking for `pallet-messenger` extensions.
use crate::{Config, Pallet as Messenger};
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use scale_info::prelude::fmt;
use sp_runtime::traits::Dispatchable;

pub struct Pallet<T: Config>(Messenger<T>);

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where
	T: Send + Sync + scale_info::TypeInfo + fmt::Debug,
    RuntimeCallFor<T>: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>)
]
mod benchmarks {
    use super::*;
    use frame_system::pallet_prelude::RuntimeCallFor;

    #[benchmark]
    fn run_bench() {
        #[block]
        {}
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::mock::chain_a::new_test_ext(),
        crate::mock::chain_a::Runtime,
    );
}
