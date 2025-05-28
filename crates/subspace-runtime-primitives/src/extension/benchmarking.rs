//! Benchmarking for `BalanceTransferCheck` extensions.

use core::marker::PhantomData;
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use pallet_balances::Config;
use pallet_utility::Config as UtilityConfig;
use scale_info::prelude::fmt;
use sp_runtime::traits::Dispatchable;

pub struct Pallet<T: Config + UtilityConfig>(PhantomData<T>);

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where
	T: Send + Sync + scale_info::TypeInfo + fmt::Debug + UtilityConfig,
    RuntimeCallFor<T>: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>)
]
mod benchmarks {
    use super::*;
    use frame_system::pallet_prelude::RuntimeCallFor;

    #[benchmark]
    fn single_balance_transfer() {
        #[block]
        {}
    }
}
