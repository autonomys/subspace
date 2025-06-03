//! Benchmarking for `BalanceTransferCheck` extensions.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::extension::{
    BalanceTransferCheckExtension, BalanceTransferChecks, MaybeBalancesCall, MaybeNestedCall,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec;
use core::marker::PhantomData;
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::Config;
use frame_system::pallet_prelude::RuntimeCallFor;
use pallet_balances::{Call as BalancesCall, Config as BalancesConfig};
use pallet_multisig::{Call as MultisigCall, Config as MultisigConfig};
use pallet_utility::{Call as UtilityCall, Config as UtilityConfig};
use scale_info::prelude::fmt;
use sp_runtime::Weight;
use sp_runtime::traits::{Dispatchable, StaticLookup};

pub struct Pallet<T: BalancesConfig + UtilityConfig + MultisigConfig>(PhantomData<T>);

const SEED: u32 = 0;

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where
	T: Send + Sync + scale_info::TypeInfo + fmt::Debug +
        UtilityConfig + BalanceTransferChecks + BalancesConfig + MultisigConfig,
    RuntimeCallFor<T>:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> +
        From<UtilityCall<T>> + From<BalancesCall<T>> + From<MultisigCall<T>> +
        Into<<T as MultisigConfig>::RuntimeCall> +
        MaybeBalancesCall<T> + MaybeNestedCall<T>)
]
mod benchmarks {
    use super::*;
    use frame_system::pallet_prelude::RuntimeCallFor;

    #[benchmark]
    fn balance_transfer_check_mixed(c: Linear<0, 1000>) {
        let mut call = construct_balance_call::<T>();
        for i in 0..=c {
            if i % 2 == 0 {
                call = construct_utility_call::<T>(call);
            } else {
                call = construct_multisig_call::<T>(call);
            }
        }
        #[block]
        {
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }

    #[benchmark]
    fn balance_transfer_check_utility(c: Linear<0, 1000>) {
        let mut call = construct_balance_call::<T>();
        for _i in 0..=c {
            call = construct_utility_call::<T>(call);
        }
        #[block]
        {
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }

    #[benchmark]
    fn balance_transfer_check_multisig(c: Linear<0, 1000>) {
        let mut call = construct_balance_call::<T>();
        for _i in 0..=c {
            call = construct_multisig_call::<T>(call);
        }
        #[block]
        {
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }
}

fn construct_balance_call<T: BalancesConfig>() -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<BalancesCall<T>>,
{
    let recipient: T::AccountId = account("recipient", 0, SEED);
    let recipient_lookup = T::Lookup::unlookup(recipient.clone());
    BalancesCall::transfer_all {
        dest: recipient_lookup,
        keep_alive: true,
    }
    .into()
}

fn construct_utility_call<T: UtilityConfig>(call: RuntimeCallFor<T>) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<UtilityCall<T>>,
{
    UtilityCall::batch_all {
        calls: vec![call.into()],
    }
    .into()
}

fn construct_multisig_call<T: MultisigConfig>(call: RuntimeCallFor<T>) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<MultisigCall<T>> + Into<<T as MultisigConfig>::RuntimeCall>,
{
    MultisigCall::as_multi {
        threshold: 0,
        other_signatories: vec![],
        maybe_timepoint: None,
        call: Box::new(call.into()),
        max_weight: Weight::zero(),
    }
    .into()
}
