//! Benchmarking for `BalanceTransferCheck` extensions.

use crate::extension::{
    BalanceTransferCheckExtension, BalanceTransferChecks, MAXIMUM_NUMBER_OF_CALLS,
    MaybeBalancesCall, MaybeNestedCall,
};
use core::marker::PhantomData;
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::Config;
use frame_system::pallet_prelude::RuntimeCallFor;
use pallet_balances::{Call as BalancesCall, Config as BalancesConfig};
use pallet_multisig::{Call as MultisigCall, Config as MultisigConfig};
use pallet_utility::{Call as UtilityCall, Config as UtilityConfig};
use scale_info::prelude::boxed::Box;
use scale_info::prelude::vec::Vec;
use scale_info::prelude::{fmt, vec};
use sp_runtime::Weight;
use sp_runtime::traits::{Dispatchable, StaticLookup};

pub struct Pallet<T: BalancesConfig + UtilityConfig + MultisigConfig>(PhantomData<T>);

const SEED: u32 = 0;

/// Some machines have smaller stack sizes, so we need to limit the depth of the call stack.
/// This is particularly important when dropping a deeply nested call stack, because each call
/// results in two stack frames: a Call drop, and a Vec drop.
const MAXIMUM_CALL_DEPTH: usize = 1000;

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

    /// Construct a single-level list of non-balance calls, with a balance call at the end.
    #[benchmark]
    fn balance_transfer_check_multiple(c: Linear<0, MAXIMUM_NUMBER_OF_CALLS>) {
        let mut calls = Vec::with_capacity(c as usize + 1);
        for _i in 0..c {
            // Non-balance calls are more expensive to check, because we have to read them all.
            // (We can only exit the check loop early if we encounter a balance transfer call.)
            calls.push(construct_non_balance_call::<T>());
        }

        calls.push(construct_balance_call::<T>());

        let call = construct_utility_call_list::<T>(calls);

        #[block]
        {
            // In benchmarks, we force the extension to always run its checks, and always return
            // success, so we can run transfer benchmarks as well.
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }

    /// Construct a multi-level utility call tree, containing non-balance calls at the tips, and a
    /// balance call at the end.
    #[benchmark]
    fn balance_transfer_check_utility(c: Linear<0, MAXIMUM_NUMBER_OF_CALLS>) {
        let c = c as usize;

        let mut outer_call = Vec::with_capacity(c.div_ceil(MAXIMUM_CALL_DEPTH));

        let mut call = construct_non_balance_call::<T>();
        for i in 0..c {
            call = construct_utility_call::<T>(call);

            if i >= MAXIMUM_CALL_DEPTH {
                outer_call.push(call);
                call = construct_non_balance_call::<T>();
            }
        }

        outer_call.push(call);
        outer_call.push(construct_balance_call::<T>());

        let call = construct_utility_call_list::<T>(outer_call);

        #[block]
        {
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }

    /// Construct a multi-level multisig call tree, containing non-balance calls at the tips, and a
    /// balance call at the end.
    #[benchmark]
    fn balance_transfer_check_multisig(c: Linear<0, MAXIMUM_NUMBER_OF_CALLS>) {
        let c = c as usize;

        let mut outer_call = Vec::with_capacity(c.div_ceil(MAXIMUM_CALL_DEPTH));

        let mut call = construct_non_balance_call::<T>();
        for i in 0..c {
            call = construct_multisig_call::<T>(call);

            if i >= MAXIMUM_CALL_DEPTH {
                outer_call.push(call);
                call = construct_non_balance_call::<T>();
            }
        }

        outer_call.push(call);
        outer_call.push(construct_balance_call::<T>());

        let call = construct_utility_call_list::<T>(outer_call);

        #[block]
        {
            BalanceTransferCheckExtension::<T>::do_validate_signed(&call).unwrap();
        }
    }
}

/// Construct a balance transfer call.
///
/// Balance calls short-circuit the extension checks, so we can only use them at the end of a call
/// list.
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

/// Construct a non-balance call.
fn construct_non_balance_call<T: BalancesConfig>() -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<BalancesCall<T>>,
{
    let recipient: T::AccountId = account("recipient", 0, SEED);
    BalancesCall::upgrade_accounts {
        who: vec![recipient],
    }
    .into()
}

/// Construct a utility call containing a single `call`.
fn construct_utility_call<T: UtilityConfig>(call: RuntimeCallFor<T>) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<UtilityCall<T>>,
{
    UtilityCall::batch_all {
        calls: vec![call.into()],
    }
    .into()
}

/// Construct a utility call containing a list of `calls`.
fn construct_utility_call_list<T: UtilityConfig>(calls: Vec<RuntimeCallFor<T>>) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<UtilityCall<T>>,
{
    UtilityCall::batch_all {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .into()
}

/// Construct a multisig call containing a single `call`.
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
