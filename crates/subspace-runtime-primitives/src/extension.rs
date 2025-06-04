#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
pub mod weights;

use crate::extension::weights::WeightInfo as SubstrateWeightInfo;
use crate::utility::{MaybeNestedCall, nested_call_iter};
use core::marker::PhantomData;
use frame_support::RuntimeDebugNoBound;
use frame_support::pallet_prelude::Weight;
use frame_system::Config;
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use pallet_balances::Call as BalancesCall;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use scale_info::prelude::fmt;
use sp_runtime::DispatchResult;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, PostDispatchInfoOf,
    TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError, ValidTransaction,
};

/// Maximum number of calls we benchmarked for.
const MAXIMUM_NUMBER_OF_CALLS: u32 = 1000;

/// Weights for the balance transfer check extension.
pub trait WeightInfo {
    fn balance_transfer_check_multiple(c: u32) -> Weight;
    fn balance_transfer_check_utility(c: u32) -> Weight;
    fn balance_transfer_check_multisig(c: u32) -> Weight;
}

/// Trait to convert Runtime call to possible Balance call.
pub trait MaybeBalancesCall<Runtime>
where
    Runtime: pallet_balances::Config,
{
    fn maybe_balance_call(&self) -> Option<&BalancesCall<Runtime>>;
}

/// Trait to check if the Balance transfers are enabled.
pub trait BalanceTransferChecks {
    fn is_balance_transferable() -> bool;
}

/// Disable balance transfers, if configured in the runtime.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct BalanceTransferCheckExtension<Runtime>(PhantomData<Runtime>);

impl<Runtime> Default for BalanceTransferCheckExtension<Runtime>
where
    Runtime: BalanceTransferChecks + pallet_balances::Config,
    RuntimeCallFor<Runtime>: MaybeBalancesCall<Runtime> + MaybeNestedCall<Runtime>,
{
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> BalanceTransferCheckExtension<Runtime>
where
    Runtime: BalanceTransferChecks + pallet_balances::Config,
    RuntimeCallFor<Runtime>: MaybeBalancesCall<Runtime> + MaybeNestedCall<Runtime>,
{
    fn do_validate_signed(
        call: &RuntimeCallFor<Runtime>,
    ) -> Result<(ValidTransaction, u32), TransactionValidityError> {
        if Runtime::is_balance_transferable() {
            return Ok((ValidTransaction::default(), 0));
        }

        // Disable normal balance transfers.
        let (contains_balance_call, calls) = Self::contains_balance_transfer(call);
        if contains_balance_call {
            Err(InvalidTransaction::Call.into())
        } else {
            Ok((ValidTransaction::default(), calls))
        }
    }

    fn contains_balance_transfer(call: &RuntimeCallFor<Runtime>) -> (bool, u32) {
        let mut calls = 0;
        for call in nested_call_iter::<Runtime>(call) {
            calls += 1;
            // Any other calls might contain nested calls, so we can only return early if we find a
            // balance transfer call.
            if let Some(balance_call) = call.maybe_balance_call()
                && matches!(
                    balance_call,
                    BalancesCall::transfer_allow_death { .. }
                        | BalancesCall::transfer_keep_alive { .. }
                        | BalancesCall::transfer_all { .. }
                )
            {
                return (true, calls);
            }
        }

        (false, calls)
    }

    fn get_weights(n: u32) -> Weight {
        SubstrateWeightInfo::<Runtime>::balance_transfer_check_multisig(n)
            .max(SubstrateWeightInfo::<Runtime>::balance_transfer_check_multiple(n))
            .max(SubstrateWeightInfo::<Runtime>::balance_transfer_check_utility(n))
    }
}

/// Data passed from prepare to post_dispatch.
#[derive(RuntimeDebugNoBound)]
pub enum Pre {
    Refund(Weight),
}

/// Data passed from validate to prepare.
#[derive(RuntimeDebugNoBound)]
pub enum Val {
    FullRefund,
    PartialRefund(Option<u32>),
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>>
    for BalanceTransferCheckExtension<Runtime>
where
    Runtime: Config
        + pallet_balances::Config
        + scale_info::TypeInfo
        + fmt::Debug
        + Send
        + Sync
        + BalanceTransferChecks,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as Config>::AccountId> + Clone,
    RuntimeCallFor<Runtime>: MaybeBalancesCall<Runtime> + MaybeNestedCall<Runtime>,
{
    const IDENTIFIER: &'static str = "BalanceTransferCheckExtension";
    type Implicit = ();
    type Val = Val;
    type Pre = Pre;

    fn weight(&self, _call: &RuntimeCallFor<Runtime>) -> Weight {
        Self::get_weights(MAXIMUM_NUMBER_OF_CALLS)
    }

    fn validate(
        &self,
        origin: OriginFor<Runtime>,
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        let (validity, val) = if origin.as_system_origin_signer().is_some() {
            let (valid, maybe_calls) =
                Self::do_validate_signed(call).map(|(valid, calls)| (valid, Some(calls)))?;
            (valid, Val::PartialRefund(maybe_calls))
        } else {
            (ValidTransaction::default(), Val::FullRefund)
        };

        Ok((validity, val, origin))
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &DispatchOriginOf<RuntimeCallFor<Runtime>>,
        _call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        let total_weight = Self::get_weights(MAXIMUM_NUMBER_OF_CALLS);
        match val {
            // not a signed transaction, so return full refund.
            Val::FullRefund => Ok(Pre::Refund(total_weight)),

            // signed transaction with a minimum of one read weight,
            // so refund any extra call weight
            Val::PartialRefund(maybe_calls) => {
                let actual_weights = Self::get_weights(maybe_calls.unwrap_or(0));
                Ok(Pre::Refund(total_weight.saturating_sub(actual_weights)))
            }
        }
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _post_info: &PostDispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        let Pre::Refund(weight) = pre;
        Ok(weight)
    }
}
