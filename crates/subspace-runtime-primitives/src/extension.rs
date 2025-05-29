#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
pub mod weights;

use crate::utility::{nested_call_iter, MaybeNestedCall};
use core::marker::PhantomData;
use frame_support::pallet_prelude::Weight;
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use frame_system::Config;
use pallet_balances::Call as BalancesCall;
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, Dispatchable, TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};

/// Weights for the balance transfer check extension.
pub trait WeightInfo {
    fn balance_transfer_check_mixed(c: u32) -> Weight;
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
    fn do_validate_signed(call: &RuntimeCallFor<Runtime>) -> TransactionValidity {
        // Disable normal balance transfers.
        if !Runtime::is_balance_transferable() && Self::contains_balance_transfer(call) {
            Err(InvalidTransaction::Call.into())
        } else {
            Ok(ValidTransaction::default())
        }
    }

    fn contains_balance_transfer(call: &RuntimeCallFor<Runtime>) -> bool {
        for call in nested_call_iter::<Runtime>(call) {
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
                return true;
            }
        }

        false
    }
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
    const IDENTIFIER: &'static str = "DisablePallets";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    // TODO: calculate weight for extension
    fn weight(&self, _call: &RuntimeCallFor<Runtime>) -> Weight {
        // there is always one storage read
        <Runtime as Config>::DbWeight::get().reads(1)
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
        let validity = if origin.as_system_origin_signer().is_some() {
            Self::do_validate_signed(call)?
        } else {
            ValidTransaction::default()
        };

        Ok((validity, (), origin))
    }

    impl_tx_ext_default!(RuntimeCallFor<Runtime>; prepare);
}
