use crate::{Runtime, RuntimeCall, RuntimeConfigs};
use frame_support::pallet_prelude::Weight;
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
    ValidTransaction,
};
use sp_std::prelude::*;
use subspace_runtime_primitives::utility::nested_call_iter;

/// Disable balance transfers, if configured in the runtime.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
pub struct DisablePallets;

impl DisablePallets {
    fn do_validate_unsigned(call: &RuntimeCall) -> TransactionValidity {
        if matches!(call, RuntimeCall::Domains(_)) && !RuntimeConfigs::enable_domains() {
            InvalidTransaction::Call.into()
        } else {
            Ok(ValidTransaction::default())
        }
    }

    fn do_validate_signed(call: &RuntimeCall) -> TransactionValidity {
        // Disable normal balance transfers.
        if !RuntimeConfigs::enable_balance_transfers() && contains_balance_transfer(call) {
            Err(InvalidTransaction::Call.into())
        } else {
            Ok(ValidTransaction::default())
        }
    }
}

impl TransactionExtension<RuntimeCall> for DisablePallets {
    const IDENTIFIER: &'static str = "DisablePallets";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    // TODO: calculate weight for extension
    fn weight(&self, _call: &RuntimeCall) -> Weight {
        // there is always one storage read
        <Runtime as frame_system::Config>::DbWeight::get().reads(1)
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

    fn bare_validate(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> TransactionValidity {
        Self::do_validate_unsigned(call)
    }

    fn bare_validate_and_prepare(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<(), TransactionValidityError> {
        Self::do_validate_unsigned(call)?;
        Ok(())
    }
}

fn contains_balance_transfer(call: &RuntimeCall) -> bool {
    for call in nested_call_iter::<Runtime>(call) {
        // Other calls are inconclusive, they might contain nested calls
        if let RuntimeCall::Balances(
            pallet_balances::Call::transfer_allow_death { .. }
            | pallet_balances::Call::transfer_keep_alive { .. }
            | pallet_balances::Call::transfer_all { .. },
        ) = call
        {
            return true;
        }
    }

    false
}
