use crate::{Call, Runtime, RuntimeConfigs, Subspace, Sudo};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::traits::{DispatchInfoOf, SignedExtension};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
};
use sp_std::prelude::*;
/// Controls non-root access to feeds and object store
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
pub struct CheckStorageAccess;

impl SignedExtension for CheckStorageAccess {
    const IDENTIFIER: &'static str = "CheckStorageAccess";
    type AccountId = <Runtime as frame_system::Config>::AccountId;
    type Call = <Runtime as frame_system::Config>::Call;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        if Subspace::is_storage_access_enabled() || Some(who) == Sudo::key().as_ref() {
            Ok(ValidTransaction::default())
        } else {
            InvalidTransaction::BadSigner.into()
        }
    }

    fn pre_dispatch(
        self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(())
    }
}

/// Disable specific pallets.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
pub struct DisablePallets;

impl SignedExtension for DisablePallets {
    const IDENTIFIER: &'static str = "DisablePallets";
    type AccountId = <Runtime as frame_system::Config>::AccountId;
    type Call = <Runtime as frame_system::Config>::Call;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn pre_dispatch(
        self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(())
    }

    fn validate_unsigned(
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        if matches!(call, Call::Executor(_)) && !RuntimeConfigs::enable_executor() {
            InvalidTransaction::Call.into()
        } else {
            Ok(ValidTransaction::default())
        }
    }
}
