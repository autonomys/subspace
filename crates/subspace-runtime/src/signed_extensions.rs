use crate::{Runtime, RuntimeCall, RuntimeConfigs};
use codec::{Decode, Encode};
use core::marker::PhantomData;
use scale_info::TypeInfo;
use sp_runtime::traits::{DispatchInfoOf, SignedExtension};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
};
use sp_std::prelude::*;

/// Disable specific pallets.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
pub struct DisablePallets;

impl SignedExtension for DisablePallets {
    const IDENTIFIER: &'static str = "DisablePallets";
    type AccountId = <Runtime as frame_system::Config>::AccountId;
    type Call = <Runtime as frame_system::Config>::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        _who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        // Disable normal balance transfers.
        if !RuntimeConfigs::enable_balance_transfers() && contains_balance_transfer(call) {
            InvalidTransaction::Call.into()
        } else {
            Ok(ValidTransaction::default())
        }
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        self.validate(who, call, info, len)?;
        Ok(())
    }

    fn validate_unsigned(
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        if matches!(call, RuntimeCall::Domains(_)) && !RuntimeConfigs::enable_domains() {
            InvalidTransaction::Call.into()
        } else {
            Ok(ValidTransaction::default())
        }
    }
}

fn contains_balance_transfer(call: &RuntimeCall) -> bool {
    match call {
        RuntimeCall::Balances(
            pallet_balances::Call::transfer_allow_death { .. }
            | pallet_balances::Call::transfer_keep_alive { .. }
            | pallet_balances::Call::transfer_all { .. },
        ) => true,
        RuntimeCall::Utility(utility_call) => match utility_call {
            pallet_utility::Call::batch { calls }
            | pallet_utility::Call::batch_all { calls }
            | pallet_utility::Call::force_batch { calls } => {
                calls.iter().any(contains_balance_transfer)
            }
            pallet_utility::Call::as_derivative { call, .. }
            | pallet_utility::Call::dispatch_as { call, .. }
            | pallet_utility::Call::with_weight { call, .. } => contains_balance_transfer(call),
            pallet_utility::Call::__Ignore(..) => false,
        },
        _ => false,
    }
}

/// A custom signed extension to check if the caller is an authorized history seeder for
/// the `history_seeding` pallet.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckHistorySeeder<T: pallet_history_seeding::Config>(PhantomData<T>);

impl<T: pallet_history_seeding::Config> core::fmt::Debug for CheckHistorySeeder<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckHistorySeeder").finish()
    }
}

impl<T: pallet_history_seeding::Config + Send + Sync> CheckHistorySeeder<T> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<T: pallet_history_seeding::Config + Send + Sync> Default for CheckHistorySeeder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: pallet_history_seeding::Config + Send + Sync> SignedExtension for CheckHistorySeeder<T> {
    const IDENTIFIER: &'static str = "CheckHistorySeeder";

    type AccountId = T::AccountId;
    type Call = <Runtime as frame_system::Config>::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        match call {
            crate::RuntimeCall::HistorySeeding(pallet_history_seeding::Call::seed_history {
                ..
            }) => {
                if Some(who.clone()) != pallet_history_seeding::Pallet::<T>::history_seeder() {
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransaction::BadSigner,
                    ));
                }

                Ok(ValidTransaction::default())
            }
            _ => Ok(ValidTransaction::default()),
        }
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        self.validate(who, _call, _info, _len)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{CheckHistorySeeder, Runtime, RuntimeCall, RuntimeOrigin};
    use codec::Encode;
    use frame_support::dispatch::DispatchInfo;
    use frame_support::pallet_prelude::{InvalidTransaction, TransactionValidityError};
    use frame_support::{assert_err, assert_ok};
    use sp_runtime::traits::SignedExtension;
    use sp_runtime::{AccountId32, BuildStorage};

    pub fn new_test_ext() -> sp_io::TestExternalities {
        let t = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        t.into()
    }

    #[test]
    fn test_check_history_seeder_works() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::HistorySeeding(pallet_history_seeding::Call::seed_history {
                remark: vec![0u8; 256],
            });

            let who = AccountId32::new([0u8; 32]);

            assert_err!(
                CheckHistorySeeder::<Runtime>::new().pre_dispatch(
                    &who,
                    &call,
                    &DispatchInfo::default(),
                    call.encoded_size()
                ),
                TransactionValidityError::Invalid(InvalidTransaction::BadSigner),
            );

            // set seeder
            pallet_history_seeding::Pallet::<Runtime>::set_history_seeder(
                RuntimeOrigin::root(),
                who.clone(),
            )
            .unwrap();

            assert_ok!(CheckHistorySeeder::<Runtime>::new().pre_dispatch(
                &who,
                &call,
                &DispatchInfo::default(),
                call.encoded_size()
            ));
        });
    }
}
