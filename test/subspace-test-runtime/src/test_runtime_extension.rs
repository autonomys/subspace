use subspace_core_primitives::U256;

sp_api::decl_runtime_apis! {
    pub trait TestOverrideApi {
        fn overriden_tx_range() -> U256;
    }
}

pub mod pallet_test_override {
    use frame_system::offchain::SubmitTransaction;
    pub use pallet::*;

    #[frame_support::pallet(dev_mode)]
    mod pallet {
        use frame_support::pallet_prelude::*;
        use frame_system::pallet_prelude::*;
        pub use subspace_core_primitives::U256;

        #[pallet::config]
        pub trait Config: frame_system::Config {}

        #[pallet::pallet]
        pub struct Pallet<T>(_);

        #[pallet::storage]
        pub(super) type OveriddenTxRange<T> = StorageValue<_, U256>;

        #[pallet::call]
        impl<T: Config> Pallet<T> {
            #[pallet::call_index(0)]
            #[pallet::weight(0)]
            pub fn override_tx_range(origin: OriginFor<T>, new_range: U256) -> DispatchResult {
                ensure_none(origin)?;
                OveriddenTxRange::<T>::put(new_range);
                Ok(())
            }
        }

        #[pallet::validate_unsigned]
        impl<T: Config> ValidateUnsigned for Pallet<T> {
            type Call = Call<T>;
            fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
                match call {
                    Call::override_tx_range { new_range: _ } => Ok(()),
                    _ => Err(InvalidTransaction::Call.into()),
                }
            }

            fn validate_unsigned(
                _source: TransactionSource,
                call: &Self::Call,
            ) -> TransactionValidity {
                match call {
                    Call::override_tx_range { new_range } => {
                        ValidTransaction::with_tag_prefix("TestOverrideTxValue")
                            .priority(TransactionPriority::MAX)
                            .longevity(TransactionLongevity::MAX)
                            .and_provides(new_range)
                            .propagate(true)
                            .build()
                    }

                    _ => InvalidTransaction::Call.into(),
                }
            }
        }
    }

    impl<T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>> Pallet<T> {
        pub fn overridden_tx_range() -> U256 {
            OveriddenTxRange::<T>::get().unwrap_or(U256::MAX)
        }

        pub fn overridden_tx_range_unsigned(new_range: U256) {
            let call = Call::override_tx_range { new_range };

            match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
                Ok(()) => {
                    log::info!(
                        target: "subspace_test_runtime::pallet_test_override",
                        "Submitted unsigned tx to override tx range to value: {new_range}",
                    );
                }
                Err(()) => {
                    log::error!(target: "subspace_test_runtime::pallet_test_override", "Error submitting override tx value");
                }
            }
        }
    }
}
