// Copyright (C) 2023 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet Domain Transaction Fees

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    use codec::{Codec, MaxEncodedLen};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;
    use sp_operator_rewards::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Saturating, Zero};
    use sp_runtime::{FixedPointOperand, SaturatedConversion};
    use sp_std::fmt::Debug;
    use sp_std::result;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The balance of an account.
        type Balance: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Codec
            + Default
            + Copy
            + MaybeSerializeDeserialize
            + Debug
            + MaxEncodedLen
            + TypeInfo
            + FixedPointOperand;
    }

    /// The accumulated rewards of the current block
    ///
    /// Currently, the only source of rewards is the transaction fees, in the future it
    /// will include the XDM reward.
    #[pallet::storage]
    #[pallet::getter(fn block_rewards)]
    pub(super) type BlockRewards<T: Config> = StorageValue<_, T::Balance, ValueQuery>;

    /// The domain transaction byte fee
    ///
    /// NOTE: we are using `ValueQuery` for convenience, which means the transactions in the domain block #1
    // are not charged for storage fees.
    #[pallet::storage]
    #[pallet::getter(fn domain_transaction_byte_fee)]
    pub(super) type DomainTransactionByteFee<T: Config> = StorageValue<_, T::Balance, ValueQuery>;

    /// The next domain transaction byte fee, it will take affect after the execution of the current
    /// block to ensure the operator are using the same fee for both validating and executing the domain
    /// transaction in the next block.
    #[pallet::storage]
    pub(super) type NextDomainTransactionByteFee<T: Config> =
        StorageValue<_, T::Balance, ValueQuery>;

    /// Pallet operator-rewards to store the accumulated rewards of the current block
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            BlockRewards::<T>::set(Zero::zero());
            T::DbWeight::get().writes(1)
        }

        fn on_finalize(_now: BlockNumberFor<T>) {
            let transaction_byte_fee = NextDomainTransactionByteFee::<T>::get();
            DomainTransactionByteFee::<T>::put(transaction_byte_fee);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight((
            // TODO: proper weight
			Weight::from_all(10_000),
			DispatchClass::Mandatory
		))]
        pub fn set_next_domain_transaction_byte_fee(
            origin: OriginFor<T>,
            #[pallet::compact] transaction_byte_fee: T::Balance,
        ) -> DispatchResult {
            ensure_none(origin)?;
            NextDomainTransactionByteFee::<T>::put(transaction_byte_fee);
            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Operator rewards inherent data not correctly encoded")
                .expect("Operator rewards inherent data must be provided");

            let transaction_byte_fee = inherent_data.saturated_into::<T::Balance>();

            Some(Call::set_next_domain_transaction_byte_fee {
                transaction_byte_fee,
            })
        }

        fn check_inherent(
            call: &Self::Call,
            data: &InherentData,
        ) -> result::Result<(), Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Operator rewards inherent data not correctly encoded")
                .expect("Operator rewards inherent data must be provided");

            let provided_transaction_byte_fee = inherent_data.saturated_into::<T::Balance>();

            if let Call::set_next_domain_transaction_byte_fee {
                transaction_byte_fee,
            } = call
            {
                if transaction_byte_fee != &provided_transaction_byte_fee {
                    return Err(InherentError::IncorrectDomainTransactionByteFee);
                }
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::set_next_domain_transaction_byte_fee { .. })
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn note_operator_rewards(rewards: T::Balance) {
            let next_block_rewards = BlockRewards::<T>::get().saturating_add(rewards);
            BlockRewards::<T>::set(next_block_rewards);
        }
    }
}
