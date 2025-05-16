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

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod fees;

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_support::storage::generator::StorageValue as _;
    use frame_system::pallet_prelude::*;
    use parity_scale_codec::{Codec, MaxEncodedLen};
    use scale_info::TypeInfo;
    use sp_block_fees::{INHERENT_IDENTIFIER, InherentError, InherentType};
    use sp_domains::{BlockFees, ChainId};
    use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Saturating};
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

        /// The domain chain byte fee
        type DomainChainByteFee: Get<Self::Balance>;
    }

    /// The accumulated rewards of the current block
    ///
    /// Currently, the only source of rewards is the transaction fees, in the future it
    /// will include the XDM reward.
    #[pallet::storage]
    #[pallet::getter(fn collected_block_fees)]
    pub(super) type CollectedBlockFees<T: Config> =
        StorageValue<_, BlockFees<T::Balance>, ValueQuery>;

    /// The consensus chain byte fee
    ///
    /// NOTE: we are using `ValueQuery` for convenience, which means the transactions in the domain block #1
    // are not charged for the consensus chain storage fees.
    #[pallet::storage]
    #[pallet::getter(fn consensus_chain_byte_fee)]
    pub(super) type ConsensusChainByteFee<T: Config> = StorageValue<_, T::Balance, ValueQuery>;

    /// The next consensus chain byte fee, it will take affect after the execution of the current
    /// block to ensure the operator are using the same fee for both validating and executing the domain
    /// transaction in the next block.
    #[pallet::storage]
    pub(super) type NextConsensusChainByteFee<T: Config> = StorageValue<_, T::Balance, ValueQuery>;

    /// Pallet block-fees to store the accumulated rewards of the current block
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            // NOTE: set the `CollectedBlockFees` to an empty value instead of removing the value
            // completely so we can generate a storage proof to prove the empty value, which is used
            // in the fraud proof.
            CollectedBlockFees::<T>::set(BlockFees::<T::Balance>::default());
            T::DbWeight::get().writes(1)
        }

        fn on_finalize(_now: BlockNumberFor<T>) {
            let transaction_byte_fee = NextConsensusChainByteFee::<T>::take();
            ConsensusChainByteFee::<T>::put(transaction_byte_fee);
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
        pub fn set_next_consensus_chain_byte_fee(
            origin: OriginFor<T>,
            #[pallet::compact] transaction_byte_fee: T::Balance,
        ) -> DispatchResult {
            ensure_none(origin)?;
            NextConsensusChainByteFee::<T>::put(transaction_byte_fee);
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
                .expect("Domain block fees inherent data not correctly encoded")
                .expect("Domain block fees inherent data must be provided");

            let transaction_byte_fee = inherent_data.saturated_into::<T::Balance>();

            Some(Call::set_next_consensus_chain_byte_fee {
                transaction_byte_fee,
            })
        }

        fn check_inherent(
            call: &Self::Call,
            data: &InherentData,
        ) -> result::Result<(), Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Domain block fees inherent data not correctly encoded")
                .expect("Domain block fees inherent data must be provided");

            let provided_transaction_byte_fee = inherent_data.saturated_into::<T::Balance>();

            if let Call::set_next_consensus_chain_byte_fee {
                transaction_byte_fee,
            } = call
                && transaction_byte_fee != &provided_transaction_byte_fee
            {
                return Err(InherentError::IncorrectConsensusChainByteFee);
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::set_next_consensus_chain_byte_fee { .. })
        }
    }

    impl<T: Config> Pallet<T> {
        /// Note the domain execution fee including the storage and compute fee on domain chain,
        /// tip, and the XDM reward.
        pub fn note_domain_execution_fee(rewards: T::Balance) {
            CollectedBlockFees::<T>::mutate(|block_fees| {
                block_fees.domain_execution_fee =
                    block_fees.domain_execution_fee.saturating_add(rewards);
            });
        }

        /// Note consensus chain storage fee
        pub fn note_consensus_storage_fee(storage_fee: T::Balance) {
            CollectedBlockFees::<T>::mutate(|block_fees| {
                block_fees.consensus_storage_fee =
                    block_fees.consensus_storage_fee.saturating_add(storage_fee);
            });
        }

        /// Note burned balance on domains
        pub fn note_burned_balance(burned_balance: T::Balance) {
            CollectedBlockFees::<T>::mutate(|block_fees| {
                block_fees.burned_balance =
                    block_fees.burned_balance.saturating_add(burned_balance);
            });
        }

        /// Note chain reward fees.
        pub fn note_chain_rewards(chain_id: ChainId, balance: T::Balance) {
            CollectedBlockFees::<T>::mutate(|block_fees| {
                let total_balance = match block_fees.chain_rewards.get(&chain_id) {
                    None => balance,
                    Some(prev_balance) => prev_balance.saturating_add(balance),
                };
                block_fees.chain_rewards.insert(chain_id, total_balance)
            });
        }

        /// Return the final domain transaction byte fee, which consist of:
        /// - The `ConsensusChainByteFee` for the consensus chain storage cost since the domain
        ///   transaction need to be bundled and submitted to the consensus chain first.
        ///
        /// - The `DomainChainByteFee` for the domain chain storage cost
        pub fn final_domain_transaction_byte_fee() -> T::Balance {
            ConsensusChainByteFee::<T>::get().saturating_add(T::DomainChainByteFee::get())
        }

        pub fn block_fees_storage_key() -> Vec<u8> {
            CollectedBlockFees::<T>::storage_value_final_key().to_vec()
        }
    }
}
