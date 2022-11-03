// Copyright (C) 2021 Subspace Labs, Inc.
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

//! # Domain Registry Module

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::traits::{Currency, Get, LockIdentifier, LockableCurrency, WithdrawReasons};
pub use pallet::*;
use sp_domains::{BundleEquivocationProof, DomainId, FraudProof, InvalidTransactionProof};

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

const DOMAIN_LOCK_ID: LockIdentifier = *b"_domains";

#[frame_support::pallet]
mod pallet {
    use super::BalanceOf;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::LockableCurrency;
    use frame_system::pallet_prelude::*;
    use sp_arithmetic::Percent;
    use sp_domains::{
        BundleEquivocationProof, DomainId, FraudProof, InvalidTransactionCode,
        InvalidTransactionProof,
    };
    use sp_runtime::traits::Zero;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;

        /// Minimum amount of deposit to create a domain.
        #[pallet::constant]
        type MinDomainDeposit: Get<BalanceOf<Self>>;

        /// Maximum amount of deposit to create a domain.
        #[pallet::constant]
        type MaxDomainDeposit: Get<BalanceOf<Self>>;

        /// Minimal stake to be a domain operator.
        ///
        /// This is global, each domain can have its own minimum stake requirement
        /// but must be no less than this value.
        #[pallet::constant]
        type MinDomainOperatorStake: Get<BalanceOf<Self>>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Domain configuration.
    #[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
    pub struct DomainConfig<Hash, Balance> {
        /// Hash of the domain wasm runtime blob.
        pub wasm_runtime_hash: Hash,

        // May be supported later.
        //pub upgrade_keys: Vec<AccountId>,
        // TODO: elaborate this field.
        pub bundle_frequency: u32,

        /// Maximum domain bundle size in bytes.
        pub max_bundle_size: u32,

        /// Maximum domain bundle weight.
        pub max_bundle_weight: Weight,

        /// Minimum executor stake value to be an operator on this domain.
        pub min_operator_stake: Balance,
    }

    /// Domain id for the next domain.
    #[pallet::storage]
    pub(super) type NextDomainId<T> = StorageValue<_, DomainId, ValueQuery>;

    /// (domain_id, domain_creator, deposit)
    #[pallet::storage]
    pub(super) type DomainCreators<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        T::AccountId,
        BalanceOf<T>,
        OptionQuery,
    >;

    /// A map tracking all the non-system domains.
    #[pallet::storage]
    pub(super) type Domains<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, DomainConfig<T::Hash, BalanceOf<T>>, OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Creates a new domain with some deposit locked.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn create_domain(
            origin: OriginFor<T>,
            deposit: BalanceOf<T>,
            domain_config: DomainConfig<T::Hash, BalanceOf<T>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Self::can_create_domain(&who, deposit, &domain_config)?;

            let domain_id = Self::apply_create_domain(&who, deposit, &domain_config);

            Self::deposit_event(Event::<T>::NewDomain {
                creator: who,
                domain_id,
                deposit,
                domain_config,
            });

            Ok(())
        }

        // TODO: support destroy_domain in the future.

        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn update_domain_config(
            origin: OriginFor<T>,
            domain_id: DomainId,
            _domain_config: DomainConfig<T::Hash, BalanceOf<T>>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // TODO: Check if the origin account is allowed to update the config.

            // TODO: validate domain_config and deposit an event DomainConfigUpdated

            Ok(())
        }

        /// Register a new domain operator.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn register_domain_operator(
            origin: OriginFor<T>,
            domain_id: DomainId,
            to_stake: Percent,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // TODO: impl

            Ok(())
        }

        /// Update the domain stake.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn update_domain_stake(
            origin: OriginFor<T>,
            domain_id: DomainId,
            new_stake: Percent,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // TODO: impl

            Ok(())
        }

        /// Deregister a domain operator.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn deregister_domain_operator(
            origin: OriginFor<T>,
            domain_id: DomainId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // TODO: impl

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(
            origin: OriginFor<T>,
            _fraud_proof: FraudProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::FraudProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            _bundle_equivocation_proof: BundleEquivocationProof<T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::BundleEquivocationProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_invalid_transaction_proof(
            origin: OriginFor<T>,
            _invalid_transaction_proof: InvalidTransactionProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::InvalidTransactionProofProcessed);

            Ok(())
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The amount of deposit is smaller than the `T::MinDomainDeposit` bound.
        DepositTooSmall,

        /// The amount of deposit is larger than the `T::MaxDomainDeposit` bound.
        DepositTooLarge,

        /// Account does not have enough balance.
        InsufficientBalance,

        /// The minimum executor stake value in the domain config is lower than the global
        /// requirement `T::MinDomainOperatorStake`.
        OperatorStakeThresholdTooLow,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new domain was created.
        NewDomain {
            creator: T::AccountId,
            domain_id: DomainId,
            deposit: BalanceOf<T>,
            domain_config: DomainConfig<T::Hash, BalanceOf<T>>,
        },

        FraudProofProcessed,

        BundleEquivocationProofProcessed,

        InvalidTransactionProofProcessed,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_block_number: T::BlockNumber) -> Weight {
            // TODO: Need a hook in pallet-executor-registry to snapshot the domain
            // authorities as well as the stake weight on each new epoch.

            // TODO: proper weight
            Weight::zero()
        }
    }

    /// Constructs a `TransactionValidity` with pallet-domain-registry specific defaults.
    fn unsigned_validity(prefix: &'static str, tag: impl Encode) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(tag)
            .longevity(TransactionLongevity::MAX)
            // TODO: may not be necessary if using farmnet as the global executor network.
            .propagate(true)
            .build()
    }

    // TODO: the fraud-proof unsigned extrinsics are same with the ones in pallet-doamins, probably
    // find an abstraction to unify them.
    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_fraud_proof { .. } => Ok(()),
                Call::submit_bundle_equivocation_proof { .. } => Ok(()),
                Call::submit_invalid_transaction_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_fraud_proof { fraud_proof } => {
                    if let Err(e) = Self::validate_fraud_proof(fraud_proof) {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid fraud proof: {:?}, error: {:?}",
                            fraud_proof, e
                        );
                        return InvalidTransactionCode::FraudProof.into();
                    }

                    // TODO: proper tag value.
                    unsigned_validity("SubspaceSubmitFraudProof", fraud_proof)
                }
                Call::submit_bundle_equivocation_proof {
                    bundle_equivocation_proof,
                } => {
                    if let Err(e) =
                        Self::validate_bundle_equivocation_proof(bundle_equivocation_proof)
                    {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid bundle equivocation proof: {:?}, error: {:?}",
                            bundle_equivocation_proof, e
                        );
                        return InvalidTransactionCode::BundleEquivicationProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitBundleEquivocationProof",
                        bundle_equivocation_proof.hash(),
                    )
                }
                Call::submit_invalid_transaction_proof {
                    invalid_transaction_proof,
                } => {
                    if let Err(e) =
                        Self::validate_invalid_transaction_proof(invalid_transaction_proof)
                    {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Wrong InvalidTransactionProof: {:?}, error: {:?}",
                            invalid_transaction_proof, e
                        );
                        return InvalidTransactionCode::TrasactionProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitInvalidTransactionProof",
                        invalid_transaction_proof,
                    )
                }

                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    fn can_create_domain(
        who: &T::AccountId,
        deposit: BalanceOf<T>,
        domain_config: &DomainConfig<T::Hash, BalanceOf<T>>,
    ) -> Result<(), Error<T>> {
        if deposit < T::MinDomainDeposit::get() {
            return Err(Error::<T>::DepositTooSmall);
        }

        if deposit > T::MaxDomainDeposit::get() {
            return Err(Error::<T>::DepositTooLarge);
        }

        if T::Currency::free_balance(who) < deposit {
            return Err(Error::<T>::InsufficientBalance);
        }

        if domain_config.min_operator_stake < T::MinDomainOperatorStake::get() {
            return Err(Error::<T>::OperatorStakeThresholdTooLow);
        }

        Ok(())
    }

    fn apply_create_domain(
        who: &T::AccountId,
        deposit: BalanceOf<T>,
        domain_config: &DomainConfig<T::Hash, BalanceOf<T>>,
    ) -> DomainId {
        T::Currency::set_lock(DOMAIN_LOCK_ID, who, deposit, WithdrawReasons::all());

        let domain_id = NextDomainId::<T>::get();

        Domains::<T>::insert(domain_id, &domain_config);
        DomainCreators::<T>::insert(domain_id, &who, deposit);
        NextDomainId::<T>::put(domain_id + 1);

        domain_id
    }

    // TODO: Verify fraud_proof.
    fn validate_fraud_proof(_fraud_proof: &FraudProof) -> Result<(), Error<T>> {
        Ok(())
    }

    // TODO: Verify bundle_equivocation_proof.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof<T::Hash>,
    ) -> Result<(), Error<T>> {
        Ok(())
    }

    // TODO: Verify invalid_transaction_proof.
    fn validate_invalid_transaction_proof(
        _invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), Error<T>> {
        Ok(())
    }
}
