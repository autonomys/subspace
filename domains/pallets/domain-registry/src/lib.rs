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

#[cfg(test)]
mod tests;

use frame_support::traits::{Currency, Get, LockIdentifier, LockableCurrency, WithdrawReasons};
use frame_support::weights::Weight;
pub use pallet::*;
use sp_domains::{
    BundleEquivocationProof, DomainId, ExecutionReceipt, ExecutorPublicKey, FraudProof,
    InvalidTransactionProof,
};
use sp_executor_registry::{ExecutorRegistry, OnNewEpoch};
use sp_runtime::traits::{One, Saturating, Zero};
use sp_runtime::Percent;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec;
use sp_std::vec::Vec;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type DomainConfig<T> =
    sp_domains::DomainConfig<<T as frame_system::Config>::Hash, BalanceOf<T>, Weight>;

const DOMAIN_LOCK_ID: LockIdentifier = *b"_domains";

#[frame_support::pallet]
mod pallet {
    use super::{BalanceOf, DomainConfig};
    use codec::Codec;
    use frame_support::pallet_prelude::{StorageMap, StorageNMap, *};
    use frame_support::traits::LockableCurrency;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_domains::{
        BundleEquivocationProof, DomainId, ExecutionReceipt, ExecutorPublicKey, FraudProof,
        InvalidTransactionCode, InvalidTransactionProof, SignedOpaqueBundle,
    };
    use sp_executor_registry::ExecutorRegistry;
    use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, One};
    use sp_runtime::{FixedPointOperand, Percent};
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;

        /// The stake weight of an executor.
        type StakeWeight: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Codec
            + Default
            + Copy
            + MaybeSerializeDeserialize
            + Debug
            + MaxEncodedLen
            + TypeInfo
            + FixedPointOperand
            + From<BalanceOf<Self>>;

        /// Interface to access the executor info.
        type ExecutorRegistry: ExecutorRegistry<Self::AccountId, BalanceOf<Self>, Self::StakeWeight>;

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
        // TODO: When an executor decreases its stake in pallet-executor-registry, we should ensure
        // the new stake amount still meets the operator stake threshold on all domains he stakes.
        #[pallet::constant]
        type MinDomainOperatorStake: Get<BalanceOf<Self>>;

        /// Maximum execution receipt drift.
        ///
        /// If the primary number of an execution receipt plus the maximum drift is bigger than the
        /// best execution chain number, this receipt will be rejected as being too far in the
        /// future.
        #[pallet::constant]
        type MaximumReceiptDrift: Get<Self::BlockNumber>;

        /// Number of execution receipts kept in the state.
        #[pallet::constant]
        type ReceiptsPruningDepth: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Domain id for the next core domain.
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
        StorageMap<_, Twox64Concat, DomainId, DomainConfig<T>, OptionQuery>;

    /// (executor, domain_id, allocated_stake_proportion)
    #[pallet::storage]
    pub(super) type DomainOperators<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        T::AccountId,
        Twox64Concat,
        DomainId,
        Percent,
        OptionQuery,
    >;

    /// (domain_id, domain_authority, domain_stake_weight)
    #[pallet::storage]
    pub(super) type DomainAuthorities<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        T::AccountId,
        T::StakeWeight,
        OptionQuery,
    >;

    /// A map tracking the total stake weight of each domain.
    #[pallet::storage]
    pub(super) type DomainTotalStakeWeight<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::StakeWeight, OptionQuery>;

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////  Same receipt tracking data structure as in pallet-domains, with the dimension `domain_id` added.
    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    #[pallet::storage]
    pub(super) type ReceiptHead<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, (T::Hash, T::BlockNumber), ValueQuery>;

    #[pallet::storage]
    pub(super) type OldestReceiptNumber<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::BlockNumber, ValueQuery>;

    #[pallet::storage]
    pub(super) type Receipts<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        H256,
        ExecutionReceipt<T::BlockNumber, T::Hash, T::Hash>,
        OptionQuery,
    >;

    /// (core_domain_id, primary_block_hash, receipt_hash, receipt_count)
    #[pallet::storage]
    pub(super) type ReceiptVotes<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::Hash>,
            NMapKey<Twox64Concat, H256>,
        ),
        u32,
        ValueQuery,
    >;

    /// (core_domain_id, core_block_number, core_block_hash, core_state_root)
    #[pallet::storage]
    pub(super) type StateRoots<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::BlockNumber>,
            NMapKey<Twox64Concat, T::Hash>,
        ),
        T::Hash,
        OptionQuery,
    >;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Creates a new domain with some deposit locked.
        // TODO: proper weight
        #[pallet::weight(10_000)]
        pub fn create_domain(
            origin: OriginFor<T>,
            deposit: BalanceOf<T>,
            domain_config: DomainConfig<T>,
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
            _domain_config: DomainConfig<T>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            ensure!(
                Domains::<T>::contains_key(domain_id),
                Error::<T>::InvalidDomainId
            );

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

            if !to_stake.is_zero() {
                Self::can_stake_on_domain(&who, domain_id, to_stake)?;

                Self::do_domain_stake_update(who, domain_id, to_stake)?;
            }

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

            if !new_stake.is_zero() {
                Self::can_stake_on_domain(&who, domain_id, new_stake)?;

                Self::do_domain_stake_update(who, domain_id, new_stake)?;
            }

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

            ensure!(
                Domains::<T>::contains_key(domain_id),
                Error::<T>::InvalidDomainId
            );

            // TODO: may also have a min_domain_operators constraint?

            DomainOperators::<T>::mutate_exists(who.clone(), domain_id, |maybe_stake| {
                let old_stake = maybe_stake.take();

                if old_stake.is_some() {
                    Self::deposit_event(Event::<T>::DomainOperatorDeregistered { who, domain_id });
                    Ok(())
                } else {
                    Err(Error::<T>::NotOperator)
                }
            })?;

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_core_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            let domain_id = signed_opaque_bundle.proof_of_election.domain_id;

            let oldest_receipt_number = OldestReceiptNumber::<T>::get(domain_id);
            let (_, mut best_number) = <ReceiptHead<T>>::get(domain_id);

            for receipt in &signed_opaque_bundle.bundle.receipts {
                // Ignore the receipt if it has already been pruned.
                if receipt.primary_number < oldest_receipt_number {
                    continue;
                }

                if receipt.primary_number <= best_number {
                    // Either increase the vote for a known receipt or add a fork receipt at this height.
                    Self::apply_non_new_best_receipt(domain_id, receipt);
                } else if receipt.primary_number == best_number + One::one() {
                    Self::apply_new_best_receipt(domain_id, receipt);
                    best_number += One::one();
                } else {
                    /*
                    // Reject the entire Bundle due to the missing receipt(s) between [best_number, .., receipt.primary_number].
                    //
                    // This should never happen as pre_dispatch_submit_bundle ensures no missing receipt.
                    return Err(Error::<T>::Bundle(BundleError::Receipt(
                        ExecutionReceiptError::MissingParent,
                    ))
                    .into());
                    */
                }
            }

            Self::deposit_event(Event::CoreBundleStored {
                bundle_hash: signed_opaque_bundle.hash(),
                bundle_author: signed_opaque_bundle.proof_of_election.executor_public_key,
            });

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

    #[cfg(feature = "std")]
    type GenesisDomainInfo<T> = (
        <T as frame_system::Config>::AccountId,
        BalanceOf<T>,
        DomainConfig<T>,
        <T as frame_system::Config>::AccountId,
        Percent,
    );

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub domains: Vec<GenesisDomainInfo<T>>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                domains: Vec::new(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            NextDomainId::<T>::put(DomainId::CORE_DOMAIN_ID_START);

            for (creator, deposit, domain_config, domain_operator, operator_stake) in &self.domains
            {
                Pallet::<T>::can_create_domain(creator, *deposit, domain_config)
                    .expect("Cannot create genesis domain");
                let domain_id = Pallet::<T>::apply_create_domain(creator, *deposit, domain_config);

                Pallet::<T>::can_stake_on_domain(domain_operator, domain_id, *operator_stake)
                    .expect("Cannot register genesis domain operator");
                Pallet::<T>::do_domain_stake_update(
                    domain_operator.clone(),
                    domain_id,
                    *operator_stake,
                )
                .expect("Failed to apply the genesis domain operator registration");

                let stake_weight = T::ExecutorRegistry::authority_stake_weight(domain_operator)
                    .expect("Genesis domain operator must be a genesis executor authority; qed");
                let domain_stake_weight: T::StakeWeight = operator_stake.mul_floor(stake_weight);

                DomainAuthorities::<T>::insert(domain_id, domain_operator, domain_stake_weight);
                DomainTotalStakeWeight::<T>::mutate(domain_id, |maybe_total| {
                    let old = maybe_total.unwrap_or_default();
                    maybe_total.replace(old + domain_stake_weight);
                });
            }
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

        /// Account is not an executor.
        NotExecutor,

        /// Account is not an operator of a domain.
        NotOperator,

        /// Domain does not exist for the given domain id.
        InvalidDomainId,

        /// The amount of allocated stake is smaller than the minimum value.
        OperatorStakeTooSmall,

        /// Domain stake allocation exceeds the maximum available value.
        StakeAllocationTooLarge,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new domain was created.
        NewDomain {
            creator: T::AccountId,
            domain_id: DomainId,
            deposit: BalanceOf<T>,
            domain_config: DomainConfig<T>,
        },

        /// A new domain operator.
        NewDomainOperator {
            who: T::AccountId,
            domain_id: DomainId,
            stake: Percent,
        },

        /// Domain operator updated its stake allocation on this domain.
        DomainStakeUpdated {
            who: T::AccountId,
            domain_id: DomainId,
            new_stake: Percent,
        },

        /// A domain operator was deregistered.
        DomainOperatorDeregistered {
            who: T::AccountId,
            domain_id: DomainId,
        },

        CoreBundleStored {
            bundle_hash: H256,
            bundle_author: ExecutorPublicKey,
        },

        NewCoreDomainReceipt {
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },

        FraudProofProcessed,

        BundleEquivocationProofProcessed,

        InvalidTransactionProofProcessed,
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
                Call::submit_core_bundle {
                    signed_opaque_bundle: _,
                } => {
                    // TODO: validate signed_opaque_bundle
                    Ok(())
                }
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

impl<T: Config> OnNewEpoch<T::AccountId, T::StakeWeight> for Pallet<T> {
    // TODO: similar to the executors, bench how many domain operators can be supported.
    /// Rotate the domain authorities on each new epoch.
    fn on_new_epoch(executor_weights: BTreeMap<T::AccountId, T::StakeWeight>) {
        let _ = DomainAuthorities::<T>::clear(u32::MAX, None);
        let _ = DomainTotalStakeWeight::<T>::clear(u32::MAX, None);

        let mut total_stake_weights = BTreeMap::new();

        for (operator, domain_id, stake_allocation) in DomainOperators::<T>::iter() {
            // TODO: Need to confirm whether an inactive executor can still be the domain authority.
            if let Some(stake_weight) = executor_weights.get(&operator) {
                let domain_stake_weight: T::StakeWeight = stake_allocation.mul_floor(*stake_weight);

                total_stake_weights
                    .entry(domain_id)
                    .and_modify(|total| *total += domain_stake_weight)
                    .or_insert(domain_stake_weight);

                DomainAuthorities::<T>::insert(domain_id, operator, domain_stake_weight);
            }
        }

        for (domain_id, total_stake_weight) in total_stake_weights {
            DomainTotalStakeWeight::<T>::insert(domain_id, total_stake_weight);
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn best_execution_chain_number(domain_id: DomainId) -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get(domain_id);
        best_number
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        Self::finalized_receipt_number(domain_id) + One::one()
    }

    /// Returns the block number of latest _finalized_ receipt.
    pub fn finalized_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get(domain_id);
        best_number.saturating_sub(T::ReceiptsPruningDepth::get())
    }

    pub fn domain_authorities(domain_id: DomainId) -> Vec<(ExecutorPublicKey, T::StakeWeight)> {
        DomainAuthorities::<T>::iter_prefix(domain_id)
            .filter_map(|(who, stake_weight)| {
                T::ExecutorRegistry::executor_public_key(&who)
                    .map(|executor_public_key| (executor_public_key, stake_weight))
            })
            .collect()
    }

    pub fn domain_total_stake_weight(domain_id: DomainId) -> Option<T::StakeWeight> {
        DomainTotalStakeWeight::<T>::get(domain_id)
    }

    pub fn domain_slot_probability(domain_id: DomainId) -> Option<(u64, u64)> {
        Domains::<T>::get(domain_id).map(|domain_config| domain_config.bundle_slot_probability)
    }

    pub fn core_bundle_election_storage_keys(
        domain_id: DomainId,
        executor: T::AccountId,
    ) -> Vec<Vec<u8>> {
        vec![
            DomainAuthorities::<T>::hashed_key_for(domain_id, executor),
            DomainTotalStakeWeight::<T>::hashed_key_for(domain_id),
            Domains::<T>::hashed_key_for(domain_id),
        ]
    }

    fn can_create_domain(
        who: &T::AccountId,
        deposit: BalanceOf<T>,
        domain_config: &DomainConfig<T>,
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
        domain_config: &DomainConfig<T>,
    ) -> DomainId {
        T::Currency::set_lock(DOMAIN_LOCK_ID, who, deposit, WithdrawReasons::all());

        let domain_id = NextDomainId::<T>::get();

        Domains::<T>::insert(domain_id, domain_config);
        DomainCreators::<T>::insert(domain_id, who, deposit);
        NextDomainId::<T>::put(domain_id + 1);

        domain_id
    }

    fn can_stake_on_domain(
        who: &T::AccountId,
        domain_id: DomainId,
        to_stake: Percent,
    ) -> Result<(), Error<T>> {
        let stake_amount =
            T::ExecutorRegistry::executor_stake(who).ok_or(Error::<T>::NotExecutor)?;

        let min_stake = Domains::<T>::get(domain_id)
            .map(|domain_config| domain_config.min_operator_stake)
            .ok_or(Error::<T>::InvalidDomainId)?;

        if to_stake.mul_floor(stake_amount) < min_stake {
            return Err(Error::<T>::OperatorStakeTooSmall);
        }

        // Exclude the potential existing stake allocation on this domain.
        let already_allocated: Percent = DomainOperators::<T>::iter_prefix(who)
            .filter_map(|(id, value)| if domain_id == id { None } else { Some(value) })
            .fold(Zero::zero(), |acc, x| acc + x);

        let available_stake = Percent::one() - already_allocated;
        if to_stake > available_stake {
            return Err(Error::<T>::StakeAllocationTooLarge);
        }

        Ok(())
    }

    fn do_domain_stake_update(
        who: T::AccountId,
        domain_id: DomainId,
        new_stake: Percent,
    ) -> Result<(), Error<T>> {
        DomainOperators::<T>::mutate_exists(who.clone(), domain_id, |maybe_stake| {
            let old_stake = maybe_stake.replace(new_stake);

            if old_stake.is_some() {
                Self::deposit_event(Event::<T>::DomainStakeUpdated {
                    who,
                    domain_id,
                    new_stake,
                });
            } else {
                Self::deposit_event(Event::<T>::NewDomainOperator {
                    who,
                    domain_id,
                    stake: new_stake,
                });
            }

            Ok(())
        })
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

    fn apply_new_best_receipt(
        domain_id: DomainId,
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::Hash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Apply the new best receipt.
        <Receipts<T>>::insert(domain_id, receipt_hash, execution_receipt);
        <ReceiptHead<T>>::insert(domain_id, (primary_hash, primary_number));
        <ReceiptVotes<T>>::mutate((domain_id, primary_hash, receipt_hash), |count| {
            *count += 1;
        });

        if !primary_number.is_zero() {
            let state_root = execution_receipt
                .trace
                .last()
                .expect("There are at least 2 elements in trace after the genesis block; qed");

            <StateRoots<T>>::insert(
                (domain_id, primary_number, execution_receipt.secondary_hash),
                state_root,
            );
        }

        /* TODO:
        // Remove the expired receipts once the receipts cache is full.
        if let Some(to_prune) = primary_number.checked_sub(&T::ReceiptsPruningDepth::get()) {
            BlockHash::<T>::mutate_exists(to_prune, |maybe_block_hash| {
                if let Some(block_hash) = maybe_block_hash.take() {
                    for (receipt_hash, _) in <ReceiptVotes<T>>::drain_prefix(block_hash) {
                        Receipts::<T>::remove(receipt_hash);
                    }
                }
            });
            OldestReceiptNumber::<T>::put(to_prune + One::one());
            let _ = <StateRoots<T>>::clear_prefix(to_prune, u32::MAX, None);
        }
        */

        Self::deposit_event(Event::NewCoreDomainReceipt {
            primary_number,
            primary_hash,
        });
    }

    fn apply_non_new_best_receipt(
        domain_id: DomainId,
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::Hash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Track the fork receipt if it's not seen before.
        if !<Receipts<T>>::contains_key(domain_id, receipt_hash) {
            <Receipts<T>>::insert(domain_id, receipt_hash, execution_receipt);
            if !primary_number.is_zero() {
                let state_root = execution_receipt
                    .trace
                    .last()
                    .expect("There are at least 2 elements in trace after the genesis block; qed");

                <StateRoots<T>>::insert(
                    (domain_id, primary_number, execution_receipt.secondary_hash),
                    state_root,
                );
            }
            Self::deposit_event(Event::NewCoreDomainReceipt {
                primary_number,
                primary_hash,
            });
        }
        <ReceiptVotes<T>>::mutate((domain_id, primary_hash, receipt_hash), |count| {
            *count += 1;
        });
    }
}
