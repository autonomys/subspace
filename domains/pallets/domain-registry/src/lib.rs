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

use codec::{Decode, Encode};
use frame_support::traits::{Currency, Get, LockIdentifier, LockableCurrency, WithdrawReasons};
use frame_support::weights::Weight;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_domains::bundle_election::{
    verify_bundle_solution_threshold, ReadBundleElectionParamsError,
};
use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use sp_domains::{
    BundleSolution, DomainId, ExecutorPublicKey, ProofOfElection, SignedOpaqueBundle, StakeWeight,
};
use sp_executor_registry::{ExecutorRegistry, OnNewEpoch};
use sp_runtime::traits::{BlakeTwo256, One, Zero};
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
    use frame_support::pallet_prelude::{StorageMap, *};
    use frame_support::traits::LockableCurrency;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use pallet_receipts::{Error as PalletReceiptError, FraudProofError};
    use sp_domain_digests::AsPredigest;
    use sp_domains::bundle_election::ReadBundleElectionParamsError;
    use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{DomainId, SignedOpaqueBundle};
    use sp_executor_registry::ExecutorRegistry;
    use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize};
    use sp_runtime::{FixedPointOperand, Percent};
    use sp_std::fmt::Debug;
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_receipts::Config {
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
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
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

    /// At which block the domain was created.
    #[pallet::storage]
    pub(super) type CreatedAt<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::BlockNumber, OptionQuery>;

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

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Creates a new domain with some deposit locked.
        // TODO: proper weight
        #[pallet::call_index(0)]
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
        #[pallet::call_index(1)]
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
        #[pallet::call_index(2)]
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
        ///
        /// NOTE: This has an _identical_ implementation to [`Call::register_domain_operator`],
        /// which is intentional, otherwise, it can be confusing when an operator wants to update
        /// the domain stake but has to call a API named `register_domain_operator` that usually
        /// implies the caller is not yet an operator.
        // TODO: proper weight
        #[pallet::call_index(3)]
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
        #[pallet::call_index(4)]
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

        // TODO: Rename this extrinsic since the core bundle is not submit to the transaction pool but crafted and injected
        // on fly when building the system domain block.
        // TODO: proper weight
        #[pallet::call_index(5)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_core_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            pallet_receipts::Pallet::<T>::track_receipts(
                signed_opaque_bundle.domain_id(),
                signed_opaque_bundle.bundle.receipts.as_slice(),
            )
            .map_err(Error::<T>::from)?;

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(6)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(origin: OriginFor<T>, fraud_proof: FraudProof) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domain-registry", "Processing fraud proof: {fraud_proof:?}");

            if fraud_proof.domain_id.is_core() {
                pallet_receipts::Pallet::<T>::process_fraud_proof(fraud_proof)
                    .map_err(Error::<T>::from)?;
            }

            // TODO: slash the executor accordingly.

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(7)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            _bundle_equivocation_proof: BundleEquivocationProof<T::BlockNumber, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::BundleEquivocationProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(8)]
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

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            let primary_block_info = <frame_system::Pallet<T>>::digest()
                .logs
                .iter()
                .filter_map(|s| s.as_primary_block_info::<T::BlockNumber, T::Hash>())
                .collect::<Vec<_>>();

            let mut consumed_weight = Weight::zero();
            for domain_id in Domains::<T>::iter_keys() {
                for (primary_number, primary_hash) in &primary_block_info {
                    pallet_receipts::PrimaryBlockHash::<T>::insert(
                        domain_id,
                        primary_number,
                        primary_hash,
                    );
                    consumed_weight += T::DbWeight::get().reads_writes(1, 1);
                }
            }

            consumed_weight
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

    impl<T> From<ReadBundleElectionParamsError> for Error<T> {
        fn from(_error: ReadBundleElectionParamsError) -> Self {
            Self::FailedToReadBundleElectionParams
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum ReceiptError {
        /// A missing core domain parent receipt.
        MissingParent,
        /// Core domain receipt is too far in the future.
        TooFarInFuture,
        /// Core domain receipt points to an unknown primary block.
        UnknownBlock,
        /// Valid receipts start after the domain creation.
        BeforeDomainCreation,
    }

    impl<T> From<PalletReceiptError> for Error<T> {
        fn from(error: PalletReceiptError) -> Self {
            match error {
                PalletReceiptError::MissingParent => Self::Receipt(ReceiptError::MissingParent),
                PalletReceiptError::FraudProof(err) => Self::FraudProof(err),
                PalletReceiptError::UnavailablePrimaryBlockHash => {
                    Self::UnavailablePrimaryBlockHash
                }
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

        /// An error occurred while reading the state needed for verifying the bundle solution.
        FailedToReadBundleElectionParams,

        /// Invalid core domain bundle solution.
        BadBundleElectionSolution,

        /// State root of a core domain block is missing.
        StateRootNotFound,

        /// Invalid core domain state root.
        BadStateRoot,

        /// Not a core domain bundle.
        NotCoreDomainBundle,

        /// Can not find the number of block the domain was created at.
        DomainNotCreated,

        /// Can not find the block hash of given primary block number.
        UnavailablePrimaryBlockHash,

        /// Bundle was created on an unknown primary block (probably a fork block).
        BundleCreatedOnUnknownBlock,

        /// Receipt error.
        Receipt(ReceiptError),

        /// Fraud proof error.
        FraudProof(FraudProofError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
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
                    signed_opaque_bundle,
                } => Self::pre_dispatch_submit_core_bundle(signed_opaque_bundle).map_err(|e| {
                    log::error!(target: "runtime::domain-registry", "Bad core bundle, error: {e:?}");
                    TransactionValidityError::Invalid(InvalidTransactionCode::Bundle.into())
                }),
                Call::submit_fraud_proof { .. } => Ok(()),
                Call::submit_bundle_equivocation_proof { .. } => Ok(()),
                Call::submit_invalid_transaction_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_fraud_proof { fraud_proof } => {
                    if let Err(e) = pallet_receipts::Pallet::<T>::validate_fraud_proof(fraud_proof)
                    {
                        log::error!(
                            target: "runtime::domain-registry",
                            "Bad fraud proof: {fraud_proof:?}, error: {e:?}",
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
                            target: "runtime::domain-registry",
                            "Bad bundle equivocation proof: {bundle_equivocation_proof:?}, error: {e:?}",
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
                            target: "runtime::domain-registry",
                            "Bad invalid transaction proof: {invalid_transaction_proof:?}, error: {e:?}",
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

impl<T: Config> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof) {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domain-registry", "Submitted fraud proof");
            }
            Err(()) => {
                log::error!(target: "runtime::domain-registry", "Error submitting fraud proof");
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn head_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::head_receipt_number(domain_id)
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::oldest_receipt_number(domain_id)
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

    fn pre_dispatch_submit_core_bundle(
        signed_opaque_bundle: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), Error<T>> {
        let BundleSolution::Core {
            proof_of_election,
            core_block_number,
            core_block_hash,
            core_state_root
        } = &signed_opaque_bundle.bundle_solution else {
            return Err(Error::<T>::NotCoreDomainBundle);
        };

        let domain_id = signed_opaque_bundle.domain_id();

        if !domain_id.is_core() {
            return Err(Error::<T>::NotCoreDomainBundle);
        }

        let bundle = &signed_opaque_bundle.bundle;

        let bundle_created_on_valid_primary_block =
            pallet_receipts::PrimaryBlockHash::<T>::get(domain_id, bundle.header.primary_number)
                .map(|block_hash| block_hash == bundle.header.primary_hash)
                .unwrap_or(false);

        if !bundle_created_on_valid_primary_block {
            log::error!(
                target: "runtime::domain-registry",
                "Bundle of {domain_id:?} is probabaly created on a primary fork #{:?}, expected: {:?}, got: {:?}",
                bundle.header.primary_number,
                pallet_receipts::PrimaryBlockHash::<T>::get(domain_id, bundle.header.primary_number),
                bundle.header.primary_hash,
            );
            return Err(Error::BundleCreatedOnUnknownBlock);
        }

        let created_at = CreatedAt::<T>::get(domain_id).ok_or(Error::<T>::DomainNotCreated)?;
        let head_receipt_number = Self::head_receipt_number(domain_id);
        let max_allowed = head_receipt_number + T::MaximumReceiptDrift::get();

        let mut new_best_number = head_receipt_number;
        let receipts = &bundle.receipts;
        for receipt in receipts {
            // Non-best receipt
            if receipt.primary_number <= new_best_number {
                continue;
                // New nest receipt.
            } else if receipt.primary_number == new_best_number + One::one() {
                new_best_number += One::one();
                // Missing receipt.
            } else {
                let missing_receipt_number = new_best_number + One::one();
                log::error!(
                    target: "runtime::domain-registry",
                    "Receipt for {domain_id:?} #{missing_receipt_number:?} is missing, \
                    head_receipt_number: {head_receipt_number:?}, max_allowed: {max_allowed:?}, received: {:?}",
                    receipts.iter().map(|r| r.primary_number).collect::<Vec<_>>()
                );
                return Err(Error::<T>::Receipt(ReceiptError::MissingParent));
            }

            let primary_number = receipt.primary_number;

            if primary_number <= created_at {
                log::error!(
                    target: "runtime::domain-registry",
                    "Domain was created at #{created_at:?}, but this receipt points to an earlier block #{:?}", receipt.primary_number,
                );
                return Err(Error::<T>::Receipt(ReceiptError::BeforeDomainCreation));
            }

            if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(domain_id, receipt) {
                log::error!(
                    target: "runtime::domain-registry",
                    "Receipt of {domain_id:?} #{primary_number:?},{:?} points to an unknown primary block, \
                    expected: #{primary_number:?},{:?}",
                    receipt.primary_hash,
                    pallet_receipts::PrimaryBlockHash::<T>::get(domain_id, primary_number),
                );
                return Err(Error::<T>::Receipt(ReceiptError::UnknownBlock));
            }

            if primary_number > max_allowed {
                log::error!(
                    target: "runtime::domain-registry",
                    "Receipt for #{primary_number:?} is too far in future, max_allowed: {max_allowed:?}",
                );
                return Err(Error::<T>::Receipt(ReceiptError::TooFarInFuture));
            }
        }

        // The validity of vrf proof itself has been verified on the primary chain, thus only the
        // proof_of_election is necessary to be checked here.
        let ProofOfElection {
            vrf_output,
            storage_proof,
            state_root,
            executor_public_key,
            global_challenge,
            ..
        } = &proof_of_election;

        let core_block_number = T::BlockNumber::from(*core_block_number);

        // Considering this scenario, a core domain stalls at block 1 for a long time and then
        // resumes at block 1000, assuming `MaximumReceiptDrift` is 128 and the receipt of
        // block 1 had been submitted, the range of receipts in the new bundle created at
        // block 1000 would be (1, 1+128] , thus the state root corresponding to block 1000,i.e.,
        // `core_state_root`, can not be verified, in which case the `core_state_root`
        // verification will be skipped.
        //
        // We can not simply remove the `MaximumReceiptDrift` constraint as it's unwise to
        // fill in an unlimited number of missing receipts in one single bundle when the
        // domain resumes because the computation resource per block is limited anyway.
        //
        // This edge case does not impact the security due to the fraud-proof mechanism.
        let state_root_verifiable = core_block_number <= new_best_number;

        if !core_block_number.is_zero() && state_root_verifiable {
            let maybe_state_root = bundle.receipts.iter().find_map(|receipt| {
                receipt.trace.last().and_then(|state_root| {
                    if (receipt.primary_number, receipt.domain_hash)
                        == (core_block_number, *core_block_hash)
                    {
                        Some(*state_root)
                    } else {
                        None
                    }
                })
            });

            let expected_state_root = match maybe_state_root {
                Some(v) => v,
                None => pallet_receipts::Pallet::<T>::state_root((
                    domain_id,
                    core_block_number,
                    core_block_hash,
                ))
                    .ok_or(Error::<T>::StateRootNotFound)
                    .map_err(|err| {
                        log::error!(
                        target: "runtime::domain-registry",
                        "State root for {domain_id:?} #{core_block_number:?},{core_block_hash:?} not found, \
                        current head receipt: {:?}",
                        pallet_receipts::Pallet::<T>::receipt_head(domain_id),
                    );
                        err
                    })?,
            };

            if expected_state_root != *core_state_root {
                log::error!(
                    target: "runtime::domains",
                    "Bad state root for {domain_id:?} #{core_block_number:?},{core_block_hash:?}, \
                    expected: {expected_state_root:?}, got: {core_state_root:?}",
                );
                return Err(Error::<T>::BadStateRoot);
            }
        }

        let db = storage_proof.clone().into_memory_db::<BlakeTwo256>();

        let state_root =
            sp_core::H256::decode(&mut state_root.encode().as_slice()).expect("StateRootNotH256");

        let read_value = |storage_key: Vec<u8>| {
            sp_trie::read_trie_value::<sp_trie::LayoutV1<BlakeTwo256>, _>(
                &db,
                &state_root,
                &storage_key,
                None,
                None,
            )
            .map_err(|_| ReadBundleElectionParamsError::TrieError)?
            .ok_or(ReadBundleElectionParamsError::MissingValue)
        };

        fn decode<T: Decode>(storage_key: Vec<u8>) -> Result<T, ReadBundleElectionParamsError> {
            T::decode(&mut storage_key.as_slice())
                .map_err(|_| ReadBundleElectionParamsError::DecodeError)
        }

        let executor_key = T::ExecutorRegistry::key_owner_storage_key(executor_public_key);
        let executor: T::AccountId = decode(read_value(executor_key)?)?;

        let stake_weight_key = DomainAuthorities::<T>::hashed_key_for(domain_id, executor);
        let stake_weight: StakeWeight = decode(read_value(stake_weight_key)?)?;

        let total_stake_weight_key = DomainTotalStakeWeight::<T>::hashed_key_for(domain_id);
        let total_stake_weight: StakeWeight = decode(read_value(total_stake_weight_key)?)?;

        let domain_config_key = Domains::<T>::hashed_key_for(domain_id);
        let domain_config: DomainConfig<T> = decode(read_value(domain_config_key)?)?;

        let slot_probability = domain_config.bundle_slot_probability;

        verify_bundle_solution_threshold(
            domain_id,
            *vrf_output,
            stake_weight,
            total_stake_weight,
            slot_probability,
            executor_public_key,
            global_challenge,
        )
        .map_err(|_| Error::<T>::BadBundleElectionSolution)?;

        Ok(())
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

        let current_block_number = frame_system::Pallet::<T>::block_number();
        CreatedAt::<T>::insert(domain_id, current_block_number);
        pallet_receipts::Pallet::<T>::initialize_head_receipt_number(
            domain_id,
            current_block_number,
        );

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

    // TODO: Verify bundle_equivocation_proof.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof<T::BlockNumber, T::Hash>,
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
