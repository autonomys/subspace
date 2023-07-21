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

//! Pallet Domains

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(array_windows)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;

pub mod block_tree;
pub mod domain_registry;
pub mod runtime_registry;
mod staking;
mod staking_epoch;
pub mod weights;

use crate::block_tree::verify_execution_receipt;
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, InspectFreeze};
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_domains::bundle_producer_election::{is_below_threshold, BundleProducerElectionParams};
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{
    DomainBlockLimit, DomainId, DomainInstanceData, OperatorId, OperatorPublicKey, RuntimeId,
};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Zero};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
use sp_runtime::{RuntimeAppPublic, SaturatedConversion, Saturating};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;
use subspace_core_primitives::U256;

pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

pub(crate) type FungibleFreezeId<T> =
    <<T as Config>::Currency as InspectFreeze<<T as frame_system::Config>::AccountId>>::Id;

pub(crate) type NominatorId<T> = <T as frame_system::Config>::AccountId;

pub trait FreezeIdentifier<T: Config> {
    fn staking_freeze_id(operator_id: OperatorId) -> FungibleFreezeId<T>;
    fn domain_instantiation_id(domain_id: DomainId) -> FungibleFreezeId<T>;
}

pub type ExecutionReceiptOf<T> = sp_domains::v2::ExecutionReceipt<
    <T as frame_system::Config>::BlockNumber,
    <T as frame_system::Config>::Hash,
    <T as Config>::DomainNumber,
    <T as Config>::DomainHash,
    BalanceOf<T>,
>;

pub type OpaqueBundleOf<T> = sp_domains::v2::OpaqueBundle<
    <T as frame_system::Config>::BlockNumber,
    <T as frame_system::Config>::Hash,
    <T as Config>::DomainNumber,
    <T as Config>::DomainHash,
    BalanceOf<T>,
>;

/// Parameters used to verify proof of election.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub(crate) struct ElectionVerificationParams<Balance> {
    operators: BTreeMap<OperatorId, Balance>,
    total_domain_stake: Balance,
}

#[frame_support::pallet]
mod pallet {
    // TODO: a complaint on `submit_bundle` call, revisit once new v2 features are complete.
    #![allow(clippy::large_enum_variant)]

    use crate::block_tree::{
        execution_receipt_type, process_execution_receipt, DomainBlock, Error as BlockTreeError,
        ReceiptType,
    };
    use crate::domain_registry::{
        do_instantiate_domain, DomainConfig, DomainObject, Error as DomainRegistryError,
    };
    use crate::runtime_registry::{
        do_register_runtime, do_schedule_runtime_upgrade, do_upgrade_runtimes,
        register_runtime_at_genesis, Error as RuntimeRegistryError, RuntimeObject,
        ScheduledRuntimeUpgrade,
    };
    use crate::staking::{
        do_deregister_operator, do_nominate_operator, do_register_operator, do_reward_operators,
        do_switch_operator_domain, do_withdraw_stake, Error as StakingError, Nominator, Operator,
        OperatorConfig, StakingSummary, Withdraw,
    };
    use crate::staking_epoch::{
        do_finalize_domain_current_epoch, do_unlock_pending_withdrawals,
        Error as StakingEpochError, PendingNominatorUnlock,
    };
    use crate::weights::WeightInfo;
    use crate::{
        BalanceOf, ElectionVerificationParams, FreezeIdentifier, NominatorId, OpaqueBundleOf,
    };
    use codec::FullCodec;
    use frame_support::pallet_prelude::{StorageMap, *};
    use frame_support::traits::fungible::{InspectFreeze, Mutate, MutateFreeze};
    use frame_support::weights::Weight;
    use frame_support::{Identity, PalletError};
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_domains::fraud_proof::FraudProof;
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{
        DomainId, ExtrinsicsRoot, GenesisDomain, OperatorId, ReceiptHash, RuntimeId, RuntimeType,
    };
    use sp_runtime::traits::{
        AtLeast32BitUnsigned, BlockNumberProvider, Bounded, CheckEqual, CheckedAdd, MaybeDisplay,
        One, SimpleBitOps, Zero,
    };
    use sp_runtime::SaturatedConversion;
    use sp_std::collections::btree_set::BTreeSet;
    use sp_std::fmt::Debug;
    use sp_std::vec;
    use sp_std::vec::Vec;
    use subspace_core_primitives::U256;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Domain block number type.
        type DomainNumber: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + MaybeDisplay
            + AtLeast32BitUnsigned
            + Default
            + Bounded
            + Copy
            + sp_std::hash::Hash
            + sp_std::str::FromStr
            + MaxEncodedLen
            + TypeInfo;

        /// Domain block hash type.
        type DomainHash: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + MaybeDisplay
            + SimpleBitOps
            + Ord
            + Default
            + Copy
            + CheckEqual
            + sp_std::hash::Hash
            + AsRef<[u8]>
            + AsMut<[u8]>
            + MaxEncodedLen
            + Into<H256>
            + From<H256>;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        type ConfirmationDepthK: Get<Self::BlockNumber>;

        /// Delay before a domain runtime is upgraded.
        type DomainRuntimeUpgradeDelay: Get<Self::BlockNumber>;

        /// Currency type used by the domains for staking and other currency related stuff.
        type Currency: Mutate<Self::AccountId>
            + MutateFreeze<Self::AccountId>
            + InspectFreeze<Self::AccountId>;

        /// Type representing the shares in the staking protocol.
        type Share: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + AtLeast32BitUnsigned
            + FullCodec
            + Copy
            + Default
            + TypeInfo
            + MaxEncodedLen
            + IsType<BalanceOf<Self>>;

        /// Identifier used for Freezing the funds used for staking.
        type FreezeIdentifier: FreezeIdentifier<Self>;

        /// The block tree pruning depth, its value should <= `BlockHashCount` because we
        /// need the consensus block hash to verify execution receipt, which is used to
        /// construct the node of the block tree.
        ///
        /// TODO: `BlockTreePruningDepth` <= `BlockHashCount` is not enough to guarantee the consensus block
        /// hash must exists while verifying receipt because the domain block is not mapping to the consensus
        /// block one by one, we need to either store the consensus block hash in runtime manually or store
        /// the consensus block hash in the client side and use host function to get them in runtime.
        #[pallet::constant]
        type BlockTreePruningDepth: Get<Self::DomainNumber>;

        /// The maximum block size limit for all domain.
        #[pallet::constant]
        type MaxDomainBlockSize: Get<u32>;

        /// The maximum block weight limit for all domain.
        #[pallet::constant]
        type MaxDomainBlockWeight: Get<Weight>;

        /// The maximum bundle per block limit for all domain.
        #[pallet::constant]
        type MaxBundlesPerBlock: Get<u32>;

        /// The maximum domain name length limit for all domain.
        #[pallet::constant]
        type MaxDomainNameLength: Get<u32>;

        /// The amount of fund to be locked up for the domain instance creator.
        #[pallet::constant]
        type DomainInstantiationDeposit: Get<BalanceOf<Self>>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;

        /// Initial domain tx range value.
        type InitialDomainTxRange: Get<u64>;

        /// Domain tx range is adjusted after every DomainTxRangeAdjustmentInterval blocks.
        type DomainTxRangeAdjustmentInterval: Get<u64>;

        /// Minimum operator stake required to become operator of a domain.
        type MinOperatorStake: Get<BalanceOf<Self>>;

        /// Minimum number of blocks after which any finalized withdrawls are released to nominators.
        type StakeWithdrawalLockingPeriod: Get<Self::BlockNumber>;

        /// Domain epoch transition interval
        type StakeEpochDuration: Get<Self::DomainNumber>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Bundles submitted successfully in current block.
    #[pallet::storage]
    pub(super) type SuccessfulBundles<T> = StorageMap<_, Identity, DomainId, Vec<H256>, ValueQuery>;

    /// Stores the next runtime id.
    #[pallet::storage]
    pub(super) type NextRuntimeId<T> = StorageValue<_, RuntimeId, ValueQuery>;

    #[pallet::storage]
    pub(super) type RuntimeRegistry<T: Config> =
        StorageMap<_, Identity, RuntimeId, RuntimeObject<T::BlockNumber, T::Hash>, OptionQuery>;

    #[pallet::storage]
    pub(super) type ScheduledRuntimeUpgrades<T: Config> = StorageDoubleMap<
        _,
        Identity,
        T::BlockNumber,
        Identity,
        RuntimeId,
        ScheduledRuntimeUpgrade,
        OptionQuery,
    >;

    #[pallet::storage]
    pub(super) type NextOperatorId<T> = StorageValue<_, OperatorId, ValueQuery>;

    #[pallet::storage]
    pub(super) type OperatorIdOwner<T: Config> =
        StorageMap<_, Identity, OperatorId, T::AccountId, OptionQuery>;

    #[pallet::storage]
    pub(super) type DomainStakingSummary<T: Config> =
        StorageMap<_, Identity, DomainId, StakingSummary<OperatorId, BalanceOf<T>>, OptionQuery>;

    /// List of all registered operators and their configuration.
    #[pallet::storage]
    pub(super) type Operators<T: Config> =
        StorageMap<_, Identity, OperatorId, Operator<BalanceOf<T>, T::Share>, OptionQuery>;

    /// Temporary hold of all the operators who decided to switch to another domain.
    /// Once epoch is complete, these operators are added to new domains under next_operators.
    #[pallet::storage]
    pub(super) type PendingOperatorSwitches<T: Config> =
        StorageMap<_, Identity, DomainId, Vec<OperatorId>, OptionQuery>;

    /// List of all current epoch's nominators and their shares under a given operator,
    #[pallet::storage]
    pub(super) type Nominators<T: Config> = StorageDoubleMap<
        _,
        Identity,
        OperatorId,
        Identity,
        NominatorId<T>,
        Nominator<T::Share>,
        OptionQuery,
    >;

    /// Deposits initiated a nominator under this operator.
    /// Will be stored temporarily until the current epoch is complete.
    /// Once, epoch is complete, these deposits are staked beginning next epoch.
    #[pallet::storage]
    pub(super) type PendingDeposits<T: Config> = StorageDoubleMap<
        _,
        Identity,
        OperatorId,
        Identity,
        NominatorId<T>,
        BalanceOf<T>,
        OptionQuery,
    >;

    /// Withdrawals initiated a nominator under this operator.
    /// Will be stored temporarily until the current epoch is complete.
    /// Once, epoch is complete, these will be moved to PendingNominatorUnlocks.
    #[pallet::storage]
    pub(super) type PendingWithdrawals<T: Config> = StorageDoubleMap<
        _,
        Identity,
        OperatorId,
        Identity,
        NominatorId<T>,
        Withdraw<BalanceOf<T>>,
        OptionQuery,
    >;

    /// Operators who chose to deregister from a domain.
    /// Stored here temporarily until domain epoch is complete.
    #[pallet::storage]
    pub(super) type PendingOperatorDeregistrations<T: Config> =
        StorageMap<_, Identity, DomainId, Vec<OperatorId>, OptionQuery>;

    /// Stores a list of operators who are unlocking in the coming blocks.
    /// The operator will be removed when the wait period is over
    /// or when the operator is slashed.
    #[pallet::storage]
    pub(super) type PendingOperatorUnlocks<T: Config> =
        StorageValue<_, BTreeSet<OperatorId>, ValueQuery>;

    /// All the pending unlocks for the nominators.
    /// We use this storage to fetch all the pending unlocks under a operator pool at the time of slashing.
    #[pallet::storage]
    pub(super) type PendingNominatorUnlocks<T: Config> = StorageDoubleMap<
        _,
        Identity,
        OperatorId,
        Identity,
        T::BlockNumber,
        Vec<PendingNominatorUnlock<NominatorId<T>, BalanceOf<T>>>,
        OptionQuery,
    >;

    /// A list of operators that are either unregistering or one more of the nominators
    /// are withdrawing some staked funds.
    #[pallet::storage]
    pub(super) type PendingUnlocks<T: Config> =
        StorageMap<_, Identity, T::BlockNumber, BTreeSet<OperatorId>, OptionQuery>;

    /// Stores the next domain id.
    #[pallet::storage]
    pub(super) type NextDomainId<T> = StorageValue<_, DomainId, ValueQuery>;

    /// The domain registry
    #[pallet::storage]
    pub(super) type DomainRegistry<T: Config> =
        StorageMap<_, Identity, DomainId, DomainObject<T::BlockNumber, T::AccountId>, OptionQuery>;

    /// The domain block tree, map (`domain_id`, `domain_block_number`) to the hash of a domain blocks,
    /// which can be used get the domain block in `DomainBlocks`
    #[pallet::storage]
    pub(super) type BlockTree<T: Config> = StorageDoubleMap<
        _,
        Identity,
        DomainId,
        Identity,
        T::DomainNumber,
        BTreeSet<ReceiptHash>,
        ValueQuery,
    >;

    /// Mapping of domain block hash to domain block
    #[pallet::storage]
    pub(super) type DomainBlocks<T: Config> = StorageMap<
        _,
        Identity,
        ReceiptHash,
        DomainBlock<T::BlockNumber, T::Hash, T::DomainNumber, T::DomainHash, BalanceOf<T>>,
        OptionQuery,
    >;

    /// The head receipt number of each domain
    #[pallet::storage]
    pub(super) type HeadReceiptNumber<T: Config> =
        StorageMap<_, Identity, DomainId, T::DomainNumber, ValueQuery>;

    /// A set of `bundle_extrinsics_root` from all bundles that successfully submitted to the consensus
    /// block, these extrinsics will be used to construct the domain block and `ExecutionInbox` is used
    /// to ensure subsequent ERs of that domain block include all pre-validated extrinsic bundles.
    #[pallet::storage]
    pub type ExecutionInbox<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Identity, DomainId>,
            NMapKey<Identity, T::DomainNumber>,
            NMapKey<Identity, T::BlockNumber>,
        ),
        Vec<ExtrinsicsRoot>,
        ValueQuery,
    >;

    /// The block number of the best domain block, increase by one when the first bundle of the domain is
    /// successfully submitted to current consensus block, which mean a new domain block with this block
    /// number will be produce. Used as a pointer in `ExecutionInbox` to identify the current under building
    /// domain block, also used as a mapping of consensus block number to domain block number.
    #[pallet::storage]
    pub(super) type HeadDomainNumber<T: Config> =
        StorageMap<_, Identity, DomainId, T::DomainNumber, ValueQuery>;

    /// The genesis domian that scheduled to register at block #1, should be removed once
    /// https://github.com/paritytech/substrate/issues/14541 is resolved.
    #[pallet::storage]
    type PendingGenesisDomain<T: Config> =
        StorageValue<_, GenesisDomain<T::AccountId>, OptionQuery>;

    /// A temporary storage to hold any previous epoch details for a given domain
    /// if the epoch transitioned in this block so that all the submitted bundles
    /// within this block are verified.
    /// The storage is cleared on block finalization.
    #[pallet::storage]
    pub(super) type LastEpochStakingDistribution<T: Config> =
        StorageMap<_, Identity, DomainId, ElectionVerificationParams<BalanceOf<T>>, OptionQuery>;

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
    pub enum BundleError {
        /// Can not find the operator for given operator id.
        InvalidOperatorId,
        /// Invalid signature on the bundle header.
        BadBundleSignature,
        /// Invalid vrf signature in the proof of election.
        BadVrfSignature,
        /// Can not find the domain for given domain id.
        InvalidDomainId,
        /// Operator is not allowed to produce bundles in current epoch.
        BadOperator,
        /// Failed to pass the threshold check.
        ThresholdUnsatisfied,
        /// The Bundle is created too long ago.
        StaleBundle,
        /// An invalid execution receipt found in the bundle.
        Receipt(BlockTreeError),
    }

    impl<T> From<RuntimeRegistryError> for Error<T> {
        fn from(err: RuntimeRegistryError) -> Self {
            Error::RuntimeRegistry(err)
        }
    }

    impl<T> From<StakingError> for Error<T> {
        fn from(err: StakingError) -> Self {
            Error::Staking(err)
        }
    }

    impl<T> From<StakingEpochError> for Error<T> {
        fn from(err: StakingEpochError) -> Self {
            Error::StakingEpoch(err)
        }
    }

    impl<T> From<DomainRegistryError> for Error<T> {
        fn from(err: DomainRegistryError) -> Self {
            Error::DomainRegistry(err)
        }
    }

    impl<T> From<BlockTreeError> for Error<T> {
        fn from(err: BlockTreeError) -> Self {
            Error::BlockTree(err)
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid fraud proof.
        FraudProof,
        /// Runtime registry specific errors
        RuntimeRegistry(RuntimeRegistryError),
        /// Staking related errors.
        Staking(StakingError),
        /// Staking epoch specific errors.
        StakingEpoch(StakingEpochError),
        /// Domain registry specific errors
        DomainRegistry(DomainRegistryError),
        /// Block tree specific errors
        BlockTree(BlockTreeError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A domain bundle was included.
        BundleStored {
            domain_id: DomainId,
            bundle_hash: H256,
            bundle_author: OperatorId,
        },
        DomainRuntimeCreated {
            runtime_id: RuntimeId,
            runtime_type: RuntimeType,
        },
        DomainRuntimeUpgradeScheduled {
            runtime_id: RuntimeId,
            scheduled_at: T::BlockNumber,
        },
        DomainRuntimeUpgraded {
            runtime_id: RuntimeId,
        },
        OperatorRegistered {
            operator_id: OperatorId,
            domain_id: DomainId,
        },
        OperatorNominated {
            operator_id: OperatorId,
            nominator_id: NominatorId<T>,
        },
        DomainInstantiated {
            domain_id: DomainId,
        },
        OperatorSwitchedDomain {
            old_domain_id: DomainId,
            new_domain_id: DomainId,
        },
        OperatorDeregistered {
            operator_id: OperatorId,
        },
        WithdrewStake {
            operator_id: OperatorId,
            nominator_id: NominatorId<T>,
        },
    }

    /// Per-domain state for tx range calculation.
    #[derive(Debug, Default, Decode, Encode, TypeInfo, PartialEq, Eq)]
    pub struct TxRangeState {
        /// Current tx range.
        pub tx_range: U256,

        /// Blocks in the current adjustment interval.
        pub interval_blocks: u64,

        /// Bundles in the current adjustment interval.
        pub interval_bundles: u64,
    }

    impl TxRangeState {
        /// Called when a bundle is added to the current block.
        pub fn on_bundle(&mut self) {
            self.interval_bundles += 1;
        }
    }

    #[pallet::storage]
    pub(super) type DomainTxRangeState<T: Config> =
        StorageMap<_, Identity, DomainId, TxRangeState, OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_all(10_000))]
        // TODO: proper benchmark
        pub fn submit_bundle(
            origin: OriginFor<T>,
            opaque_bundle: OpaqueBundleOf<T>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {opaque_bundle:?}");

            let domain_id = opaque_bundle.domain_id();
            let bundle_hash = opaque_bundle.hash();
            let extrinsics_root = opaque_bundle.extrinsics_root();
            let operator_id = opaque_bundle.operator_id();
            let receipt = opaque_bundle.into_receipt();

            match execution_receipt_type::<T>(domain_id, &receipt) {
                // The stale receipt should not be further processed, but we still track them for purposes
                // of measuring the bundle production rate.
                ReceiptType::Stale => {
                    Self::note_domain_bundle(domain_id);
                    return Ok(());
                }
                ReceiptType::Rejected(rejected_receipt_type) => {
                    return Err(Error::<T>::BlockTree(rejected_receipt_type.into()).into());
                }
                // Add the exeuctione receipt to the block tree
                ReceiptType::Accepted(accepted_receipt_type) => {
                    let maybe_pruned_domain_block_info = process_execution_receipt::<T>(
                        domain_id,
                        operator_id,
                        receipt,
                        accepted_receipt_type,
                    )
                    .map_err(Error::<T>::from)?;

                    // if any domain block is pruned, then we have a new head added
                    // so distribute the operator rewards and, if required, do epoch transition as well.
                    if let Some(pruned_block_info) = maybe_pruned_domain_block_info {
                        do_reward_operators::<T>(
                            domain_id,
                            pruned_block_info.operator_ids.into_iter(),
                            pruned_block_info.rewards,
                        )
                        .map_err(Error::<T>::from)?;

                        let consensus_block_number = frame_system::Pallet::<T>::block_number();
                        do_finalize_domain_current_epoch::<T>(
                            domain_id,
                            pruned_block_info.domain_block_number,
                            consensus_block_number,
                        )
                        .map_err(Error::<T>::from)?;
                    }
                }
            }

            // `SuccessfulBundles` is empty means this is the first accepted bundle for this domain in this
            // consensus block, which also mean a domain block will be produced thus update `HeadDomainNumber`
            // to this domain block's block number.
            if SuccessfulBundles::<T>::get(domain_id).is_empty() {
                let next_number = HeadDomainNumber::<T>::get(domain_id)
                    .checked_add(&One::one())
                    .ok_or::<Error<T>>(BlockTreeError::MaxHeadDomainNumber.into())?;
                HeadDomainNumber::<T>::set(domain_id, next_number);
            }

            // Put the `extrinsics_root` to the inbox of the current under building domain block
            let head_domain_number = HeadDomainNumber::<T>::get(domain_id);
            let consensus_block_number = frame_system::Pallet::<T>::current_block_number();
            ExecutionInbox::<T>::append(
                (domain_id, head_domain_number, consensus_block_number),
                extrinsics_root,
            );

            SuccessfulBundles::<T>::append(domain_id, bundle_hash);

            Self::note_domain_bundle(domain_id);

            Self::deposit_event(Event::BundleStored {
                domain_id,
                bundle_hash,
                bundle_author: operator_id,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(
            match fraud_proof {
                FraudProof::InvalidStateTransition(..) => (
                    T::WeightInfo::submit_system_domain_invalid_state_transition_proof(),
                    Pays::No
                ),
                // TODO: proper weight
                _ => (Weight::from_all(10_000), Pays::No),
            }
        )]
        pub fn submit_fraud_proof(
            origin: OriginFor<T>,
            fraud_proof: FraudProof<T::BlockNumber, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing fraud proof: {fraud_proof:?}");

            // TODO: Implement fraud proof processing.

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn register_domain_runtime(
            origin: OriginFor<T>,
            runtime_name: Vec<u8>,
            runtime_type: RuntimeType,
            code: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let block_number = frame_system::Pallet::<T>::current_block_number();
            let runtime_id =
                do_register_runtime::<T>(runtime_name, runtime_type.clone(), code, block_number)
                    .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::DomainRuntimeCreated {
                runtime_id,
                runtime_type,
            });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn upgrade_domain_runtime(
            origin: OriginFor<T>,
            runtime_id: RuntimeId,
            code: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let block_number = frame_system::Pallet::<T>::current_block_number();
            let scheduled_at = do_schedule_runtime_upgrade::<T>(runtime_id, code, block_number)
                .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::DomainRuntimeUpgradeScheduled {
                runtime_id,
                scheduled_at,
            });

            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn register_operator(
            origin: OriginFor<T>,
            domain_id: DomainId,
            amount: BalanceOf<T>,
            config: OperatorConfig<BalanceOf<T>>,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            let operator_id = do_register_operator::<T>(owner, domain_id, amount, config)
                .map_err(Error::<T>::from)?;
            Self::deposit_event(Event::OperatorRegistered {
                operator_id,
                domain_id,
            });

            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn nominate_operator(
            origin: OriginFor<T>,
            operator_id: OperatorId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let nominator_id = ensure_signed(origin)?;

            do_nominate_operator::<T>(operator_id, nominator_id.clone(), amount)
                .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::OperatorNominated {
                operator_id,
                nominator_id,
            });

            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn instantiate_domain(
            origin: OriginFor<T>,
            domain_config: DomainConfig,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let created_at = frame_system::Pallet::<T>::current_block_number();

            let domain_id = do_instantiate_domain::<T>(domain_config, who, created_at)
                .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::DomainInstantiated { domain_id });

            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn switch_domain(
            origin: OriginFor<T>,
            operator_id: OperatorId,
            new_domain_id: DomainId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let old_domain_id = do_switch_operator_domain::<T>(who, operator_id, new_domain_id)
                .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::OperatorSwitchedDomain {
                old_domain_id,
                new_domain_id,
            });

            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn deregister_operator(
            origin: OriginFor<T>,
            operator_id: OperatorId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            do_deregister_operator::<T>(who, operator_id).map_err(Error::<T>::from)?;

            Self::deposit_event(Event::OperatorDeregistered { operator_id });

            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight((Weight::from_all(10_000), Pays::Yes))]
        // TODO: proper benchmark
        pub fn withdraw_stake(
            origin: OriginFor<T>,
            operator_id: OperatorId,
            withdraw: Withdraw<BalanceOf<T>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            do_withdraw_stake::<T>(operator_id, who.clone(), withdraw).map_err(Error::<T>::from)?;

            Self::deposit_event(Event::WithdrewStake {
                operator_id,
                nominator_id: who,
            });

            Ok(())
        }
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub genesis_domain: Option<GenesisDomain<T::AccountId>>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                genesis_domain: None,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            // Delay the genesis domain register to block #1 due to the required `GenesisReceiptExtension` is not
            // registered during genesis storage build, remove once https://github.com/paritytech/substrate/issues/14541
            // is resolved.
            if let Some(genesis_domain) = &self.genesis_domain {
                PendingGenesisDomain::<T>::set(Some(genesis_domain.clone()));
            }
        }
    }

    #[pallet::hooks]
    // TODO: proper benchmark
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            if block_number.is_one() {
                if let Some(ref genesis_domain) = PendingGenesisDomain::<T>::take() {
                    // Register the genesis domain runtime
                    let runtime_id = register_runtime_at_genesis::<T>(
                        genesis_domain.runtime_name.clone(),
                        genesis_domain.runtime_type.clone(),
                        genesis_domain.runtime_version.clone(),
                        genesis_domain.code.clone(),
                        Zero::zero(),
                    )
                    .expect("Genesis runtime registration must always succeed");

                    // Instantiate the genesis domain
                    let domain_config = DomainConfig::from_genesis::<T>(genesis_domain, runtime_id);
                    let domain_owner = genesis_domain.owner_account_id.clone();
                    let domain_id = do_instantiate_domain::<T>(
                        domain_config,
                        domain_owner.clone(),
                        Zero::zero(),
                    )
                    .expect("Genesis domain instantiation must always succeed");

                    // Register domain_owner as the genesis operator.
                    let operator_config = OperatorConfig {
                        signing_key: genesis_domain.signing_key.clone(),
                        minimum_nominator_stake: genesis_domain
                            .minimum_nominator_stake
                            .saturated_into(),
                        nomination_tax: genesis_domain.nomination_tax,
                    };
                    let operator_stake = T::MinOperatorStake::get();
                    do_register_operator::<T>(
                        domain_owner,
                        domain_id,
                        operator_stake,
                        operator_config,
                    )
                    .expect("Genesis operator registration must succeed");

                    do_finalize_domain_current_epoch::<T>(domain_id, Zero::zero(), Zero::zero())
                        .expect("Genesis epoch must succeed");
                }
            }

            do_upgrade_runtimes::<T>(block_number);

            do_unlock_pending_withdrawals::<T>(block_number)
                .expect("Pending unlocks should not fail due to checks at epoch");

            let _ = SuccessfulBundles::<T>::clear(u32::MAX, None);

            Weight::zero()
        }

        fn on_finalize(_: T::BlockNumber) {
            let _ = LastEpochStakingDistribution::<T>::clear(u32::MAX, None);
            Self::update_domain_tx_range();
        }
    }

    /// Constructs a `TransactionValidity` with pallet-executor specific defaults.
    fn unsigned_validity(prefix: &'static str, tag: impl Encode) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(tag)
            .longevity(TransactionLongevity::MAX)
            // We need this extrinsic to be propagated to the farmer nodes.
            .propagate(true)
            .build()
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_bundle { opaque_bundle } => {
                    Self::pre_dispatch_submit_bundle(opaque_bundle)
                }
                Call::submit_fraud_proof { fraud_proof: _ } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_bundle { opaque_bundle } => {
                    if let Err(e) = Self::validate_bundle(opaque_bundle) {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad bundle {:?}, error: {e:?}", opaque_bundle.domain_id(),
                        );
                        if let BundleError::Receipt(_) = e {
                            return InvalidTransactionCode::ExecutionReceipt.into();
                        } else {
                            return InvalidTransactionCode::Bundle.into();
                        }
                    }

                    ValidTransaction::with_tag_prefix("SubspaceSubmitBundle")
                        .priority(TransactionPriority::MAX)
                        .longevity(T::ConfirmationDepthK::get().try_into().unwrap_or_else(|_| {
                            panic!("Block number always fits in TransactionLongevity; qed")
                        }))
                        .and_provides(opaque_bundle.hash())
                        .propagate(true)
                        .build()
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    // TODO: Validate fraud proof

                    // TODO: proper tag value.
                    unsigned_validity("SubspaceSubmitFraudProof", fraud_proof)
                }

                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn successful_bundles(domain_id: DomainId) -> Vec<H256> {
        SuccessfulBundles::<T>::get(domain_id)
    }

    pub fn successful_bundles_of_all_domains() -> Vec<H256> {
        let mut res = Vec::new();
        for mut bundles in SuccessfulBundles::<T>::iter_values() {
            res.append(&mut bundles);
        }
        res
    }

    pub fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>> {
        RuntimeRegistry::<T>::get(Self::runtime_id(domain_id)?)
            .map(|runtime_object| runtime_object.code)
    }

    pub fn runtime_id(domain_id: DomainId) -> Option<RuntimeId> {
        DomainRegistry::<T>::get(domain_id)
            .map(|domain_object| domain_object.domain_config.runtime_id)
    }

    pub fn domain_instance_data(domain_id: DomainId) -> Option<DomainInstanceData> {
        let runtime_id = DomainRegistry::<T>::get(domain_id)?
            .domain_config
            .runtime_id;
        let (runtime_type, runtime_code) = RuntimeRegistry::<T>::get(runtime_id)
            .map(|runtime_object| (runtime_object.runtime_type, runtime_object.code))?;
        Some(DomainInstanceData {
            runtime_type,
            runtime_code,
        })
    }

    pub fn genesis_state_root(domain_id: DomainId) -> Option<H256> {
        BlockTree::<T>::get(domain_id, T::DomainNumber::zero())
            .first()
            .and_then(DomainBlocks::<T>::get)
            .map(|block| block.execution_receipt.final_state_root.into())
    }

    /// Returns the tx range for the domain.
    pub fn domain_tx_range(domain_id: DomainId) -> U256 {
        DomainTxRangeState::<T>::try_get(domain_id)
            .map(|state| state.tx_range)
            .ok()
            .unwrap_or_else(Self::initial_tx_range)
    }

    pub fn bundle_producer_election_params(
        domain_id: DomainId,
    ) -> Option<BundleProducerElectionParams<BalanceOf<T>>> {
        match (
            DomainRegistry::<T>::get(domain_id),
            DomainStakingSummary::<T>::get(domain_id),
        ) {
            (Some(domain_object), Some(stake_summary)) => Some(BundleProducerElectionParams {
                current_operators: stake_summary
                    .current_operators
                    .keys()
                    .cloned()
                    .collect::<Vec<OperatorId>>(),
                total_domain_stake: stake_summary.current_total_stake,
                bundle_slot_probability: domain_object.domain_config.bundle_slot_probability,
            }),
            _ => None,
        }
    }

    pub fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, BalanceOf<T>)> {
        Operators::<T>::get(operator_id)
            .map(|operator| (operator.signing_key, operator.current_total_stake))
    }

    fn pre_dispatch_submit_bundle(
        opaque_bundle: &OpaqueBundleOf<T>,
    ) -> Result<(), TransactionValidityError> {
        let domain_id = opaque_bundle.domain_id();
        let receipt = &opaque_bundle.sealed_header.header.receipt;

        // TODO: Implement bundle validation.

        verify_execution_receipt::<T>(domain_id, receipt)
            .map_err(|_| InvalidTransaction::Call.into())
    }

    // Check if a bundle is stale
    fn check_stale_bundle(
        current_block_number: T::BlockNumber,
        bundle_create_at: T::BlockNumber,
    ) -> Result<(), BundleError> {
        let confirmation_depth_k = T::ConfirmationDepthK::get();
        if let Some(finalized) = current_block_number.checked_sub(&confirmation_depth_k) {
            {
                // Ideally, `bundle_create_at` is `current_block_number - 1`, we need
                // to handle the edge case that `T::ConfirmationDepthK` happens to be 1.
                let is_stale_bundle = if confirmation_depth_k.is_zero() {
                    unreachable!(
                        "ConfirmationDepthK is guaranteed to be non-zero at genesis config"
                    )
                } else if confirmation_depth_k == One::one() {
                    bundle_create_at < finalized
                } else {
                    bundle_create_at <= finalized
                };

                if is_stale_bundle {
                    log::debug!(
                        target: "runtime::domains",
                        "Bundle created on an ancient consensus block, current_block_number: {current_block_number:?}, \
                        ConfirmationDepthK: {confirmation_depth_k:?}, `bundle_create_at`: {:?}, `finalized`: {finalized:?}",
                        bundle_create_at,
                    );
                    return Err(BundleError::StaleBundle);
                }
            }
        }
        Ok(())
    }

    fn validate_bundle(opaque_bundle: &OpaqueBundleOf<T>) -> Result<(), BundleError> {
        let operator_id = opaque_bundle.operator_id();
        let sealed_header = &opaque_bundle.sealed_header;

        let operator = Operators::<T>::get(operator_id).ok_or(BundleError::InvalidOperatorId)?;

        if !operator
            .signing_key
            .verify(&sealed_header.pre_hash(), &sealed_header.signature)
        {
            return Err(BundleError::BadBundleSignature);
        }

        let domain_id = opaque_bundle.domain_id();
        let receipt = &sealed_header.header.receipt;
        let bundle_create_at = sealed_header.header.consensus_block_number;

        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Reject the stale bundles so that they can't be used by attacker to occupy the block space without cost.
        Self::check_stale_bundle(current_block_number, bundle_create_at)?;

        // TODO: Implement bundle validation.

        verify_execution_receipt::<T>(domain_id, receipt).map_err(BundleError::Receipt)?;

        let proof_of_election = &sealed_header.header.proof_of_election;
        proof_of_election
            .verify_vrf_signature(&operator.signing_key)
            .map_err(|_| BundleError::BadVrfSignature)?;

        let bundle_slot_probability = DomainRegistry::<T>::get(domain_id)
            .ok_or(BundleError::InvalidDomainId)?
            .domain_config
            .bundle_slot_probability;

        let (operator_stake, total_domain_stake) =
            Self::fetch_operator_stake_info(domain_id, &operator_id)?;

        let threshold = sp_domains::bundle_producer_election::calculate_threshold(
            operator_stake.saturated_into(),
            total_domain_stake.saturated_into(),
            bundle_slot_probability,
        );

        if !is_below_threshold(&proof_of_election.vrf_signature.output, threshold) {
            return Err(BundleError::ThresholdUnsatisfied);
        }

        Ok(())
    }

    /// Return operators specific election verification params for Proof of Election verification.
    /// If there was an epoch transition in this block for this domain,
    ///     then return the parameters from previous epoch stored in LastEpochStakingDistribution
    /// Else, return those details from the Domain's stake summary for this epoch.
    fn fetch_operator_stake_info(
        domain_id: DomainId,
        operator_id: &OperatorId,
    ) -> Result<(BalanceOf<T>, BalanceOf<T>), BundleError> {
        match LastEpochStakingDistribution::<T>::get(domain_id) {
            None => {
                let domain_stake_summary = DomainStakingSummary::<T>::get(domain_id)
                    .ok_or(BundleError::InvalidDomainId)?;

                let operator_stake = domain_stake_summary
                    .current_operators
                    .get(operator_id)
                    .ok_or(BundleError::BadOperator)?;

                Ok((*operator_stake, domain_stake_summary.current_total_stake))
            }
            Some(pending_election_params) => {
                let operator_stake = pending_election_params
                    .operators
                    .get(operator_id)
                    .ok_or(BundleError::BadOperator)?;
                Ok((*operator_stake, pending_election_params.total_domain_stake))
            }
        }
    }

    /// Called when a bundle is added to update the bundle state for tx range
    /// calculation.
    fn note_domain_bundle(domain_id: DomainId) {
        DomainTxRangeState::<T>::mutate(domain_id, |maybe_state| match maybe_state {
            Some(state) => {
                state.interval_bundles += 1;
            }
            None => {
                maybe_state.replace(TxRangeState {
                    tx_range: Self::initial_tx_range(),
                    interval_blocks: 0,
                    interval_bundles: 1,
                });
            }
        });
    }

    /// Called when the block is finalized to update the tx range for all the
    /// domains with bundles in the block.
    fn update_domain_tx_range() {
        for domain_id in DomainTxRangeState::<T>::iter_keys() {
            if let Some(domain_config) =
                DomainRegistry::<T>::get(domain_id).map(|obj| obj.domain_config)
            {
                DomainTxRangeState::<T>::mutate(domain_id, |maybe_tx_range_state| {
                    if let Some(tx_range_state) = maybe_tx_range_state {
                        let tx_range_adjustment_interval =
                            T::DomainTxRangeAdjustmentInterval::get();

                        tx_range_state.interval_blocks += 1;

                        if tx_range_state.interval_blocks < tx_range_adjustment_interval {
                            return;
                        }

                        // End of interval, calculate the new tx range.
                        let TxRangeState {
                            tx_range,
                            interval_blocks,
                            interval_bundles,
                        } = tx_range_state;

                        let actual_bundle_count = *interval_bundles;
                        let expected_bundle_count = tx_range_adjustment_interval
                            * u64::from(domain_config.target_bundles_per_block);

                        let new_tx_range = calculate_tx_range(
                            *tx_range,
                            actual_bundle_count,
                            expected_bundle_count,
                        );

                        log::trace!(
                            target: "runtime::domains",
                            "tx range update: blocks = {interval_blocks}, bundles = {actual_bundle_count}, prev = {tx_range}, new = {new_tx_range}"
                        );

                        // Reset the tx range and start over.
                        tx_range_state.tx_range = new_tx_range;
                        tx_range_state.interval_blocks = 0;
                        tx_range_state.interval_bundles = 0;
                    }
                })
            }
        }
    }

    /// Calculates the initial tx range.
    fn initial_tx_range() -> U256 {
        U256::MAX / T::InitialDomainTxRange::get()
    }

    /// Returns the best execution chain number.
    pub fn head_receipt_number(domain_id: DomainId) -> T::DomainNumber {
        HeadReceiptNumber::<T>::get(domain_id)
    }

    /// Returns the block number of oldest execution receipt.
    pub fn oldest_receipt_number(domain_id: DomainId) -> T::DomainNumber {
        Self::head_receipt_number(domain_id).saturating_sub(Self::block_tree_pruning_depth())
    }

    /// Returns the block tree pruning depth.
    pub fn block_tree_pruning_depth() -> T::DomainNumber {
        T::BlockTreePruningDepth::get()
    }

    /// Returns the domain block limit of the given domain.
    pub fn domain_block_limit(domain_id: DomainId) -> Option<DomainBlockLimit> {
        DomainRegistry::<T>::get(domain_id).map(|domain_obj| DomainBlockLimit {
            max_block_size: domain_obj.domain_config.max_block_size,
            max_block_weight: domain_obj.domain_config.max_block_weight,
        })
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_bundle`].
    pub fn submit_bundle_unsigned(opaque_bundle: OpaqueBundleOf<T>) {
        let slot = opaque_bundle.sealed_header.slot_number();
        let extrincis_count = opaque_bundle.extrinsics.len();

        let call = Call::submit_bundle { opaque_bundle };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(
                    target: "runtime::domains",
                    "Submitted bundle from slot {slot}, extrinsics: {extrincis_count}",
                );
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting bundle");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof<T::BlockNumber, T::Hash>) {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted fraud proof");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting fraud proof");
            }
        }
    }
}

/// Calculates the new tx range based on the bundles produced during the interval.
pub fn calculate_tx_range(
    cur_tx_range: U256,
    actual_bundle_count: u64,
    expected_bundle_count: u64,
) -> U256 {
    if actual_bundle_count == 0 || expected_bundle_count == 0 {
        return cur_tx_range;
    }

    let Some(new_tx_range) = U256::from(actual_bundle_count)
        .saturating_mul(&cur_tx_range)
        .checked_div(&U256::from(expected_bundle_count)) else {
        return cur_tx_range;
    };

    let upper_bound = cur_tx_range.saturating_mul(&U256::from(4_u64));
    let Some(lower_bound) = cur_tx_range.checked_div(&U256::from(4_u64)) else {
        return cur_tx_range;
    };
    new_tx_range.clamp(lower_bound, upper_bound)
}
