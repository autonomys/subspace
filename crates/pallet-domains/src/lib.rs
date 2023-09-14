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
use crate::staking::{do_nominate_operator, Operator, OperatorStatus};
use codec::{Decode, Encode};
use frame_support::ensure;
use frame_support::traits::fungible::{Inspect, InspectHold};
use frame_support::traits::{Get, Randomness as RandomnessT};
use frame_system::offchain::SubmitTransaction;
use frame_system::pallet_prelude::*;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_domains::bundle_producer_election::{is_below_threshold, BundleProducerElectionParams};
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{
    DomainBlockLimit, DomainId, DomainInstanceData, ExecutionReceipt, OpaqueBundle, OperatorId,
    OperatorPublicKey, ProofOfElection, RuntimeId, EMPTY_EXTRINSIC_ROOT,
};
use sp_runtime::traits::{BlakeTwo256, CheckedSub, Hash, One, Zero};
use sp_runtime::{RuntimeAppPublic, SaturatedConversion, Saturating};
use sp_std::boxed::Box;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;
use subspace_core_primitives::U256;

pub(crate) type BalanceOf<T> =
    <<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

pub(crate) type FungibleHoldId<T> =
    <<T as Config>::Currency as InspectHold<<T as frame_system::Config>::AccountId>>::Reason;

pub(crate) type NominatorId<T> = <T as frame_system::Config>::AccountId;

pub trait HoldIdentifier<T: Config> {
    fn staking_pending_deposit(operator_id: OperatorId) -> FungibleHoldId<T>;
    fn staking_staked(operator_id: OperatorId) -> FungibleHoldId<T>;
    fn staking_pending_unlock(operator_id: OperatorId) -> FungibleHoldId<T>;
    fn domain_instantiation_id(domain_id: DomainId) -> FungibleHoldId<T>;
}

pub type ExecutionReceiptOf<T> = ExecutionReceipt<
    BlockNumberFor<T>,
    <T as frame_system::Config>::Hash,
    <T as Config>::DomainNumber,
    <T as Config>::DomainHash,
    BalanceOf<T>,
>;

pub type OpaqueBundleOf<T> = OpaqueBundle<
    BlockNumberFor<T>,
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
        do_auto_stake_block_rewards, do_deregister_operator, do_nominate_operator,
        do_register_operator, do_reward_operators, do_slash_operators, do_switch_operator_domain,
        do_withdraw_stake, Error as StakingError, Nominator, Operator, OperatorConfig,
        StakingSummary, Withdraw,
    };
    use crate::staking_epoch::{
        do_finalize_domain_current_epoch, do_unlock_pending_withdrawals,
        Error as StakingEpochError, PendingNominatorUnlock, PendingOperatorSlashInfo,
    };
    use crate::weights::WeightInfo;
    use crate::{
        BalanceOf, ElectionVerificationParams, HoldIdentifier, NominatorId, OpaqueBundleOf,
    };
    use codec::FullCodec;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::fungible::{InspectHold, Mutate, MutateHold};
    use frame_support::traits::Randomness as RandomnessT;
    use frame_support::weights::Weight;
    use frame_support::{Identity, PalletError};
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_domains::fraud_proof::FraudProof;
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{
        BundleDigest, DomainId, EpochIndex, GenesisDomain, OperatorId, ReceiptHash, RuntimeId,
        RuntimeType,
    };
    use sp_runtime::traits::{
        AtLeast32BitUnsigned, BlockNumberProvider, Bounded, CheckEqual, CheckedAdd, Hash,
        MaybeDisplay, One, SimpleBitOps, Zero,
    };
    use sp_runtime::SaturatedConversion;
    use sp_std::boxed::Box;
    use sp_std::collections::btree_map::BTreeMap;
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

        /// The domain hashing algorithm.
        type DomainHashing: Hash<Output = Self::DomainHash> + TypeInfo;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        #[pallet::constant]
        type ConfirmationDepthK: Get<BlockNumberFor<Self>>;

        /// Delay before a domain runtime is upgraded.
        #[pallet::constant]
        type DomainRuntimeUpgradeDelay: Get<BlockNumberFor<Self>>;

        /// Currency type used by the domains for staking and other currency related stuff.
        type Currency: Mutate<Self::AccountId>
            + InspectHold<Self::AccountId>
            + MutateHold<Self::AccountId>;

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

        /// A variation of the Identifier used for holding the funds used for staking and domains.
        type HoldIdentifier: HoldIdentifier<Self>;

        /// The block tree pruning depth.
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
        #[pallet::constant]
        type InitialDomainTxRange: Get<u64>;

        /// Domain tx range is adjusted after every DomainTxRangeAdjustmentInterval blocks.
        #[pallet::constant]
        type DomainTxRangeAdjustmentInterval: Get<u64>;

        /// Minimum operator stake required to become operator of a domain.
        #[pallet::constant]
        type MinOperatorStake: Get<BalanceOf<Self>>;

        /// Minimum number of blocks after which any finalized withdrawals are released to nominators.
        #[pallet::constant]
        type StakeWithdrawalLockingPeriod: Get<Self::DomainNumber>;

        /// Domain epoch transition interval
        #[pallet::constant]
        type StakeEpochDuration: Get<Self::DomainNumber>;

        /// Treasury account.
        #[pallet::constant]
        type TreasuryAccount: Get<Self::AccountId>;

        /// The maximum number of pending staking operation that can perform upon epoch transition.
        #[pallet::constant]
        type MaxPendingStakingOperation: Get<u32>;

        #[pallet::constant]
        type SudoId: Get<Self::AccountId>;

        /// Randomness source.
        type Randomness: RandomnessT<Self::Hash, BlockNumberFor<Self>>;
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
        StorageMap<_, Identity, RuntimeId, RuntimeObject<BlockNumberFor<T>, T::Hash>, OptionQuery>;

    #[pallet::storage]
    pub(super) type ScheduledRuntimeUpgrades<T: Config> = StorageDoubleMap<
        _,
        Identity,
        BlockNumberFor<T>,
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
        StorageMap<_, Identity, DomainId, BTreeSet<OperatorId>, OptionQuery>;

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
        StorageMap<_, Identity, DomainId, BTreeSet<OperatorId>, OptionQuery>;

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
        T::DomainNumber,
        Vec<PendingNominatorUnlock<NominatorId<T>, BalanceOf<T>>>,
        OptionQuery,
    >;

    /// A list of operators that are either unregistering or one more of the nominators
    /// are withdrawing some staked funds.
    #[pallet::storage]
    pub(super) type PendingUnlocks<T: Config> =
        StorageMap<_, Identity, (DomainId, T::DomainNumber), BTreeSet<OperatorId>, OptionQuery>;

    /// A list operators who were slashed during the current epoch associated with the domain.
    /// When the epoch for a given domain is complete, operator total stake is moved to treasury and
    /// then deleted.
    #[pallet::storage]
    pub(super) type PendingSlashes<T: Config> = StorageMap<
        _,
        Identity,
        DomainId,
        BTreeMap<OperatorId, PendingOperatorSlashInfo<NominatorId<T>, BalanceOf<T>>>,
        OptionQuery,
    >;

    /// The pending staking operation count of the current epoch, it should not larger than
    /// `MaxPendingStakingOperation` and will be resetted to 0 upon epoch transition.
    #[pallet::storage]
    pub(super) type PendingStakingOperationCount<T: Config> =
        StorageMap<_, Identity, DomainId, u32, ValueQuery>;

    /// Stores the next domain id.
    #[pallet::storage]
    pub(super) type NextDomainId<T> = StorageValue<_, DomainId, ValueQuery>;

    /// The domain registry
    #[pallet::storage]
    pub(super) type DomainRegistry<T: Config> = StorageMap<
        _,
        Identity,
        DomainId,
        DomainObject<BlockNumberFor<T>, T::AccountId>,
        OptionQuery,
    >;

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
        DomainBlock<BlockNumberFor<T>, T::Hash, T::DomainNumber, T::DomainHash, BalanceOf<T>>,
        OptionQuery,
    >;

    // Mapping of the parent ER to all its immediate descendants ER
    // TODO: remove this mapping once https://github.com/subspace/subspace/issues/1731 is implemented
    // by then every parent ER should only have one immediate descendants ER
    #[pallet::storage]
    pub(super) type DomainBlockDescendants<T: Config> =
        StorageMap<_, Identity, ReceiptHash, BTreeSet<ReceiptHash>, ValueQuery>;

    /// The head receipt number of each domain
    #[pallet::storage]
    pub(super) type HeadReceiptNumber<T: Config> =
        StorageMap<_, Identity, DomainId, T::DomainNumber, ValueQuery>;

    /// State root mapped again each domain (block, hash)
    /// This acts as an index for other protocols like XDM to fetch state roots faster.
    #[pallet::storage]
    pub(super) type StateRoots<T: Config> = StorageMap<
        _,
        Identity,
        (DomainId, T::DomainNumber, T::DomainHash),
        T::DomainHash,
        OptionQuery,
    >;

    /// The consensus block hash used to verify ER, only store the consensus block hash for a domain
    /// if that consensus block contains bundle of the domain, the hash will be pruned when the ER
    /// that point to the consensus block is pruned.
    ///
    /// TODO: this storage is unbounded in some cases, see https://github.com/subspace/subspace/issues/1673
    /// for more details, this will be fixed once https://github.com/subspace/subspace/issues/1731 is implemented.
    #[pallet::storage]
    #[pallet::getter(fn consensus_hash)]
    pub type ConsensusBlockHash<T: Config> =
        StorageDoubleMap<_, Identity, DomainId, Identity, BlockNumberFor<T>, T::Hash, OptionQuery>;

    /// A set of `BundleDigest` from all bundles that successfully submitted to the consensus block,
    /// these bundles will be used to construct the domain block and `ExecutionInbox` is used to:
    ///
    /// 1. Ensure subsequent ERs of that domain block include all pre-validated extrinsic bundles
    /// 2. Index the `InboxedBundle` and pruned its value when the corresponding `ExecutionInbox` is pruned
    #[pallet::storage]
    pub type ExecutionInbox<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Identity, DomainId>,
            NMapKey<Identity, T::DomainNumber>,
            NMapKey<Identity, BlockNumberFor<T>>,
        ),
        Vec<BundleDigest>,
        ValueQuery,
    >;

    /// A mapping of `bundle_header_hash` -> `bundle_author` for all the successfully submitted bundles of
    /// the last `BlockTreePruningDepth` domain blocks. Used to verify the invalid bundle fraud proof and
    /// slash malicious operator who have submitted invalid bundle.
    #[pallet::storage]
    pub(super) type InboxedBundle<T: Config> =
        StorageMap<_, Identity, H256, OperatorId, OptionQuery>;

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

    /// A preferred Operator for a given Farmer, enabling automatic staking of block rewards.
    /// For the auto-staking to succeed, the Farmer must also be a Nominator of the preferred Operator.
    #[pallet::storage]
    pub(super) type PreferredOperator<T: Config> =
        StorageMap<_, Identity, NominatorId<T>, OperatorId, OptionQuery>;

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
        /// Bundle size exceed the max bundle size limit in the domain config
        BundleTooLarge,
        // Bundle with an invalid extrinsic root
        InvalidExtrinsicRoot,
        /// This bundle duplicated with an already submitted bundle
        DuplicatedBundle,
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
    pub enum FraudProofError {
        /// The targetted bad receipt not found which may already pruned by other
        /// fraud proof or the fraud proof is submitted to the wrong fork.
        BadReceiptNotFound,
        /// The genesis receipt is unchallengeable.
        ChallengingGenesisReceipt,
        /// The descendants of the fraudulent ER is not pruned
        DescendantsOfFraudulentERNotPruned,
    }

    impl<T> From<FraudProofError> for Error<T> {
        fn from(err: FraudProofError) -> Self {
            Error::FraudProof(err)
        }
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
        FraudProof(FraudProofError),
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
            scheduled_at: BlockNumberFor<T>,
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
        PreferredOperator {
            operator_id: OperatorId,
            nominator_id: NominatorId<T>,
        },
        OperatorRewarded {
            operator_id: OperatorId,
            reward: BalanceOf<T>,
        },
        DomainEpochCompleted {
            domain_id: DomainId,
            completed_epoch_index: EpochIndex,
        },
        FraudProofProcessed {
            domain_id: DomainId,
            new_head_receipt_number: Option<T::DomainNumber>,
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
        #[pallet::weight(T::WeightInfo::submit_bundle().saturating_add(T::WeightInfo::pending_staking_operation()))]
        pub fn submit_bundle(
            origin: OriginFor<T>,
            opaque_bundle: OpaqueBundleOf<T>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {opaque_bundle:?}");

            let domain_id = opaque_bundle.domain_id();
            let bundle_hash = opaque_bundle.hash();
            let bundle_header_hash = opaque_bundle.sealed_header.pre_hash();
            let extrinsics_root = opaque_bundle.extrinsics_root();
            let operator_id = opaque_bundle.operator_id();
            let receipt = opaque_bundle.into_receipt();

            match execution_receipt_type::<T>(domain_id, &receipt) {
                // The stale receipt should not be further processed, but we still track them for purposes
                // of measuring the bundle production rate.
                ReceiptType::Stale => {
                    return Ok(());
                }
                ReceiptType::Rejected(rejected_receipt_type) => {
                    return Err(Error::<T>::BlockTree(rejected_receipt_type.into()).into());
                }
                // Add the exeuctione receipt to the block tree
                ReceiptType::Accepted(accepted_receipt_type) => {
                    let maybe_confirmed_domain_block_info = process_execution_receipt::<T>(
                        domain_id,
                        operator_id,
                        receipt,
                        accepted_receipt_type,
                    )
                    .map_err(Error::<T>::from)?;

                    // If any domain block is confirmed, then we have a new head added
                    // so distribute the operator rewards and, if required, do epoch transition as well.
                    //
                    // NOTE: Skip the following staking related operations when benchmarking the
                    // `submit_bundle` call, these operations will be benchmarked separately.
                    #[cfg(not(feature = "runtime-benchmarks"))]
                    if let Some(confirmed_block_info) = maybe_confirmed_domain_block_info {
                        do_reward_operators::<T>(
                            domain_id,
                            confirmed_block_info.operator_ids.into_iter(),
                            confirmed_block_info.rewards,
                        )
                        .map_err(Error::<T>::from)?;

                        do_slash_operators::<T, _>(
                            confirmed_block_info.invalid_bundle_authors.into_iter(),
                        )
                        .map_err(Error::<T>::from)?;

                        if confirmed_block_info.domain_block_number % T::StakeEpochDuration::get()
                            == Zero::zero()
                        {
                            let completed_epoch_index = do_finalize_domain_current_epoch::<T>(
                                domain_id,
                                confirmed_block_info.domain_block_number,
                            )
                            .map_err(Error::<T>::from)?;

                            Self::deposit_event(Event::DomainEpochCompleted {
                                domain_id,
                                completed_epoch_index,
                            });
                        }

                        do_unlock_pending_withdrawals::<T>(
                            domain_id,
                            confirmed_block_info.domain_block_number,
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
                BundleDigest {
                    header_hash: bundle_header_hash,
                    extrinsics_root,
                },
            );

            InboxedBundle::<T>::insert(bundle_header_hash, operator_id);

            SuccessfulBundles::<T>::append(domain_id, bundle_hash);

            Self::deposit_event(Event::BundleStored {
                domain_id,
                bundle_hash,
                bundle_author: operator_id,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        // TODO: proper weight
        #[pallet::weight((Weight::from_all(10_000), Pays::No))]
        pub fn submit_fraud_proof(
            origin: OriginFor<T>,
            fraud_proof: Box<FraudProof<BlockNumberFor<T>, T::Hash>>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing fraud proof: {fraud_proof:?}");

            let domain_id = fraud_proof.domain_id();
            let mut receipt_to_remove = vec![fraud_proof.bad_receipt_hash()];
            let mut operator_to_slash = BTreeSet::new();
            let mut next_head_receipt_number = None;

            // Prune the bad ER and all of its descendants from the block tree. ER are pruning
            // with BFS order from lower height to higher height.
            while let Some(receipt_hash) = receipt_to_remove.pop() {
                let DomainBlock {
                    execution_receipt,
                    operator_ids,
                } = DomainBlocks::<T>::take(receipt_hash)
                    .ok_or::<Error<T>>(FraudProofError::BadReceiptNotFound.into())?;

                BlockTree::<T>::mutate_exists(
                    domain_id,
                    execution_receipt.domain_block_number,
                    |maybe_er_hashes| {
                        if let Some(er_hashes) = maybe_er_hashes {
                            // Remove ER hash from the set, remove the whole set if it is empty.
                            er_hashes.remove(&receipt_hash);
                            if er_hashes.is_empty() {
                                maybe_er_hashes.take();
                            }
                            // If all the ER at `domain_block_number` are pruned then any ER that derive from domain
                            // block with height > `domain_block_number` must also be pruned since their parent ER
                            // are pruned thus we can reset the new head receipt number to `domain_block_number - 1`.
                            if maybe_er_hashes.is_none() && next_head_receipt_number.is_none() {
                                next_head_receipt_number
                                    .replace(execution_receipt.domain_block_number - One::one());
                            } else if maybe_er_hashes.is_some()
                                && next_head_receipt_number.is_some()
                            {
                                // `next_head_receipt_number` is `Some` means all the ER at prior height are pruned
                                // thus the descendants must also be pruned
                                return Err::<(), Error<T>>(
                                    FraudProofError::DescendantsOfFraudulentERNotPruned.into(),
                                );
                            }
                        }
                        Ok(())
                    },
                )?;

                _ = StateRoots::<T>::take((
                    domain_id,
                    execution_receipt.domain_block_number,
                    execution_receipt.domain_block_hash,
                ));

                // Add all the immediate descendants of the pruned ER to the `receipt_to_remove` list
                DomainBlockDescendants::<T>::take(receipt_hash)
                    .into_iter()
                    .for_each(|descendant| receipt_to_remove.push(descendant));

                // NOTE: the operator id will be deduplicated since we are using `BTreeSet`
                operator_ids.into_iter().for_each(|id| {
                    operator_to_slash.insert(id);
                });
            }

            // Update the head receipt number
            if let Some(next_head_receipt_number) = next_head_receipt_number {
                HeadReceiptNumber::<T>::insert(domain_id, next_head_receipt_number);
            }

            // Slash operator who have submitted the pruned fraudulent ER
            do_slash_operators::<T, _>(operator_to_slash.into_iter()).map_err(Error::<T>::from)?;

            Self::deposit_event(Event::FraudProofProcessed {
                domain_id,
                new_head_receipt_number: next_head_receipt_number,
            });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::register_domain_runtime())]
        pub fn register_domain_runtime(
            origin: OriginFor<T>,
            runtime_name: Vec<u8>,
            runtime_type: RuntimeType,
            raw_genesis_storage: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let block_number = frame_system::Pallet::<T>::current_block_number();
            let runtime_id = do_register_runtime::<T>(
                runtime_name,
                runtime_type.clone(),
                raw_genesis_storage,
                block_number,
            )
            .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::DomainRuntimeCreated {
                runtime_id,
                runtime_type,
            });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::upgrade_domain_runtime())]
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
        #[pallet::weight(T::WeightInfo::register_operator())]
        pub fn register_operator(
            origin: OriginFor<T>,
            domain_id: DomainId,
            amount: BalanceOf<T>,
            config: OperatorConfig<BalanceOf<T>>,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            let (operator_id, current_epoch_index) =
                do_register_operator::<T>(owner, domain_id, amount, config)
                    .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::OperatorRegistered {
                operator_id,
                domain_id,
            });

            // if the domain's current epoch is 0,
            // then do an epoch transition so that operator can start producing bundles
            if current_epoch_index.is_zero() {
                do_finalize_domain_current_epoch::<T>(domain_id, One::one())
                    .map_err(Error::<T>::from)?;
            }

            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::nominate_operator())]
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
        #[pallet::weight(T::WeightInfo::instantiate_domain())]
        pub fn instantiate_domain(
            origin: OriginFor<T>,
            domain_config: DomainConfig,
            raw_genesis: Vec<u8>,
        ) -> DispatchResult {
            let (who, raw_genesis) = if raw_genesis.is_empty() {
                (ensure_signed(origin)?, None)
            } else {
                // TODO: remove once XDM is finished
                ensure_root(origin)?;
                (T::SudoId::get(), Some(raw_genesis))
            };

            let created_at = frame_system::Pallet::<T>::current_block_number();

            let domain_id = do_instantiate_domain::<T>(domain_config, who, created_at, raw_genesis)
                .map_err(Error::<T>::from)?;

            Self::deposit_event(Event::DomainInstantiated { domain_id });

            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::switch_domain())]
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
        #[pallet::weight(T::WeightInfo::deregister_operator())]
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
        #[pallet::weight(T::WeightInfo::withdraw_stake())]
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

        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::auto_stake_block_rewards())]
        pub fn auto_stake_block_rewards(
            origin: OriginFor<T>,
            operator_id: OperatorId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            do_auto_stake_block_rewards::<T>(who.clone(), operator_id).map_err(Error::<T>::from)?;

            Self::deposit_event(Event::PreferredOperator {
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
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
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
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
            if block_number.is_one() {
                if let Some(genesis_domain) = PendingGenesisDomain::<T>::take() {
                    // Register the genesis domain runtime
                    let runtime_id = register_runtime_at_genesis::<T>(
                        genesis_domain.runtime_name,
                        genesis_domain.runtime_type,
                        genesis_domain.runtime_version,
                        genesis_domain.raw_genesis_storage,
                        One::one(),
                )
                .expect("Genesis runtime registration must always succeed");

                    // Instantiate the genesis domain
                    let domain_config = DomainConfig {
                        domain_name: genesis_domain.domain_name,
                        runtime_id,
                        max_block_size: genesis_domain.max_block_size,
                        max_block_weight: genesis_domain.max_block_weight,
                        bundle_slot_probability: genesis_domain.bundle_slot_probability,
                        target_bundles_per_block: genesis_domain.target_bundles_per_block,
                    };
                    let domain_owner = genesis_domain.owner_account_id;
                let domain_id =
                    do_instantiate_domain::<T>(domain_config, domain_owner.clone(), One::one(), None)
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

                    do_finalize_domain_current_epoch::<T>(domain_id, One::one())
                        .expect("Genesis epoch must succeed");
                }
            }

            do_upgrade_runtimes::<T>(block_number);

            // Store the hash of the parent consensus block for domain that have bundles submitted
            // in that consensus block
            let parent_number = block_number - One::one();
            let parent_hash = frame_system::Pallet::<T>::block_hash(parent_number);
            for (domain_id, _) in SuccessfulBundles::<T>::drain() {
                ConsensusBlockHash::<T>::insert(domain_id, parent_number, parent_hash);
            }

            Weight::zero()
        }

        fn on_finalize(_: BlockNumberFor<T>) {
            let _ = LastEpochStakingDistribution::<T>::clear(u32::MAX, None);
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
                Call::submit_bundle { opaque_bundle } => Self::validate_bundle(opaque_bundle)
                    .map_err(|_| InvalidTransaction::Call.into()),
                Call::submit_fraud_proof { fraud_proof } => Self::validate_fraud_proof(fraud_proof)
                    .map_err(|_| InvalidTransaction::Call.into()),
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
                    if let Err(e) = Self::validate_fraud_proof(fraud_proof) {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad fraud proof {:?}, error: {e:?}", fraud_proof.domain_id(),
                        );
                        return InvalidTransactionCode::FraudProof.into();
                    }

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

    pub fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>> {
        RuntimeRegistry::<T>::get(Self::runtime_id(domain_id)?)
            .map(|runtime_object| runtime_object.code)
    }

    pub fn domain_best_number(domain_id: DomainId) -> Option<T::DomainNumber> {
        Some(HeadDomainNumber::<T>::get(domain_id))
    }

    pub fn domain_state_root(
        domain_id: DomainId,
        domain_block_number: T::DomainNumber,
        domain_block_hash: T::DomainHash,
    ) -> Option<T::DomainHash> {
        StateRoots::<T>::get((domain_id, domain_block_number, domain_block_hash))
    }

    pub fn runtime_id(domain_id: DomainId) -> Option<RuntimeId> {
        DomainRegistry::<T>::get(domain_id)
            .map(|domain_object| domain_object.domain_config.runtime_id)
    }

    pub fn domain_instance_data(
        domain_id: DomainId,
    ) -> Option<(DomainInstanceData, BlockNumberFor<T>)> {
        let domain_obj = DomainRegistry::<T>::get(domain_id)?;
        let runtime_object = RuntimeRegistry::<T>::get(domain_obj.domain_config.runtime_id)?;
        let runtime_type = runtime_object.runtime_type.clone();
        let raw_genesis = runtime_object.into_complete_raw_genesis(domain_id);
        Some((
            DomainInstanceData {
                runtime_type,
                raw_genesis,
            },
            domain_obj.created_at,
        ))
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

    fn check_bundle_duplication(opaque_bundle: &OpaqueBundleOf<T>) -> Result<(), BundleError> {
        // NOTE: it is important to use the hash that not incliude the signature, otherwise
        // the malicious operator may update its `signing_key` (this may support in the future)
        // and sign an existing bundle thus creating a duplicated bundle and pass the check.
        let bundle_header_hash = opaque_bundle.sealed_header.pre_hash();
        ensure!(
            !InboxedBundle::<T>::contains_key(bundle_header_hash),
            BundleError::DuplicatedBundle
        );
        Ok(())
    }

    fn check_bundle_size(
        opaque_bundle: &OpaqueBundleOf<T>,
        max_size: u32,
    ) -> Result<(), BundleError> {
        let bundle_size = opaque_bundle
            .extrinsics
            .iter()
            .fold(0, |acc, xt| acc + xt.encoded_size() as u32);
        ensure!(max_size >= bundle_size, BundleError::BundleTooLarge);
        Ok(())
    }

    fn check_extrinsics_root(opaque_bundle: &OpaqueBundleOf<T>) -> Result<(), BundleError> {
        let expected_extrinsics_root = BlakeTwo256::ordered_trie_root(
            opaque_bundle
                .extrinsics
                .iter()
                .map(|xt| xt.encode())
                .collect(),
            sp_core::storage::StateVersion::V1,
        );
        ensure!(
            expected_extrinsics_root == opaque_bundle.extrinsics_root(),
            BundleError::InvalidExtrinsicRoot
        );
        Ok(())
    }

    fn check_proof_of_election(
        domain_id: DomainId,
        operator_id: OperatorId,
        operator: Operator<BalanceOf<T>, T::Share>,
        bundle_slot_probability: (u64, u64),
        proof_of_election: &ProofOfElection,
    ) -> Result<(), BundleError> {
        proof_of_election
            .verify_vrf_signature(&operator.signing_key)
            .map_err(|_| BundleError::BadVrfSignature)?;

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

    fn validate_bundle(opaque_bundle: &OpaqueBundleOf<T>) -> Result<(), BundleError> {
        let domain_id = opaque_bundle.domain_id();
        let operator_id = opaque_bundle.operator_id();
        let sealed_header = &opaque_bundle.sealed_header;

        let operator = Operators::<T>::get(operator_id).ok_or(BundleError::InvalidOperatorId)?;

        ensure!(
            operator.status != OperatorStatus::Slashed,
            BundleError::BadOperator
        );

        if !operator
            .signing_key
            .verify(&sealed_header.pre_hash(), &sealed_header.signature)
        {
            return Err(BundleError::BadBundleSignature);
        }

        Self::check_bundle_duplication(opaque_bundle)?;

        let domain_config = DomainRegistry::<T>::get(domain_id)
            .ok_or(BundleError::InvalidDomainId)?
            .domain_config;

        // TODO: check bundle weight with `domain_config.max_block_weight`

        Self::check_bundle_size(opaque_bundle, domain_config.max_block_size)?;

        Self::check_extrinsics_root(opaque_bundle)?;

        let proof_of_election = &sealed_header.header.proof_of_election;
        Self::check_proof_of_election(
            domain_id,
            operator_id,
            operator,
            domain_config.bundle_slot_probability,
            proof_of_election,
        )?;

        let receipt = &sealed_header.header.receipt;
        verify_execution_receipt::<T>(domain_id, receipt).map_err(BundleError::Receipt)?;

        Ok(())
    }

    fn validate_fraud_proof(
        fraud_proof: &FraudProof<BlockNumberFor<T>, T::Hash>,
    ) -> Result<(), FraudProofError> {
        let bad_receipt = DomainBlocks::<T>::get(fraud_proof.bad_receipt_hash())
            .ok_or(FraudProofError::BadReceiptNotFound)?
            .execution_receipt;

        ensure!(
            !bad_receipt.domain_block_number.is_zero(),
            FraudProofError::ChallengingGenesisReceipt
        );

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
    #[allow(dead_code)]
    // TODO: use once we support tx-range dynamic adjustment properly
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
    #[allow(dead_code)]
    // TODO: use once we support tx-range dynamic adjustment properly
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

    /// Increase the nomination stake by `reward` to the preferred operator of `who`.
    /// Preference is removed if the nomination fails.
    pub fn on_block_reward(who: NominatorId<T>, reward: BalanceOf<T>) {
        PreferredOperator::<T>::mutate_exists(who.clone(), |maybe_preferred_operator_id| {
            if let Some(operator_id) = maybe_preferred_operator_id {
                if let Err(err) = do_nominate_operator::<T>(*operator_id, who, reward) {
                    log::trace!(
                        target: "runtime::domains",
                        "Failed to stake the reward amount to preferred operator: {err:?}. Removing preference."
                    );
                    maybe_preferred_operator_id.take();
                }
            }
        });
    }

    /// Returns if there are any ERs in the challenge period that have non empty extrinsics.
    /// Note that Genesis ER is also considered special and hence non empty
    pub fn non_empty_er_exists(domain_id: DomainId) -> bool {
        if BlockTree::<T>::contains_key(domain_id, T::DomainNumber::zero()) {
            return true;
        }

        let head_number = HeadDomainNumber::<T>::get(domain_id);
        let mut to_check = head_number
            .checked_sub(&T::BlockTreePruningDepth::get())
            .unwrap_or(Zero::zero());

        while to_check <= head_number {
            if !ExecutionInbox::<T>::iter_prefix_values((domain_id, to_check)).all(|digests| {
                digests
                    .iter()
                    .all(|digest| digest.extrinsics_root == EMPTY_EXTRINSIC_ROOT)
            }) {
                return true;
            }

            to_check = to_check.saturating_add(One::one())
        }

        false
    }

    pub fn extrinsics_shuffling_seed() -> T::Hash {
        let seed: &[u8] = b"extrinsics-shuffling-seed";
        let (randomness, _) = T::Randomness::random(seed);
        randomness
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
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof<BlockNumberFor<T>, T::Hash>) {
        let call = Call::submit_fraud_proof {
            fraud_proof: Box::new(fraud_proof),
        };

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
        .checked_div(&U256::from(expected_bundle_count))
    else {
        return cur_tx_range;
    };

    let upper_bound = cur_tx_range.saturating_mul(&U256::from(4_u64));
    let Some(lower_bound) = cur_tx_range.checked_div(&U256::from(4_u64)) else {
        return cur_tx_range;
    };
    new_tx_range.clamp(lower_bound, upper_bound)
}
