// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(const_option, variant_count)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use codec::{Compact, CompactLen, Decode, Encode, MaxEncodedLen};
use core::num::NonZeroU64;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use domain_runtime_primitives::{
    AccountIdConverter, BlockNumber as DomainNumber, Hash as DomainHash,
};
use frame_support::genesis_builder_helper::{build_config, create_default_config};
use frame_support::inherent::ProvideInherent;
use frame_support::traits::{
    ConstU128, ConstU16, ConstU32, ConstU64, ConstU8, Currency, ExistenceRequirement, Get,
    Imbalance, VariantCount, WithdrawReasons,
};
use frame_support::weights::constants::{ParityDbWeight, WEIGHT_REF_TIME_PER_SECOND};
use frame_support::weights::{ConstantMultiplier, IdentityFee, Weight};
use frame_support::{construct_runtime, parameter_types, PalletId};
use frame_system::limits::{BlockLength, BlockWeights};
use frame_system::EnsureNever;
use pallet_balances::NegativeImbalance;
pub use pallet_rewards::RewardPoint;
pub use pallet_subspace::{AllowAuthoringBy, EnableRewardsAt};
use pallet_transporter::EndpointHandler;
use scale_info::TypeInfo;
use sp_api::impl_runtime_apis;
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::{
    ChainConstants, EquivocationProof, FarmerPublicKey, PotParameters, SignedVote, SolutionRanges,
    Vote,
};
use sp_core::crypto::{ByteArray, KeyTypeId};
use sp_core::{OpaqueMetadata, H256};
use sp_domains::bundle_producer_election::BundleProducerElectionParams;
use sp_domains::{
    DomainAllowlistUpdates, DomainId, DomainInstanceData, DomainsHoldIdentifier,
    ExecutionReceiptFor, MessengerHoldIdentifier, OpaqueBundle, OpaqueBundles, OperatorId,
    OperatorPublicKey, StakingHoldIdentifier,
};
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockMessagesWithStorageKey, ChainId, ChannelId, CrossDomainMessage, MessageId, MessageKey,
};
use sp_messenger_host_functions::{get_storage_key, StorageKeyRequest};
use sp_mmr_primitives::EncodableOpaqueLeaf;
use sp_runtime::traits::{
    AccountIdConversion, AccountIdLookup, BlakeTwo256, Block as BlockT, ConstBool, DispatchInfoOf,
    Keccak256, NumberFor, PostDispatchInfoOf, Zero,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
};
use sp_runtime::{
    create_runtime_str, generic, AccountId32, ApplyExtrinsicResult, ExtrinsicInclusionMode, Perbill,
};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::iter::Peekable;
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_version::RuntimeVersion;
use static_assertions::const_assert;
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping};
use subspace_core_primitives::{
    HistorySize, Piece, Randomness, SegmentCommitment, SegmentHeader, SegmentIndex, SlotNumber,
    SolutionRange, U256,
};
use subspace_runtime_primitives::{
    AccountId, Balance, BlockNumber, Hash, Moment, Nonce, Signature, MIN_REPLICATION_FACTOR,
};

sp_runtime::impl_opaque_keys! {
    pub struct SessionKeys {
    }
}

// The domain storage fee multiplier used to charge a higher storage fee to the domain
// transaction to even out the duplicated/illegal domain transaction storage cost, which
// can not be eliminated currently.
const DOMAIN_STORAGE_FEE_MULTIPLIER: Balance = 3;

// Smaller value for testing purposes
const MAX_PIECES_IN_SECTOR: u16 = 32;

// To learn more about runtime versioning and what each of the following value means:
//   https://substrate.dev/docs/en/knowledgebase/runtime/upgrades#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("subspace"),
    impl_name: create_runtime_str!("subspace"),
    authoring_version: 1,
    // The version of the runtime specification. A full node will not attempt to use its native
    //   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
    //   `spec_version`, and `authoring_version` are the same between Wasm and native.
    // This value is set to 100 to notify Polkadot-JS App (https://polkadot.js.org/apps) to use
    //   the compatible custom types.
    spec_version: 100,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
    extrinsic_state_version: 0,
};

/// The smallest unit of the token is called Shannon.
pub const SHANNON: Balance = 1;
/// Subspace Credits have 18 decimal places.
pub const DECIMAL_PLACES: u8 = 18;
/// One Subspace Credit.
pub const SSC: Balance = (10 * SHANNON).pow(DECIMAL_PLACES as u32);

// TODO: Many of below constants should probably be updatable but currently they are not

/// Since Subspace is probabilistic this is the average expected block time that
/// we are targeting. Blocks will be produced at a minimum duration defined
/// by `SLOT_DURATION`, but some slots will not be allocated to any
/// farmer and hence no block will be produced. We expect to have this
/// block time on average following the defined slot duration and the value
/// of `c` configured for Subspace (where `1 - c` represents the probability of
/// a slot being empty).
/// This value is only used indirectly to define the unit constants below
/// that are expressed in blocks. The rest of the code should use
/// `SLOT_DURATION` instead (like the Timestamp pallet for calculating the
/// minimum period).
///
/// Based on:
/// <https://research.web3.foundation/en/latest/polkadot/block-production/Babe.html#-6.-practical-results>
pub const MILLISECS_PER_BLOCK: u64 = 2000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
pub const SLOT_DURATION: u64 = 2000;

/// 1 in 6 slots (on average, not counting collisions) will have a block.
/// Must match ratio between block and slot duration in constants above.
const SLOT_PROBABILITY: (u64, u64) = (1, 1);
/// Number of slots between slot arrival and when corresponding block can be produced.
const BLOCK_AUTHORING_DELAY: SlotNumber = 2;

/// Interval, in blocks, between blockchain entropy injection into proof of time chain.
const POT_ENTROPY_INJECTION_INTERVAL: BlockNumber = 5;

/// Interval, in entropy injection intervals, where to take entropy for injection from.
const POT_ENTROPY_INJECTION_LOOKBACK_DEPTH: u8 = 2;

/// Delay after block, in slots, when entropy injection takes effect.
const POT_ENTROPY_INJECTION_DELAY: SlotNumber = 4;

// Entropy injection interval must be bigger than injection delay or else we may end up in a
// situation where we'll need to do more than one injection at the same slot
const_assert!(POT_ENTROPY_INJECTION_INTERVAL as u64 > POT_ENTROPY_INJECTION_DELAY);
// Entropy injection delay must be bigger than block authoring delay or else we may include
// invalid future proofs in parent block, +1 ensures we do not have unnecessary reorgs that will
// inevitably happen otherwise
const_assert!(POT_ENTROPY_INJECTION_DELAY > BLOCK_AUTHORING_DELAY + 1);

/// Era duration in blocks.
const ERA_DURATION_IN_BLOCKS: BlockNumber = 2016;

const EQUIVOCATION_REPORT_LONGEVITY: BlockNumber = 256;

/// Any solution range is valid in the test environment.
const INITIAL_SOLUTION_RANGE: SolutionRange = SolutionRange::MAX;

/// A ratio of `Normal` dispatch class within block, for `BlockWeight` and `BlockLength`.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// The block weight for 2 seconds of compute
const BLOCK_WEIGHT_FOR_2_SEC: Weight =
    Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2), u64::MAX);

/// Maximum block length for non-`Normal` extrinsic is 5 MiB.
const MAX_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;

const MAX_OBJECT_MAPPING_RECURSION_DEPTH: u16 = 5;

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 250;
    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub SubspaceBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(BLOCK_WEIGHT_FOR_2_SEC, NORMAL_DISPATCH_RATIO);
    /// We allow for 3.75 MiB for `Normal` extrinsic with 5 MiB maximum block length.
    pub SubspaceBlockLength: BlockLength = BlockLength::max_with_normal_ratio(MAX_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
}

pub type SS58Prefix = ConstU16<2254>;

// Configure FRAME pallets to include in runtime.

impl frame_system::Config for Runtime {
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = frame_support::traits::Everything;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = SubspaceBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = SubspaceBlockLength;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
    /// The aggregated `RuntimeTask` type.
    type RuntimeTask = RuntimeTask;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = AccountIdLookup<AccountId, ()>;
    /// The type for storing how many extrinsics an account has signed.
    type Nonce = Nonce;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// The hashing algorithm used.
    type Hashing = BlakeTwo256;
    /// The block type.
    type Block = Block;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    /// The ubiquitous origin type.
    type RuntimeOrigin = RuntimeOrigin;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = ParityDbWeight;
    /// Version of the runtime.
    type Version = Version;
    /// Converts a module to the index of the module in `construct_runtime!`.
    ///
    /// This type is being generated by `construct_runtime!`.
    type PalletInfo = PalletInfo;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    /// This is used as an identifier of the chain.
    type SS58Prefix = SS58Prefix;
    /// The set code logic, just the default since we're not a parachain.
    type OnSetCode = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const BlockAuthoringDelay: SlotNumber = BLOCK_AUTHORING_DELAY;
    pub const PotEntropyInjectionInterval: BlockNumber = POT_ENTROPY_INJECTION_INTERVAL;
    pub const PotEntropyInjectionLookbackDepth: u8 = POT_ENTROPY_INJECTION_LOOKBACK_DEPTH;
    pub const PotEntropyInjectionDelay: SlotNumber = POT_ENTROPY_INJECTION_DELAY;
    pub const EraDuration: BlockNumber = ERA_DURATION_IN_BLOCKS;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ShouldAdjustSolutionRange: bool = false;
    pub const ExpectedVotesPerBlock: u32 = 9;
    pub const ConfirmationDepthK: u32 = 100;
    pub const RecentSegments: HistorySize = HistorySize::new(NonZeroU64::new(5).unwrap());
    pub const RecentHistoryFraction: (HistorySize, HistorySize) = (
        HistorySize::new(NonZeroU64::new(1).unwrap()),
        HistorySize::new(NonZeroU64::new(10).unwrap()),
    );
    pub const MinSectorLifetime: HistorySize = HistorySize::new(NonZeroU64::new(4).unwrap());
    pub const BlockSlotCount: u32 = 6;
}

impl pallet_subspace::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type BlockAuthoringDelay = BlockAuthoringDelay;
    type PotEntropyInjectionInterval = PotEntropyInjectionInterval;
    type PotEntropyInjectionLookbackDepth = PotEntropyInjectionLookbackDepth;
    type PotEntropyInjectionDelay = PotEntropyInjectionDelay;
    type EraDuration = EraDuration;
    type InitialSolutionRange = ConstU64<INITIAL_SOLUTION_RANGE>;
    type SlotProbability = SlotProbability;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecentSegments = RecentSegments;
    type RecentHistoryFraction = RecentHistoryFraction;
    type MinSectorLifetime = MinSectorLifetime;
    type ExpectedVotesPerBlock = ExpectedVotesPerBlock;
    type MaxPiecesInSector = ConstU16<{ MAX_PIECES_IN_SECTOR }>;
    type ShouldAdjustSolutionRange = ShouldAdjustSolutionRange;
    type EraChangeTrigger = pallet_subspace::NormalEraChange;
    type BlockSlotCount = BlockSlotCount;

    type HandleEquivocation = pallet_subspace::equivocation::EquivocationHandler<
        OffencesSubspace,
        ConstU64<{ EQUIVOCATION_REPORT_LONGEVITY as u64 }>,
    >;

    type WeightInfo = ();
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum HoldIdentifier {
    Domains(DomainsHoldIdentifier),
    Messenger(MessengerHoldIdentifier),
}

impl pallet_domains::HoldIdentifier<Runtime> for HoldIdentifier {
    fn staking_staked(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::Staked(operator_id),
        ))
    }

    fn domain_instantiation_id(domain_id: DomainId) -> Self {
        Self::Domains(DomainsHoldIdentifier::DomainInstantiation(domain_id))
    }

    fn storage_fund_withdrawal(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::StorageFund(operator_id))
    }
}

impl pallet_messenger::HoldIdentifier<Runtime> for HoldIdentifier {
    fn messenger_channel(dst_chain_id: ChainId, channel_id: ChannelId) -> Self {
        Self::Messenger(MessengerHoldIdentifier::Channel((dst_chain_id, channel_id)))
    }
}

impl VariantCount for HoldIdentifier {
    // TODO: HACK this is not the actual variant count but it is required see
    // https://github.com/subspace/subspace/issues/2674 for more details. It
    // will be resolved as https://github.com/paritytech/polkadot-sdk/issues/4033.
    const VARIANT_COUNT: u32 = 10;
}

impl pallet_balances::Config for Runtime {
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    // TODO: Correct value
    type ExistentialDeposit = ConstU128<{ 500 * SHANNON }>;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = HoldIdentifier;
}

pub struct CreditSupply;

impl Get<Balance> for CreditSupply {
    fn get() -> Balance {
        Balances::total_issuance()
    }
}

pub struct TotalSpacePledged;

impl Get<u128> for TotalSpacePledged {
    fn get() -> u128 {
        // Operations reordered to avoid data loss, but essentially are:
        // u64::MAX * SlotProbability / (solution_range / PIECE_SIZE)
        u128::from(u64::MAX)
            .saturating_mul(Piece::SIZE as u128)
            .saturating_mul(u128::from(SlotProbability::get().0))
            / u128::from(Subspace::solution_ranges().current)
            / u128::from(SlotProbability::get().1)
    }
}

pub struct BlockchainHistorySize;

impl Get<u128> for BlockchainHistorySize {
    fn get() -> u128 {
        u128::from(Subspace::archived_history_size())
    }
}

impl pallet_transaction_fees::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MinReplicationFactor = ConstU16<MIN_REPLICATION_FACTOR>;
    type CreditSupply = CreditSupply;
    type TotalSpacePledged = TotalSpacePledged;
    type BlockchainHistorySize = BlockchainHistorySize;
    type Currency = Balances;
    type FindBlockRewardAddress = Subspace;
    type DynamicCostOfStorage = ConstBool<false>;
    type WeightInfo = ();
}

pub struct TransactionByteFee;

impl Get<Balance> for TransactionByteFee {
    fn get() -> Balance {
        TransactionFees::transaction_byte_fee()
    }
}

pub struct LiquidityInfo {
    storage_fee: Balance,
    imbalance: NegativeImbalance<Runtime>,
}

/// Implementation of [`pallet_transaction_payment::OnChargeTransaction`] that charges transaction
/// fees and distributes storage/compute fees and tip separately.
pub struct OnChargeTransaction;

impl pallet_transaction_payment::OnChargeTransaction<Runtime> for OnChargeTransaction {
    type LiquidityInfo = Option<LiquidityInfo>;
    type Balance = Balance;

    fn withdraw_fee(
        who: &AccountId,
        call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        fee: Self::Balance,
        tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
        if fee.is_zero() {
            return Ok(None);
        }

        let withdraw_reason = if tip.is_zero() {
            WithdrawReasons::TRANSACTION_PAYMENT
        } else {
            WithdrawReasons::TRANSACTION_PAYMENT | WithdrawReasons::TIP
        };

        let withdraw_result = <Balances as Currency<AccountId>>::withdraw(
            who,
            fee,
            withdraw_reason,
            ExistenceRequirement::KeepAlive,
        );
        let imbalance = withdraw_result.map_err(|_error| InvalidTransaction::Payment)?;

        // Separate storage fee while we have access to the call data structure to calculate it.
        let storage_fee = TransactionByteFee::get()
            * Balance::try_from(call.encoded_size())
                .expect("Size of the call never exceeds balance units; qed");

        Ok(Some(LiquidityInfo {
            storage_fee,
            imbalance,
        }))
    }

    fn correct_and_deposit_fee(
        who: &AccountId,
        _dispatch_info: &DispatchInfoOf<RuntimeCall>,
        _post_info: &PostDispatchInfoOf<RuntimeCall>,
        corrected_fee: Self::Balance,
        tip: Self::Balance,
        liquidity_info: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
        if let Some(LiquidityInfo {
            storage_fee,
            imbalance,
        }) = liquidity_info
        {
            // Calculate how much refund we should return
            let refund_amount = imbalance.peek().saturating_sub(corrected_fee);
            // Refund to the the account that paid the fees. If this fails, the account might have
            // dropped below the existential balance. In that case we don't refund anything.
            let refund_imbalance = Balances::deposit_into_existing(who, refund_amount)
                .unwrap_or_else(|_| <Balances as Currency<AccountId>>::PositiveImbalance::zero());
            // Merge the imbalance caused by paying the fees and refunding parts of it again.
            let adjusted_paid = imbalance
                .offset(refund_imbalance)
                .same()
                .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

            // Split the tip from the total fee that ended up being paid.
            let (tip, fee) = adjusted_paid.split(tip);
            // Split paid storage and compute fees so that they can be distributed separately.
            let (paid_storage_fee, paid_compute_fee) = fee.split(storage_fee);

            TransactionFees::note_transaction_fees(
                paid_storage_fee.peek(),
                paid_compute_fee.peek(),
                tip.peek(),
            );
        }
        Ok(())
    }
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = OnChargeTransaction;
    type OperationalFeeMultiplier = ConstU8<5>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = ();
}

impl pallet_utility::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub SelfChainId: ChainId = ChainId::Consensus;
}

pub struct MmrProofVerifier;

impl sp_subspace_mmr::MmrProofVerifier<mmr::Hash, NumberFor<Block>, Hash> for MmrProofVerifier {
    fn verify_proof_and_extract_consensus_state_root(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, Hash, mmr::Hash>,
    ) -> Option<Hash> {
        let ConsensusChainMmrLeafProof {
            consensus_block_number,
            opaque_mmr_leaf,
            proof,
            ..
        } = mmr_leaf_proof;

        let mmr_root = SubspaceMmr::mmr_root_hash(consensus_block_number)?;

        pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(
            mmr_root,
            vec![mmr::DataOrHash::Data(
                EncodableOpaqueLeaf(opaque_mmr_leaf.0.clone()).into_opaque_leaf(),
            )],
            proof,
        )
        .ok()?;

        let leaf: mmr::Leaf = opaque_mmr_leaf.into_opaque_leaf().try_decode()?;

        Some(leaf.state_root())
    }
}

pub struct StorageKeys;

impl sp_messenger::StorageKeys for StorageKeys {
    fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Option<Vec<u8>> {
        Some(Domains::confirmed_domain_block_storage_key(domain_id))
    }

    fn outbox_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        get_storage_key(StorageKeyRequest::OutboxStorageKey {
            chain_id,
            message_key,
        })
    }

    fn inbox_responses_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        get_storage_key(StorageKeyRequest::InboxResponseStorageKey {
            chain_id,
            message_key,
        })
    }
}

parameter_types! {
    pub const ChannelReserveFee: Balance = SSC;
}

impl pallet_messenger::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;

    fn get_endpoint_handler(endpoint: &Endpoint) -> Option<Box<dyn EndpointHandlerT<MessageId>>> {
        if endpoint == &Endpoint::Id(TransporterEndpointId::get()) {
            Some(Box::new(EndpointHandler(PhantomData::<Runtime>)))
        } else {
            None
        }
    }

    type Currency = Balances;
    type WeightInfo = pallet_messenger::weights::SubstrateWeight<Runtime>;
    type WeightToFee = IdentityFee<domain_runtime_primitives::Balance>;
    type OnXDMRewards = ();
    type MmrHash = mmr::Hash;
    type MmrProofVerifier = MmrProofVerifier;
    type StorageKeys = StorageKeys;
    type DomainOwner = Domains;
    type HoldIdentifier = HoldIdentifier;
    type ChannelReserveFee = ChannelReserveFee;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = RuntimeCall;
}

parameter_types! {
    pub const TransporterEndpointId: EndpointId = 1;
}

impl pallet_transporter::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = TransporterEndpointId;
    type Currency = Balances;
    type Sender = Messenger;
    type AccountIdConverter = AccountIdConverter;
    type WeightInfo = pallet_transporter::weights::SubstrateWeight<Runtime>;
}

impl pallet_offences_subspace::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnOffenceHandler = Subspace;
}

parameter_types! {
    pub const MaximumReceiptDrift: BlockNumber = 2;
    pub const InitialDomainTxRange: u64 = 3;
    pub const DomainTxRangeAdjustmentInterval: u64 = 100;
    pub const DomainRuntimeUpgradeDelay: BlockNumber = 10;
    pub const MinOperatorStake: Balance = 100 * SSC;
    pub const MinNominatorStake: Balance = SSC;
    /// Use the consensus chain's `Normal` extrinsics block size limit as the domain block size limit
    pub MaxDomainBlockSize: u32 = NORMAL_DISPATCH_RATIO * MAX_BLOCK_LENGTH;
    /// Use the consensus chain's `Normal` extrinsics block weight limit as the domain block weight limit
    pub MaxDomainBlockWeight: Weight = NORMAL_DISPATCH_RATIO * BLOCK_WEIGHT_FOR_2_SEC;
    pub const MaxBundlesPerBlock: u32 = 10;
    pub const DomainInstantiationDeposit: Balance = 100 * SSC;
    pub const MaxDomainNameLength: u32 = 32;
    pub const BlockTreePruningDepth: u32 = 16;
    pub const StakeWithdrawalLockingPeriod: BlockNumber = 20;
    pub const StakeEpochDuration: DomainNumber = 5;
    pub TreasuryAccount: AccountId = PalletId(*b"treasury").into_account_truncating();
    pub const MaxPendingStakingOperation: u32 = 512;
    pub const MaxNominators: u32 = 100;
    pub const DomainsPalletId: PalletId = PalletId(*b"domains_");
    pub const MaxInitialDomainAccounts: u32 = 20;
    pub const MinInitialDomainAccountBalance: Balance = SSC;
    pub const BundleLongevity: u32 = 5;
}

// `BlockSlotCount` must at least keep the slot for the current and the parent block, it also need to
// keep enough block slot for bundle validation
const_assert!(BlockSlotCount::get() >= 2 && BlockSlotCount::get() > BundleLongevity::get());

// `BlockHashCount` must greater than `BlockSlotCount` because we need to use the block number found
// with `BlockSlotCount` to get the block hash.
const_assert!(BlockHashCount::get() > BlockSlotCount::get());

// Minimum operator stake must be >= minimum nominator stake since operator is also a nominator.
const_assert!(MinOperatorStake::get() >= MinNominatorStake::get());

pub struct BlockSlot;

impl pallet_domains::BlockSlot<Runtime> for BlockSlot {
    fn future_slot(block_number: BlockNumber) -> Option<Slot> {
        let block_slots = Subspace::block_slots();
        block_slots
            .get(&block_number)
            .map(|slot| *slot + Slot::from(BlockAuthoringDelay::get()))
    }

    fn slot_produced_after(to_check: Slot) -> Option<BlockNumber> {
        let block_slots = Subspace::block_slots();
        for (block_number, slot) in block_slots.into_iter().rev() {
            if to_check > slot {
                return Some(block_number);
            }
        }
        None
    }
}

impl pallet_domains::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type DomainHash = DomainHash;
    type DomainHeader = DomainHeader;
    type ConfirmationDepthK = ConfirmationDepthK;
    type DomainRuntimeUpgradeDelay = DomainRuntimeUpgradeDelay;
    type Currency = Balances;
    type HoldIdentifier = HoldIdentifier;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Runtime>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type MinOperatorStake = MinOperatorStake;
    type MaxDomainBlockSize = MaxDomainBlockSize;
    type MaxDomainBlockWeight = MaxDomainBlockWeight;
    type MaxBundlesPerBlock = MaxBundlesPerBlock;
    type DomainInstantiationDeposit = DomainInstantiationDeposit;
    type MaxDomainNameLength = MaxDomainNameLength;
    type Share = Balance;
    type BlockTreePruningDepth = BlockTreePruningDepth;
    type ConsensusSlotProbability = SlotProbability;
    type StakeWithdrawalLockingPeriod = StakeWithdrawalLockingPeriod;
    type StakeEpochDuration = StakeEpochDuration;
    type TreasuryAccount = TreasuryAccount;
    type MaxPendingStakingOperation = MaxPendingStakingOperation;
    type MaxNominators = MaxNominators;
    type Randomness = Subspace;
    type MinNominatorStake = MinNominatorStake;
    type PalletId = DomainsPalletId;
    type StorageFee = TransactionFees;
    type BlockSlot = BlockSlot;
    type BundleLongevity = BundleLongevity;
    type DomainsTransfersTracker = Transporter;
    type MaxInitialDomainAccounts = MaxInitialDomainAccounts;
    type MinInitialDomainAccountBalance = MinInitialDomainAccountBalance;
    type DomainBundleSubmitted = Messenger;
    type Balance = Balance;
}

parameter_types! {
    pub const AvgBlockspaceUsageNumBlocks: BlockNumber = 100;
    pub const ProposerTaxOnVotes: (u32, u32) = (1, 10);
}

impl pallet_rewards::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AvgBlockspaceUsageNumBlocks = AvgBlockspaceUsageNumBlocks;
    type TransactionByteFee = TransactionByteFee;
    type MaxRewardPoints = ConstU32<20>;
    type ProposerTaxOnVotes = ProposerTaxOnVotes;
    type RewardsEnabled = Subspace;
    type FindBlockRewardAddress = Subspace;
    type FindVotingRewardAddresses = Subspace;
    type WeightInfo = ();
    type OnReward = ();
}

parameter_types! {
    // This value doesn't matter, we don't use it (`VestedTransferOrigin = EnsureNever` below).
    pub const MinVestedTransfer: Balance = 0;
}

impl orml_vesting::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MinVestedTransfer = MinVestedTransfer;
    type VestedTransferOrigin = EnsureNever<AccountId>;
    type WeightInfo = ();
    type MaxVestingSchedules = ConstU32<2>;
    type BlockNumberProvider = System;
}

mod mmr {
    use super::Runtime;
    pub use pallet_mmr::primitives::*;

    pub type Leaf = <<Runtime as pallet_mmr::Config>::LeafData as LeafDataProvider>::LeafData;
    pub type Hashing = <Runtime as pallet_mmr::Config>::Hashing;
    pub type Hash = <Hashing as sp_runtime::traits::Hash>::Output;
}

pub struct BlockHashProvider;

impl pallet_mmr::BlockHashProvider<BlockNumber, Hash> for BlockHashProvider {
    fn block_hash(block_number: BlockNumber) -> Hash {
        sp_subspace_mmr::subspace_mmr_runtime_interface::consensus_block_hash(block_number)
            .expect("Hash must exist for a given block number.")
    }
}

impl pallet_mmr::Config for Runtime {
    const INDEXING_PREFIX: &'static [u8] = mmr::INDEXING_PREFIX;
    type Hashing = Keccak256;
    type LeafData = SubspaceMmr;
    type OnNewRoot = SubspaceMmr;
    type BlockHashProvider = BlockHashProvider;
    type WeightInfo = ();
}

parameter_types! {
    pub const MmrRootHashCount: u32 = 15;
}

impl pallet_subspace_mmr::Config for Runtime {
    type MmrRootHash = mmr::Hash;
    type MmrRootHashCount = MmrRootHashCount;
}

construct_runtime!(
    pub struct Runtime {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,

        Subspace: pallet_subspace = 2,
        OffencesSubspace: pallet_offences_subspace = 3,
        Rewards: pallet_rewards = 9,

        Balances: pallet_balances = 4,
        TransactionFees: pallet_transaction_fees = 12,
        TransactionPayment: pallet_transaction_payment = 5,
        Utility: pallet_utility = 8,

        Domains: pallet_domains = 11,

        Vesting: orml_vesting = 7,

        Mmr: pallet_mmr = 30,
        SubspaceMmr: pallet_subspace_mmr = 31,

        // messenger stuff
        // Note: Indexes should match with indexes on other chains and domains
        Messenger: pallet_messenger exclude_parts { Inherent } = 60,
        Transporter: pallet_transporter = 61,

        // Reserve some room for other pallets as we'll remove sudo pallet eventually.
        Sudo: pallet_sudo = 100,
    }
);

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

fn extract_segment_headers(ext: &UncheckedExtrinsic) -> Option<Vec<SegmentHeader>> {
    match &ext.function {
        RuntimeCall::Subspace(pallet_subspace::Call::store_segment_headers { segment_headers }) => {
            Some(segment_headers.clone())
        }
        _ => None,
    }
}

fn is_xdm_valid(encoded_ext: Vec<u8>) -> Option<bool> {
    if let Ok(ext) = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()) {
        match &ext.function {
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg }) => {
                Some(Messenger::validate_relay_message(msg).is_ok())
            }
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                Some(Messenger::validate_relay_message_response(msg).is_ok())
            }
            _ => None,
        }
    } else {
        None
    }
}

fn extract_utility_block_object_mapping<I: Iterator<Item = Hash>>(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &pallet_utility::Call<Runtime>,
    mut recursion_depth_left: u16,
    successful_calls: &mut Peekable<I>,
) {
    if recursion_depth_left == 0 {
        return;
    }

    recursion_depth_left -= 1;

    // Add enum variant to the base offset.
    base_offset += 1;

    match call {
        pallet_utility::Call::batch { calls }
        | pallet_utility::Call::batch_all { calls }
        | pallet_utility::Call::force_batch { calls } => {
            base_offset += Compact::compact_len(&(calls.len() as u32)) as u32;

            for call in calls {
                extract_call_block_object_mapping(
                    base_offset,
                    objects,
                    call,
                    recursion_depth_left,
                    successful_calls,
                );

                base_offset += call.encoded_size() as u32;
            }
        }
        pallet_utility::Call::as_derivative { index, call } => {
            base_offset += index.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
                successful_calls,
            );
        }
        pallet_utility::Call::dispatch_as { as_origin, call } => {
            base_offset += as_origin.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
                successful_calls,
            );
        }
        pallet_utility::Call::with_weight { call, .. } => {
            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
                successful_calls,
            );
        }
        pallet_utility::Call::__Ignore(_, _) => {
            // Ignore.
        }
    }
}

fn extract_call_block_object_mapping<I: Iterator<Item = Hash>>(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &RuntimeCall,
    recursion_depth_left: u16,
    successful_calls: &mut Peekable<I>,
) {
    // Add enum variant to the base offset.
    base_offset += 1;

    if let RuntimeCall::Utility(call) = call {
        extract_utility_block_object_mapping(
            base_offset,
            objects,
            call,
            recursion_depth_left,
            successful_calls,
        );
    }
}

fn extract_block_object_mapping(block: Block, successful_calls: Vec<Hash>) -> BlockObjectMapping {
    let mut block_object_mapping = BlockObjectMapping::default();
    let mut successful_calls = successful_calls.into_iter().peekable();
    let mut base_offset =
        block.header.encoded_size() + Compact::compact_len(&(block.extrinsics.len() as u32));
    for extrinsic in block.extrinsics {
        let signature_size = extrinsic
            .signature
            .as_ref()
            .map(|s| s.encoded_size())
            .unwrap_or_default();
        // Extrinsic starts with vector length and version byte, followed by optional signature and
        // `function` encoding.
        let base_extrinsic_offset = base_offset
            + Compact::compact_len(
                &((1 + signature_size + extrinsic.function.encoded_size()) as u32),
            )
            + 1
            + signature_size;

        extract_call_block_object_mapping(
            base_extrinsic_offset as u32,
            &mut block_object_mapping.objects,
            &extrinsic.function,
            MAX_OBJECT_MAPPING_RECURSION_DEPTH,
            &mut successful_calls,
        );

        base_offset += extrinsic.encoded_size();
    }

    block_object_mapping
}

fn extract_successful_bundles(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> OpaqueBundles<Block, DomainHeader, Balance> {
    let successful_bundles = Domains::successful_bundles(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle })
                if opaque_bundle.domain_id() == domain_id
                    && successful_bundles.contains(&opaque_bundle.hash()) =>
            {
                Some(opaque_bundle)
            }
            _ => None,
        })
        .collect()
}

fn extract_bundle(
    extrinsic: UncheckedExtrinsic,
) -> Option<
    sp_domains::OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader, Balance>,
> {
    match extrinsic.function {
        RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) => {
            Some(opaque_bundle)
        }
        _ => None,
    }
}

pub(crate) fn extract_fraud_proofs(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> Vec<FraudProof<NumberFor<Block>, Hash, DomainHeader>> {
    let successful_fraud_proofs = Domains::successful_fraud_proofs(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_fraud_proof { fraud_proof })
                if fraud_proof.domain_id() == domain_id
                    && successful_fraud_proofs.contains(&fraud_proof.hash()) =>
            {
                Some(*fraud_proof)
            }
            _ => None,
        })
        .collect()
}

struct RewardAddress([u8; 32]);

impl From<FarmerPublicKey> for RewardAddress {
    #[inline]
    fn from(farmer_public_key: FarmerPublicKey) -> Self {
        Self(
            farmer_public_key
                .as_slice()
                .try_into()
                .expect("Public key is always of correct size; qed"),
        )
    }
}

impl From<RewardAddress> for AccountId32 {
    #[inline]
    fn from(reward_address: RewardAddress) -> Self {
        reward_address.0.into()
    }
}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_objects::ObjectsApi<Block> for Runtime {
        fn extract_block_object_mapping(block: Block, successful_calls: Vec<Hash>) -> BlockObjectMapping {
            extract_block_object_mapping(block, successful_calls)
        }

        fn validated_object_call_hashes() -> Vec<Hash> {
            // No pallets produce objects right now
            Vec::new()
        }
    }

    impl sp_consensus_subspace::SubspaceApi<Block, FarmerPublicKey> for Runtime {
        fn pot_parameters() -> PotParameters {
            Subspace::pot_parameters()
        }

        fn solution_ranges() -> SolutionRanges {
            Subspace::solution_ranges()
        }

        fn submit_report_equivocation_extrinsic(
            equivocation_proof: EquivocationProof<<Block as BlockT>::Header>,
        ) -> Option<()> {
            Subspace::submit_equivocation_report(equivocation_proof)
        }

        fn submit_vote_extrinsic(
            signed_vote: SignedVote<NumberFor<Block>, <Block as BlockT>::Hash, FarmerPublicKey>,
        ) {
            let SignedVote { vote, signature } = signed_vote;
            let Vote::V0 {
                height,
                parent_hash,
                slot,
                solution,
                proof_of_time,
                future_proof_of_time,
            } = vote;

            Subspace::submit_vote(SignedVote {
                vote: Vote::V0 {
                    height,
                    parent_hash,
                    slot,
                    solution: solution.into_reward_address_format::<RewardAddress, AccountId32>(),
                    proof_of_time,
                    future_proof_of_time,
                },
                signature,
            })
        }

        fn is_in_block_list(farmer_public_key: &FarmerPublicKey) -> bool {
            // TODO: Either check tx pool too for pending equivocations or replace equivocation
            //  mechanism with an alternative one, so that blocking happens faster
            Subspace::is_in_block_list(farmer_public_key)
        }

        fn history_size() -> HistorySize {
            <pallet_subspace::Pallet<Runtime>>::history_size()
        }

        fn max_pieces_in_sector() -> u16 {
            MAX_PIECES_IN_SECTOR
        }

        fn segment_commitment(segment_index: SegmentIndex) -> Option<SegmentCommitment> {
            Subspace::segment_commitment(segment_index)
        }

        fn extract_segment_headers(ext: &<Block as BlockT>::Extrinsic) -> Option<Vec<SegmentHeader >> {
            extract_segment_headers(ext)
        }

        fn is_inherent(ext: &<Block as BlockT>::Extrinsic) -> bool {
            match &ext.function {
                RuntimeCall::Subspace(call) => Subspace::is_inherent(call),
                RuntimeCall::Timestamp(call) => Timestamp::is_inherent(call),
                _ => false,
            }
        }

        fn root_plot_public_key() -> Option<FarmerPublicKey> {
            Subspace::root_plot_public_key()
        }

        fn should_adjust_solution_range() -> bool {
            Subspace::should_adjust_solution_range()
        }

        fn chain_constants() -> ChainConstants {
            ChainConstants::V0 {
                confirmation_depth_k: ConfirmationDepthK::get(),
                block_authoring_delay: Slot::from(BlockAuthoringDelay::get()),
                era_duration: EraDuration::get(),
                slot_probability: SlotProbability::get(),
                slot_duration: SlotDuration::from_millis(SLOT_DURATION),
                recent_segments: RecentSegments::get(),
                recent_history_fraction: RecentHistoryFraction::get(),
                min_sector_lifetime: MinSectorLifetime::get(),
            }
        }
    }

    impl sp_domains::DomainsApi<Block, DomainHeader> for Runtime {
        fn submit_bundle_unsigned(
            opaque_bundle: OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader, Balance>,
        ) {
            Domains::submit_bundle_unsigned(opaque_bundle)
        }

        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> OpaqueBundles<Block, DomainHeader, Balance> {
            extract_successful_bundles(domain_id, extrinsics)
        }

        fn extract_bundle(
            extrinsic: <Block as BlockT>::Extrinsic
        ) -> Option<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader, Balance>> {
            extract_bundle(extrinsic)
        }


        fn extract_receipts(
            domain_id: DomainId,
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<ExecutionReceiptFor<DomainHeader, Block, Balance>> {
            extract_successful_bundles(domain_id, extrinsics)
                .into_iter()
                .map(|bundle| bundle.into_receipt())
                .collect()
        }

        fn extrinsics_shuffling_seed() -> Randomness {
            Randomness::from(Domains::extrinsics_shuffling_seed().to_fixed_bytes())
        }

        fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>> {
            Domains::domain_runtime_code(domain_id)
        }

        fn runtime_id(domain_id: DomainId) -> Option<sp_domains::RuntimeId> {
            Domains::runtime_id(domain_id)
        }

        fn domain_instance_data(domain_id: DomainId) -> Option<(DomainInstanceData, NumberFor<Block>)> {
            Domains::domain_instance_data(domain_id)
        }

        fn timestamp() -> Moment{
            Timestamp::now()
        }

        fn domain_tx_range(_: DomainId) -> U256 {
            U256::MAX
        }

        fn genesis_state_root(domain_id: DomainId) -> Option<H256> {
            Domains::genesis_state_root(domain_id)
        }

        fn head_receipt_number(domain_id: DomainId) -> DomainNumber {
            Domains::head_receipt_number(domain_id)
        }

        fn oldest_unconfirmed_receipt_number(domain_id: DomainId) -> Option<DomainNumber> {
            Domains::oldest_unconfirmed_receipt_number(domain_id)
        }

        fn domain_block_limit(domain_id: DomainId) -> Option<sp_domains::DomainBlockLimit> {
            Domains::domain_block_limit(domain_id)
        }

        fn domain_bundle_limit(domain_id: DomainId) -> Option<sp_domains::DomainBundleLimit> {
            Domains::domain_bundle_limit(domain_id).ok().flatten()
        }

        fn non_empty_er_exists(domain_id: DomainId) -> bool {
            Domains::non_empty_er_exists(domain_id)
        }

        fn domain_best_number(domain_id: DomainId) -> Option<DomainNumber> {
            Domains::domain_best_number(domain_id)
        }

        fn execution_receipt(receipt_hash: DomainHash) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>> {
            Domains::execution_receipt(receipt_hash)
        }

        fn domain_operators(domain_id: DomainId) -> Option<(BTreeMap<OperatorId, Balance>, Vec<OperatorId>)> {
            Domains::domain_staking_summary(domain_id).map(|summary| {
                let next_operators = summary.next_operators.into_iter().collect();
                (summary.current_operators, next_operators)
            })
        }

        fn operator_id_by_signing_key(signing_key: OperatorPublicKey) -> Option<OperatorId> {
            Domains::operator_signing_key(signing_key)
        }

        fn receipt_hash(domain_id: DomainId, domain_number: DomainNumber) -> Option<DomainHash> {
            Domains::receipt_hash(domain_id, domain_number)
        }

        fn consensus_chain_byte_fee() -> Balance {
            DOMAIN_STORAGE_FEE_MULTIPLIER * TransactionFees::transaction_byte_fee()
        }

        fn latest_confirmed_domain_block(domain_id: DomainId) -> Option<(DomainNumber, DomainHash)>{
            Domains::latest_confirmed_domain_block(domain_id)
        }

        fn is_bad_er_pending_to_prune(domain_id: DomainId, receipt_hash: DomainHash) -> bool {
            Domains::execution_receipt(receipt_hash).map(
                |er| Domains::is_bad_er_pending_to_prune(domain_id, er.domain_block_number)
            )
            .unwrap_or(false)
        }

        fn storage_fund_account_balance(operator_id: OperatorId) -> Balance {
            Domains::storage_fund_account_balance(operator_id)
        }
    }

    impl sp_domains::BundleProducerElectionApi<Block, Balance> for Runtime {
        fn bundle_producer_election_params(domain_id: DomainId) -> Option<BundleProducerElectionParams<Balance>> {
            Domains::bundle_producer_election_params(domain_id)
        }

        fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, Balance)> {
            Domains::operator(operator_id)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }
        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl sp_messenger::MessengerApi<Block> for Runtime {
        fn is_xdm_valid(
            extrinsic: Vec<u8>,
        ) -> Option<bool> {
            is_xdm_valid(extrinsic)
        }

        fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Vec<u8> {
            Domains::confirmed_domain_block_storage_key(domain_id)
        }

        fn outbox_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::outbox_storage_key(message_key)
        }

        fn inbox_response_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::inbox_response_storage_key(message_key)
        }

        fn domain_chains_allowlist_update(domain_id: DomainId) -> Option<DomainAllowlistUpdates>{
            Messenger::domain_chains_allowlist_update(domain_id)
        }
    }

    impl sp_messenger::RelayerApi<Block, BlockNumber, BlockNumber, <Block as BlockT>::Hash> for Runtime {
        fn block_messages() -> BlockMessagesWithStorageKey {
            Messenger::get_block_messages()
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_outbox_message(dst_chain_id, msg_id)
        }

        fn should_relay_inbox_message_response(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_inbox_message_response(dst_chain_id, msg_id)
        }
    }

    impl sp_domains_fraud_proof::FraudProofApi<Block, DomainHeader> for Runtime {
        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader>) {
            Domains::submit_fraud_proof_unsigned(fraud_proof)
        }

        fn extract_fraud_proofs(
            domain_id: DomainId,
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<FraudProof<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader>> {
            extract_fraud_proofs(domain_id, extrinsics)
        }
    }

    impl mmr::MmrApi<Block, mmr::Hash, BlockNumber> for Runtime {
        fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
            Ok(Mmr::mmr_root())
        }

        fn mmr_leaf_count() -> Result<mmr::LeafIndex, mmr::Error> {
            Ok(Mmr::mmr_leaves())
        }

        fn generate_proof(
            block_numbers: Vec<BlockNumber>,
            best_known_block_number: Option<BlockNumber>,
        ) -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::Proof<mmr::Hash>), mmr::Error> {
            Mmr::generate_proof(block_numbers, best_known_block_number).map(
                |(leaves, proof)| {
                    (
                        leaves
                            .into_iter()
                            .map(|leaf| mmr::EncodableOpaqueLeaf::from_leaf(&leaf))
                            .collect(),
                        proof,
                    )
                },
            )
        }

        fn verify_proof(leaves: Vec<mmr::EncodableOpaqueLeaf>, proof: mmr::Proof<mmr::Hash>)
            -> Result<(), mmr::Error>
        {
            let leaves = leaves.into_iter().map(|leaf|
                leaf.into_opaque_leaf()
                .try_decode()
                .ok_or(mmr::Error::Verify)).collect::<Result<Vec<mmr::Leaf>, mmr::Error>>()?;
            Mmr::verify_leaves(leaves, proof)
        }

        fn verify_proof_stateless(
            root: mmr::Hash,
            leaves: Vec<mmr::EncodableOpaqueLeaf>,
            proof: mmr::Proof<mmr::Hash>
        ) -> Result<(), mmr::Error> {
            let nodes = leaves.into_iter().map(|leaf|mmr::DataOrHash::Data(leaf.into_opaque_leaf())).collect();
            pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(root, nodes, proof)
        }
    }

    impl subspace_test_primitives::OnchainStateApi<Block, AccountId, Balance> for Runtime {
        fn free_balance(account_id: AccountId) -> Balance {
            Balances::free_balance(account_id)
        }

        fn get_open_channel_for_chain(dst_chain_id: ChainId) -> Option<ChannelId> {
            Messenger::get_open_channel_for_chain(dst_chain_id).map(|(c, _)| c)
        }

        fn verify_proof_and_extract_consensus_state_root(mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, <Block as BlockT>::Hash, H256>) -> Option<H256> {
            <MmrProofVerifier as sp_subspace_mmr::MmrProofVerifier<_, _, _,>>::verify_proof_and_extract_consensus_state_root(mmr_leaf_proof)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn create_default_config() -> Vec<u8> {
            create_default_config::<RuntimeGenesisConfig>()
        }

        fn build_config(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_config::<RuntimeGenesisConfig>(config)
        }
    }
}
