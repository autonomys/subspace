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
#![feature(const_option, const_trait_impl)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

mod domains;
mod feed_processor;
mod fees;
mod object_mapping;
mod signed_extensions;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use crate::feed_processor::feed_processor;
pub use crate::feed_processor::FeedProcessorKind;
use crate::fees::{OnChargeTransaction, TransactionByteFee};
use crate::object_mapping::extract_block_object_mapping;
use crate::signed_extensions::{CheckStorageAccess, DisablePallets};
use codec::{Decode, Encode, MaxEncodedLen};
use core::mem;
use core::num::NonZeroU64;
use domain_runtime_primitives::{
    BlockNumber as DomainNumber, Hash as DomainHash, MultiAccountId, TryConvertBack,
};
use frame_support::inherent::ProvideInherent;
use frame_support::traits::{ConstU16, ConstU32, ConstU64, ConstU8, Currency, Everything, Get};
use frame_support::weights::constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND};
use frame_support::weights::{ConstantMultiplier, IdentityFee, Weight};
use frame_support::{construct_runtime, parameter_types, PalletId};
use frame_system::limits::{BlockLength, BlockWeights};
use frame_system::EnsureNever;
use pallet_feeds::feed_processor::FeedProcessor;
pub use pallet_subspace::AllowAuthoringBy;
use pallet_transporter::EndpointHandler;
use scale_info::TypeInfo;
use sp_api::{impl_runtime_apis, BlockT};
use sp_consensus_slots::SlotDuration;
use sp_consensus_subspace::{
    ChainConstants, EquivocationProof, FarmerPublicKey, PotParameters, SignedVote, SolutionRanges,
    Vote,
};
use sp_core::crypto::{ByteArray, KeyTypeId};
use sp_core::storage::StateVersion;
use sp_core::{OpaqueMetadata, H256};
use sp_domains::bundle_producer_election::BundleProducerElectionParams;
use sp_domains::{
    DomainId, DomainInstanceData, DomainsHoldIdentifier, ExecutionReceipt, OperatorId,
    OperatorPublicKey, ReceiptHash, StakingHoldIdentifier,
};
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockInfo, BlockMessagesWithStorageKey, ChainId, CrossDomainMessage,
    ExtractedStateRootsFromProof, MessageId,
};
use sp_runtime::traits::{AccountIdConversion, AccountIdLookup, BlakeTwo256, Convert, NumberFor};
use sp_runtime::transaction_validity::{TransactionSource, TransactionValidity};
use sp_runtime::{
    create_runtime_str, generic, AccountId32, ApplyExtrinsicResult, Perbill, SaturatedConversion,
};
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use static_assertions::const_assert;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    HistorySize, Piece, Randomness, Record, SegmentCommitment, SegmentHeader, SegmentIndex,
    SlotNumber, SolutionRange, U256,
};
use subspace_runtime_primitives::{
    AccountId, Balance, BlockNumber, FindBlockRewardAddress, Hash, Moment, Nonce, Signature,
    MIN_REPLICATION_FACTOR, SHANNON, SSC, STORAGE_FEES_ESCROW_BLOCK_REWARD,
    STORAGE_FEES_ESCROW_BLOCK_TAX,
};

sp_runtime::impl_opaque_keys! {
    pub struct SessionKeys {
    }
}

/// How many pieces one sector is supposed to contain (max)
const MAX_PIECES_IN_SECTOR: u16 = 1000;

// To learn more about runtime versioning and what each of the following value means:
//   https://substrate.dev/docs/en/knowledgebase/runtime/upgrades#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("subspace"),
    impl_name: create_runtime_str!("subspace"),
    authoring_version: 0,
    spec_version: 2,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 0,
    state_version: 0,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

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
pub const MILLISECS_PER_BLOCK: u64 = 6000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
const SLOT_DURATION: u64 = 1000;

/// 1 in 6 slots (on average, not counting collisions) will have a block.
/// Must match ratio between block and slot duration in constants above.
const SLOT_PROBABILITY: (u64, u64) = (1, 6);

/// Number of slots between slot arrival and when corresponding block can be produced.
const BLOCK_AUTHORING_DELAY: SlotNumber = 4;

/// Interval, in blocks, between blockchain entropy injection into proof of time chain.
const POT_ENTROPY_INJECTION_INTERVAL: BlockNumber = 50;

/// Interval, in entropy injection intervals, where to take entropy for injection from.
const POT_ENTROPY_INJECTION_LOOKBACK_DEPTH: u8 = 2;

/// Delay after block, in slots, when entropy injection takes effect.
const POT_ENTROPY_INJECTION_DELAY: SlotNumber = 15;

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

/// Initial tx range = U256::MAX / INITIAL_DOMAIN_TX_RANGE.
const INITIAL_DOMAIN_TX_RANGE: u64 = 3;

/// Tx range is adjusted every DOMAIN_TX_RANGE_ADJUSTMENT_INTERVAL blocks.
const TX_RANGE_ADJUSTMENT_INTERVAL_BLOCKS: u64 = 100;

// We assume initial plot size starts with the a single sector.
const INITIAL_SOLUTION_RANGE: SolutionRange = sectors_to_solution_range(1);

/// Number of votes expected per block.
///
/// This impacts solution range for votes in consensus.
const EXPECTED_VOTES_PER_BLOCK: u32 = 9;

/// Number of latest archived segments that are considered "recent history".
const RECENT_SEGMENTS: HistorySize = HistorySize::new(NonZeroU64::new(5).expect("Not zero; qed"));
/// Fraction of pieces from the "recent history" (`recent_segments`) in each sector.
const RECENT_HISTORY_FRACTION: (HistorySize, HistorySize) = (
    HistorySize::new(NonZeroU64::new(1).expect("Not zero; qed")),
    HistorySize::new(NonZeroU64::new(10).expect("Not zero; qed")),
);
/// Minimum lifetime of a plotted sector, measured in archived segment.
const MIN_SECTOR_LIFETIME: HistorySize =
    HistorySize::new(NonZeroU64::new(4).expect("Not zero; qed"));

/// The block weight for 2 seconds of compute
const BLOCK_WEIGHT_FOR_2_SEC: Weight =
    Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2), u64::MAX);

/// A ratio of `Normal` dispatch class within block, for `BlockWeight` and `BlockLength`.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// Maximum block length for non-`Normal` extrinsic is 5 MiB.
const MAX_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;

/// Computes the following:
/// ```
/// MAX * slot_probability / audit_chunks_per_chunk / (pieces_in_sector * chunks / s_buckets)
///     / sectors
/// ```
const fn sectors_to_solution_range(sectors: u64) -> SolutionRange {
    let audit_chunks_per_chunk = Scalar::FULL_BYTES / mem::size_of::<SolutionRange>();
    let solution_range = SolutionRange::MAX
        // Account for slot probability
        / SLOT_PROBABILITY.1 * SLOT_PROBABILITY.0
        // We're auditing one chunk in each sector, account for how many audit chunks each chunk has
        / audit_chunks_per_chunk as u64
        // Now take sector size and probability of hitting occupied s-bucket in sector into account
        / (MAX_PIECES_IN_SECTOR as u64 * Record::NUM_CHUNKS as u64 / Record::NUM_S_BUCKETS as u64);

    // Take number of sectors into account
    solution_range / sectors
}

/// Computes the following:
/// ```
/// MAX * slot_probability / audit_chunks_per_chunk / (pieces_in_sector * chunks / s_buckets)
///     / solution_range
/// ```
const fn solution_range_to_sectors(solution_range: SolutionRange) -> u64 {
    let audit_chunks_per_chunk = Scalar::FULL_BYTES / mem::size_of::<SolutionRange>();
    let sectors = SolutionRange::MAX
        // Account for slot probability
        / SLOT_PROBABILITY.1 * SLOT_PROBABILITY.0
        // We're auditing one chunk in each sector, account for how many audit chunks each chunk has
        / audit_chunks_per_chunk as u64
        // Now take sector size and probability of hitting occupied s-bucket in sector into account
        / (MAX_PIECES_IN_SECTOR as u64 * Record::NUM_CHUNKS as u64 / Record::NUM_S_BUCKETS as u64);

    // Take solution range into account
    sectors / solution_range
}

// Quick test to ensure functions above are the inverse of each other
const_assert!(solution_range_to_sectors(sectors_to_solution_range(1)) == 1);
const_assert!(solution_range_to_sectors(sectors_to_solution_range(3)) == 3);
const_assert!(solution_range_to_sectors(sectors_to_solution_range(5)) == 5);

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 2400;
    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub SubspaceBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(BLOCK_WEIGHT_FOR_2_SEC, NORMAL_DISPATCH_RATIO);
    /// We allow for 3.75 MiB for `Normal` extrinsic with 5 MiB maximum block length.
    pub SubspaceBlockLength: BlockLength = BlockLength::max_with_normal_ratio(MAX_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
    pub const ExtrinsicsRootStateVersion: StateVersion = StateVersion::V0;
}

pub type SS58Prefix = ConstU16<2254>;

// Configure FRAME pallets to include in runtime.

impl frame_system::Config for Runtime {
    /// The basic call filter to use in dispatchable.
    ///
    /// `Everything` is used here as we use the signed extension
    /// `DisablePallets` as the actual call filter.
    type BaseCallFilter = Everything;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = SubspaceBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = SubspaceBlockLength;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
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
    type BlockHashCount = ConstU32<250>;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
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
    type MaxConsumers = ConstU32<16>;
    type ExtrinsicsRootStateVersion = ExtrinsicsRootStateVersion;
}

parameter_types! {
    pub const BlockAuthoringDelay: SlotNumber = BLOCK_AUTHORING_DELAY;
    pub const PotEntropyInjectionInterval: BlockNumber = POT_ENTROPY_INJECTION_INTERVAL;
    pub const PotEntropyInjectionLookbackDepth: u8 = POT_ENTROPY_INJECTION_LOOKBACK_DEPTH;
    pub const PotEntropyInjectionDelay: SlotNumber = POT_ENTROPY_INJECTION_DELAY;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ExpectedVotesPerBlock: u32 = EXPECTED_VOTES_PER_BLOCK;
    pub const RecentSegments: HistorySize = RECENT_SEGMENTS;
    pub const RecentHistoryFraction: (HistorySize, HistorySize) = RECENT_HISTORY_FRACTION;
    pub const MinSectorLifetime: HistorySize = MIN_SECTOR_LIFETIME;
    // Disable solution range adjustment at the start of chain.
    // Root origin must enable later
    pub const ShouldAdjustSolutionRange: bool = false;
}

pub struct ConfirmationDepthK;

impl Get<BlockNumber> for ConfirmationDepthK {
    fn get() -> BlockNumber {
        pallet_runtime_configs::ConfirmationDepthK::<Runtime>::get()
    }
}

impl pallet_subspace::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type BlockAuthoringDelay = BlockAuthoringDelay;
    type PotEntropyInjectionInterval = PotEntropyInjectionInterval;
    type PotEntropyInjectionLookbackDepth = PotEntropyInjectionLookbackDepth;
    type PotEntropyInjectionDelay = PotEntropyInjectionDelay;
    type EraDuration = ConstU32<ERA_DURATION_IN_BLOCKS>;
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

    type HandleEquivocation = pallet_subspace::equivocation::EquivocationHandler<
        OffencesSubspace,
        ConstU64<{ EQUIVOCATION_REPORT_LONGEVITY as u64 }>,
    >;

    type WeightInfo = pallet_subspace::weights::SubstrateWeight<Runtime>;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

parameter_types! {
    // TODO: Correct value
    pub const ExistentialDeposit: Balance = 500 * SHANNON;
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum HoldIdentifier {
    Domains(DomainsHoldIdentifier),
}

impl pallet_domains::HoldIdentifier<Runtime> for HoldIdentifier {
    fn staking_pending_deposit(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::PendingDeposit(operator_id),
        ))
    }

    fn staking_staked(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::Staked(operator_id),
        ))
    }

    fn staking_pending_unlock(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::PendingUnlock(operator_id),
        ))
    }

    fn domain_instantiation_id(domain_id: DomainId) -> Self {
        Self::Domains(DomainsHoldIdentifier::DomainInstantiation(domain_id))
    }
}

parameter_types! {
    // TODO: revisit this
    pub const MaxHolds: u32 = 100;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = HoldIdentifier;
    type MaxHolds = MaxHolds;
}

parameter_types! {
    pub const StorageFeesEscrowBlockReward: (u64, u64) = STORAGE_FEES_ESCROW_BLOCK_REWARD;
    pub const StorageFeesEscrowBlockTax: (u64, u64) = STORAGE_FEES_ESCROW_BLOCK_TAX;
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
        let sectors = solution_range_to_sectors(Subspace::solution_ranges().current);
        sectors as u128 * MAX_PIECES_IN_SECTOR as u128 * Piece::SIZE as u128
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
    type StorageFeesEscrowBlockReward = StorageFeesEscrowBlockReward;
    type StorageFeesEscrowBlockTax = StorageFeesEscrowBlockTax;
    type CreditSupply = CreditSupply;
    type TotalSpacePledged = TotalSpacePledged;
    type BlockchainHistorySize = BlockchainHistorySize;
    type Currency = Balances;
    type FindBlockRewardAddress = Subspace;
    type WeightInfo = ();
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
    pub const RelayConfirmationDepth: BlockNumber = 18;
    pub SelfChainId: ChainId = ChainId::Consensus;
}

pub struct DomainInfo;

impl sp_messenger::endpoint::DomainInfo<BlockNumber, Hash, Hash> for DomainInfo {
    fn domain_best_number(domain_id: DomainId) -> Option<BlockNumber> {
        Domains::domain_best_number(domain_id)
    }

    fn domain_state_root(domain_id: DomainId, number: BlockNumber, hash: Hash) -> Option<Hash> {
        Domains::domain_state_root(domain_id, number, hash)
    }
}

pub struct OnXDMRewards;

impl sp_messenger::OnXDMRewards<Balance> for OnXDMRewards {
    fn on_xdm_rewards(reward: Balance) {
        if let Some(block_author) = Subspace::find_block_reward_address() {
            let _ = Balances::deposit_creating(&block_author, reward);
        }
    }
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
    type DomainInfo = DomainInfo;
    type ConfirmationDepth = RelayConfirmationDepth;
    type WeightInfo = pallet_messenger::weights::SubstrateWeight<Runtime>;
    type WeightToFee = IdentityFee<domain_runtime_primitives::Balance>;
    type OnXDMRewards = OnXDMRewards;
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

pub struct AccountIdConverter;

impl Convert<AccountId, MultiAccountId> for AccountIdConverter {
    fn convert(account_id: AccountId) -> MultiAccountId {
        MultiAccountId::AccountId32(account_id.into())
    }
}

impl TryConvertBack<AccountId, MultiAccountId> for AccountIdConverter {
    fn try_convert_back(multi_account_id: MultiAccountId) -> Option<AccountId> {
        match multi_account_id {
            MultiAccountId::AccountId32(acc) => Some(AccountId::from(acc)),
            _ => None,
        }
    }
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
    pub const MaximumReceiptDrift: BlockNumber = 128;
    pub const InitialDomainTxRange: u64 = INITIAL_DOMAIN_TX_RANGE;
    pub const DomainTxRangeAdjustmentInterval: u64 = TX_RANGE_ADJUSTMENT_INTERVAL_BLOCKS;
    /// Runtime upgrade is delayed for 1 day at 6 sec block time.
    pub const DomainRuntimeUpgradeDelay: BlockNumber = 14_400;
    // Minimum Operator stake is 2 * MaximumBlockWeight * WeightToFee
    pub MinOperatorStake: Balance = Balance::saturated_from(2 * BLOCK_WEIGHT_FOR_2_SEC.ref_time());
    /// Use the consensus chain's `Normal` extrinsics block size limit as the domain block size limit
    pub MaxDomainBlockSize: u32 = NORMAL_DISPATCH_RATIO * MAX_BLOCK_LENGTH;
    /// Use the consensus chain's `Normal` extrinsics block weight limit as the domain block weight limit
    pub MaxDomainBlockWeight: Weight = NORMAL_DISPATCH_RATIO * BLOCK_WEIGHT_FOR_2_SEC;
    pub const MaxBundlesPerBlock: u32 = 10;
    pub const DomainInstantiationDeposit: Balance = 100 * SSC;
    pub const MaxDomainNameLength: u32 = 32;
    pub const BlockTreePruningDepth: u32 = 256;
    // TODO: revisit these
    pub const StakeWithdrawalLockingPeriod: DomainNumber = 256;
    // TODO: revisit these. For now epoch every 10 mins for a 6 second block and only 100 number of staking
    // operations allowed within each epoch.
    pub const StakeEpochDuration: DomainNumber = 100;
    pub TreasuryAccount: AccountId = PalletId(*b"treasury").into_account_truncating();
    pub const MaxPendingStakingOperation: u32 = 100;
    pub const MaxNominators: u32 = 100;
}

impl pallet_domains::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type DomainHash = DomainHash;
    type DomainHeader = sp_runtime::generic::Header<DomainNumber, BlakeTwo256>;
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
    type StakeWithdrawalLockingPeriod = StakeWithdrawalLockingPeriod;
    type StakeEpochDuration = StakeEpochDuration;
    type TreasuryAccount = TreasuryAccount;
    type MaxPendingStakingOperation = MaxPendingStakingOperation;
    type MaxNominators = MaxNominators;
    type Randomness = Subspace;
}

pub struct StakingOnReward;

impl pallet_rewards::OnReward<AccountId, Balance> for StakingOnReward {
    fn on_reward(account: AccountId, reward: Balance) {
        Domains::on_block_reward(account, reward);
    }
}

parameter_types! {
    pub const BlockReward: Balance = SSC / (ExpectedVotesPerBlock::get() as Balance + 1);
    pub const VoteReward: Balance = SSC / (ExpectedVotesPerBlock::get() as Balance + 1);
}

impl pallet_rewards::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type BlockReward = BlockReward;
    type VoteReward = VoteReward;
    type FindBlockRewardAddress = Subspace;
    type FindVotingRewardAddresses = Subspace;
    type WeightInfo = ();
    type OnReward = StakingOnReward;
}

pub type FeedId = u64;

parameter_types! {
    // Limit maximum number of feeds per account
    pub const MaxFeeds: u32 = 100;
}

impl pallet_feeds::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FeedId = FeedId;
    type FeedProcessorKind = FeedProcessorKind;
    type MaxFeeds = MaxFeeds;

    fn feed_processor(
        feed_processor_kind: Self::FeedProcessorKind,
    ) -> Box<dyn FeedProcessor<Self::FeedId>> {
        feed_processor(feed_processor_kind)
    }
}

impl pallet_grandpa_finality_verifier::Config for Runtime {
    type ChainId = FeedId;
}

impl pallet_object_store::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
}

impl pallet_runtime_configs::Config for Runtime {
    type WeightInfo = pallet_runtime_configs::weights::SubstrateWeight<Runtime>;
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

construct_runtime!(
    pub struct Runtime {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,

        Subspace: pallet_subspace = 2,
        OffencesSubspace: pallet_offences_subspace = 3,
        Rewards: pallet_rewards = 4,

        Balances: pallet_balances = 5,
        TransactionFees: pallet_transaction_fees = 6,
        TransactionPayment: pallet_transaction_payment = 7,
        Utility: pallet_utility = 8,

        Feeds: pallet_feeds = 9,
        GrandpaFinalityVerifier: pallet_grandpa_finality_verifier = 10,
        ObjectStore: pallet_object_store = 11,
        Domains: pallet_domains = 12,
        RuntimeConfigs: pallet_runtime_configs = 14,

        Vesting: orml_vesting = 13,

        // messenger stuff
        // Note: Indexes should match with indexes on other chains and domains
        Messenger: pallet_messenger = 60,
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
    CheckStorageAccess,
    DisablePallets,
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

fn extract_segment_headers(ext: &UncheckedExtrinsic) -> Option<Vec<SegmentHeader>> {
    match &ext.function {
        RuntimeCall::Subspace(pallet_subspace::Call::store_segment_headers { segment_headers }) => {
            Some(segment_headers.clone())
        }
        _ => None,
    }
}

fn extract_xdm_proof_state_roots(
    encoded_ext: Vec<u8>,
) -> Option<
    ExtractedStateRootsFromProof<
        domain_runtime_primitives::BlockNumber,
        domain_runtime_primitives::Hash,
        domain_runtime_primitives::Hash,
    >,
> {
    if let Ok(ext) = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()) {
        match &ext.function {
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg }) => {
                msg.extract_state_roots_from_proof::<BlakeTwo256>()
            }
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                msg.extract_state_roots_from_proof::<BlakeTwo256>()
            }
            _ => None,
        }
    } else {
        None
    }
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

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame_benchmarking::define_benchmarks!(
        [frame_benchmarking, BaselineBench::<Runtime>]
        [frame_system, SystemBench::<Runtime>]
        [pallet_balances, Balances]
        [pallet_domains, Domains]
        [pallet_runtime_configs, RuntimeConfigs]
        [pallet_subspace, Subspace]
        [pallet_timestamp, Timestamp]
    );
}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) {
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

        fn metadata_versions() -> sp_std::vec::Vec<u32> {
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
            Feeds::successful_puts()
        }
    }

    impl sp_consensus_subspace::SubspaceApi<Block, FarmerPublicKey> for Runtime {
        fn slot_duration() -> SlotDuration {
            SlotDuration::from_millis(SLOT_DURATION)
        }

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
            Subspace::chain_constants()
        }
    }

    impl sp_domains::transaction::PreValidationObjectApi<Block, DomainNumber, DomainHash, > for Runtime {
        fn extract_pre_validation_object(
            extrinsic: <Block as BlockT>::Extrinsic,
        ) -> sp_domains::transaction::PreValidationObject<Block, DomainNumber, DomainHash> {
            crate::domains::extract_pre_validation_object(extrinsic)
        }
    }

    impl sp_domains::DomainsApi<Block, DomainNumber, DomainHash> for Runtime {
        fn submit_bundle_unsigned(
            opaque_bundle: sp_domains::OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainNumber, DomainHash, Balance>,
        ) {
            Domains::submit_bundle_unsigned(opaque_bundle)
        }

        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> sp_domains::OpaqueBundles<Block, DomainNumber, DomainHash, Balance> {
            crate::domains::extract_successful_bundles(domain_id, extrinsics)
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

        fn domain_tx_range(domain_id: DomainId) -> U256 {
            Domains::domain_tx_range(domain_id)
        }

        fn genesis_state_root(domain_id: DomainId) -> Option<H256> {
            Domains::genesis_state_root(domain_id)
        }

        fn head_receipt_number(domain_id: DomainId) -> NumberFor<Block> {
            Domains::head_receipt_number(domain_id)
        }

        fn oldest_receipt_number(domain_id: DomainId) -> NumberFor<Block> {
            Domains::oldest_receipt_number(domain_id)
        }

        fn block_tree_pruning_depth() -> NumberFor<Block> {
            Domains::block_tree_pruning_depth()
        }

        fn domain_block_limit(domain_id: DomainId) -> Option<sp_domains::DomainBlockLimit> {
            Domains::domain_block_limit(domain_id)
        }

        fn non_empty_er_exists(domain_id: DomainId) -> bool {
            Domains::non_empty_er_exists(domain_id)
        }

        fn domain_best_number(domain_id: DomainId) -> Option<DomainNumber> {
            Domains::domain_best_number(domain_id)
        }

        fn domain_state_root(domain_id: DomainId, number: DomainNumber, hash: DomainHash) -> Option<DomainHash>{
            Domains::domain_state_root(domain_id, number, hash)
        }

        fn execution_receipt(receipt_hash: ReceiptHash) -> Option<ExecutionReceipt<NumberFor<Block>, <Block as BlockT>::Hash, DomainNumber, DomainHash, Balance>> {
            Domains::execution_receipt(receipt_hash)
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

    impl sp_messenger::MessengerApi<Block, BlockNumber> for Runtime {
        fn extract_xdm_proof_state_roots(
            extrinsic: Vec<u8>,
        ) -> Option<ExtractedStateRootsFromProof<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>> {
            extract_xdm_proof_state_roots(extrinsic)
        }

        fn is_domain_info_confirmed(
            domain_id: DomainId,
            domain_block_info: BlockInfo<BlockNumber, <Block as BlockT>::Hash>,
            domain_state_root: <Block as BlockT>::Hash,
        ) -> bool{
            Messenger::is_domain_info_confirmed(domain_id, domain_block_info, domain_state_root)
        }
    }

    impl sp_messenger::RelayerApi<Block, BlockNumber> for Runtime {
        fn chain_id() -> ChainId {
            SelfChainId::get()
        }

        fn relay_confirmation_depth() -> BlockNumber {
            RelayConfirmationDepth::get()
        }

        fn block_messages() -> BlockMessagesWithStorageKey {
            Messenger::get_block_messages()
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_outbox_message(dst_chain_id, msg_id)
        }

        fn should_relay_inbox_message_response(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_inbox_message_response(dst_chain_id, msg_id)
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;
            use frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();

            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch};
            use sp_core::storage::TrackedStorageKey;

            use frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;

            impl frame_system_benchmarking::Config for Runtime {}
            impl baseline::Config for Runtime {}

            use frame_support::traits::WhitelistedStorageKeys;
            let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);
            add_benchmarks!(params, batches);

            Ok(batches)
        }
    }
}
