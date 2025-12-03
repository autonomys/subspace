use crate::{self as pallet_domains, BlockSlot, FungibleHoldId};
use core::mem;
use domain_runtime_primitives::BlockNumber as DomainBlockNumber;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use frame_support::dispatch::DispatchInfo;
use frame_support::pallet_prelude::{Decode, Encode, MaxEncodedLen, TypeInfo};
use frame_support::traits::{ConstU16, ConstU64, VariantCount};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{IdentityFee, Weight};
use frame_support::{PalletId, derive_impl, parameter_types};
use frame_system::mocking::MockUncheckedExtrinsic;
use frame_system::pallet_prelude::BlockNumberFor;
use pallet_subspace::NormalEraChange;
use parity_scale_codec::DecodeWithMemTracking;
use sp_consensus_slots::Slot;
use sp_core::H256;
use sp_domains::bundle::BundleVersion;
use sp_domains::execution_receipt::ExecutionReceiptVersion;
use sp_domains::{BundleAndExecutionReceiptVersion, ChainId, DomainId, EpochIndex};
use sp_runtime::traits::{AccountIdConversion, Get, IdentityLookup};
use sp_runtime::transaction_validity::TransactionValidityError;
use std::num::NonZeroU64;
use subspace_core_primitives::SlotNumber;
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::segments::HistorySize;
use subspace_core_primitives::solutions::SolutionRange;
use subspace_runtime_primitives::{
    AI3, ConsensusEventSegmentSize, HoldIdentifier, Moment, StorageFee,
};

pub(crate) type Block = frame_system::mocking::MockBlockU32<Test>;
pub(crate) type Balance = u128;

// TODO: Remove when DomainRegistry is usable.
pub(crate) const DOMAIN_ID: DomainId = DomainId::new(0);

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        Subspace: pallet_subspace,
        Domains: pallet_domains,
        DomainExecutive: domain_pallet_executive,
        BlockFees: pallet_block_fees,
        MockVersionStore: pallet_mock_version_store,
    }
);

pub(crate) type BlockNumber = u32;
pub(crate) type Hash = H256;
pub(crate) type AccountId = u128;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type Hash = Hash;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
    type DbWeight = ParityDbWeight;
    type EventSegmentSize = ConsensusEventSegmentSize;
}

parameter_types! {
    pub const MaximumReceiptDrift: BlockNumber = 128;
    pub const InitialDomainTxRange: u64 = 3;
    pub const DomainTxRangeAdjustmentInterval: u64 = 100;
    pub const MaxDomainBlockSize: u32 = 1024 * 1024;
    pub const MaxDomainBlockWeight: Weight = Weight::from_parts(1024 * 1024, 0);
    pub const DomainInstantiationDeposit: Balance = 100;
    pub const MaxDomainNameLength: u32 = 16;
    pub const BlockTreePruningDepth: u32 = 16;
    pub const SlotProbability: (u64, u64) = (1, 6);
}

pub struct ConfirmationDepthK;

impl Get<BlockNumber> for ConfirmationDepthK {
    fn get() -> BlockNumber {
        10
    }
}

#[derive(
    PartialEq,
    Eq,
    Clone,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    Ord,
    PartialOrd,
    Copy,
    Debug,
    DecodeWithMemTracking,
)]
pub struct HoldIdentifierWrapper(HoldIdentifier);

impl crate::HoldIdentifier<Test> for HoldIdentifierWrapper {
    fn staking_staked() -> FungibleHoldId<Test> {
        Self(HoldIdentifier::DomainStaking)
    }

    fn domain_instantiation_id() -> FungibleHoldId<Test> {
        Self(HoldIdentifier::DomainInstantiation)
    }

    fn storage_fund_withdrawal() -> Self {
        Self(HoldIdentifier::DomainStorageFund)
    }
}

impl VariantCount for HoldIdentifierWrapper {
    const VARIANT_COUNT: u32 = mem::variant_count::<HoldIdentifier>() as u32;
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type RuntimeHoldReason = HoldIdentifierWrapper;
    type DustRemoval = ();
}

parameter_types! {
    pub const MinOperatorStake: Balance = 100 * AI3;
    pub const MinNominatorStake: Balance = AI3;
    pub const StakeWithdrawalLockingPeriod: DomainBlockNumber = 5;
    pub const StakeEpochDuration: DomainBlockNumber = 5;
    pub TreasuryAccount: u128 = PalletId(*b"treasury").into_account_truncating();
    pub const BlockReward: Balance = 10 * AI3;
    pub const MaxPendingStakingOperation: u32 = 512;
    pub const DomainsPalletId: PalletId = PalletId(*b"domains_");
    pub const DomainChainByteFee: Balance = 1;
    pub const MaxInitialDomainAccounts: u32 = 5;
    pub const MinInitialDomainAccountBalance: Balance = AI3;
    pub const BundleLongevity: u32 = 5;
    pub const WithdrawalLimit: u32 = 10;
    pub const CurrentBundleAndExecutionReceiptVersion: BundleAndExecutionReceiptVersion = BundleAndExecutionReceiptVersion {
        bundle_version: BundleVersion::V0,
        execution_receipt_version: ExecutionReceiptVersion::V0,
    };
    pub const OperatorActivationDelayInEpochs: EpochIndex = 5;
}

pub struct MockRandomness;

impl frame_support::traits::Randomness<Hash, BlockNumber> for MockRandomness {
    fn random(_: &[u8]) -> (Hash, BlockNumber) {
        (Default::default(), Default::default())
    }
}

const SLOT_DURATION: u64 = 1000;

impl pallet_timestamp::Config for Test {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

pub struct DummyStorageFee;

impl StorageFee<Balance> for DummyStorageFee {
    fn transaction_byte_fee() -> Balance {
        AI3
    }
    fn note_storage_fees(_fee: Balance) {}
}

pub struct DummyBlockSlot;

impl BlockSlot<Test> for DummyBlockSlot {
    fn future_slot(_block_number: BlockNumberFor<Test>) -> Option<sp_consensus_slots::Slot> {
        None
    }

    fn slot_produced_after(_slot: sp_consensus_slots::Slot) -> Option<BlockNumberFor<Test>> {
        Some(0u32)
    }

    fn current_slot() -> Slot {
        Slot::from(0)
    }
}

pub struct MockDomainsTransfersTracker;

impl sp_domains::DomainsTransfersTracker<Balance> for MockDomainsTransfersTracker {
    type Error = ();

    fn initialize_domain_balance(
        _domain_id: DomainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn note_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn confirm_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_rejected_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reject_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reduce_domain_balance(_domain_id: DomainId, _amount: Balance) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DomainHash = sp_core::H256;
    type Balance = Balance;
    type DomainHeader = DomainHeader;
    type ConfirmationDepthK = ConfirmationDepthK;
    type Currency = Balances;
    type Share = Balance;
    type HoldIdentifier = HoldIdentifierWrapper;
    type BlockTreePruningDepth = BlockTreePruningDepth;
    type ConsensusSlotProbability = SlotProbability;
    type MaxDomainBlockSize = MaxDomainBlockSize;
    type MaxDomainBlockWeight = MaxDomainBlockWeight;
    type MaxDomainNameLength = MaxDomainNameLength;
    type DomainInstantiationDeposit = DomainInstantiationDeposit;
    type WeightInfo = crate::weights::SubstrateWeight<Test>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type MinOperatorStake = MinOperatorStake;
    type MinNominatorStake = MinNominatorStake;
    type StakeWithdrawalLockingPeriod = StakeWithdrawalLockingPeriod;
    type StakeEpochDuration = StakeEpochDuration;
    type TreasuryAccount = TreasuryAccount;
    type MaxPendingStakingOperation = MaxPendingStakingOperation;
    type Randomness = MockRandomness;
    type PalletId = DomainsPalletId;
    type StorageFee = DummyStorageFee;
    type BlockTimestamp = pallet_timestamp::Pallet<Test>;
    type BlockSlot = DummyBlockSlot;
    type DomainsTransfersTracker = MockDomainsTransfersTracker;
    type MaxInitialDomainAccounts = MaxInitialDomainAccounts;
    type MinInitialDomainAccountBalance = MinInitialDomainAccountBalance;
    type BundleLongevity = BundleLongevity;
    type DomainBundleSubmitted = ();
    type OnDomainInstantiated = ();
    type MmrHash = H256;
    type MmrProofVerifier = ();
    type FraudProofStorageKeyProvider = ();
    type OnChainRewards = ();
    type WithdrawalLimit = WithdrawalLimit;
    type DomainOrigin = crate::EnsureDomainOrigin;
    type CurrentBundleAndExecutionReceiptVersion = CurrentBundleAndExecutionReceiptVersion;
    type OperatorActivationDelayInEpochs = OperatorActivationDelayInEpochs;
}

pub struct ExtrinsicStorageFees;

impl domain_pallet_executive::ExtrinsicStorageFees<Test> for ExtrinsicStorageFees {
    fn extract_signer(_xt: MockUncheckedExtrinsic<Test>) -> (Option<AccountId>, DispatchInfo) {
        (None, DispatchInfo::default())
    }

    fn on_storage_fees_charged(
        _charged_fees: Balance,
        _tx_size: u32,
    ) -> Result<(), TransactionValidityError> {
        Ok(())
    }
}

impl domain_pallet_executive::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Currency = Balances;
    type LengthToFee = IdentityFee<Balance>;
    type ExtrinsicStorageFees = ExtrinsicStorageFees;
}

impl pallet_block_fees::Config for Test {
    type Balance = Balance;
    type DomainChainByteFee = DomainChainByteFee;
}

pub const INITIAL_SOLUTION_RANGE: SolutionRange =
    u64::MAX / (1024 * 1024 * 1024 / Piece::SIZE as u64) * 3 / 10;

parameter_types! {
    pub const BlockAuthoringDelay: SlotNumber = 2;
    pub const PotEntropyInjectionInterval: BlockNumber = 5;
    pub const PotEntropyInjectionLookbackDepth: u8 = 2;
    pub const PotEntropyInjectionDelay: SlotNumber = 4;
    pub const EraDuration: u32 = 4;
    // 1GB
    pub const InitialSolutionRange: SolutionRange = INITIAL_SOLUTION_RANGE;
    pub const RecentSegments: HistorySize = HistorySize::new(NonZeroU64::new(5).unwrap());
    pub const RecentHistoryFraction: (HistorySize, HistorySize) = (
        HistorySize::new(NonZeroU64::new(1).unwrap()),
        HistorySize::new(NonZeroU64::new(10).unwrap()),
    );
    pub const MinSectorLifetime: HistorySize = HistorySize::new(NonZeroU64::new(4).unwrap());
    pub const RecordSize: u32 = 3840;
    pub const ExpectedVotesPerBlock: u32 = 9;
    pub const ReplicationFactor: u16 = 1;
    pub const ReportLongevity: u64 = 34;
    pub const ShouldAdjustSolutionRange: bool = false;
    pub const BlockSlotCount: u32 = 6;
}

impl pallet_subspace::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type SubspaceOrigin = pallet_subspace::EnsureSubspaceOrigin;
    type BlockAuthoringDelay = BlockAuthoringDelay;
    type PotEntropyInjectionInterval = PotEntropyInjectionInterval;
    type PotEntropyInjectionLookbackDepth = PotEntropyInjectionLookbackDepth;
    type PotEntropyInjectionDelay = PotEntropyInjectionDelay;
    type EraDuration = EraDuration;
    type InitialSolutionRange = InitialSolutionRange;
    type SlotProbability = SlotProbability;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecentSegments = RecentSegments;
    type RecentHistoryFraction = RecentHistoryFraction;
    type MinSectorLifetime = MinSectorLifetime;
    type ExpectedVotesPerBlock = ExpectedVotesPerBlock;
    type MaxPiecesInSector = ConstU16<1>;
    type ShouldAdjustSolutionRange = ShouldAdjustSolutionRange;
    type EraChangeTrigger = NormalEraChange;
    type WeightInfo = ();
    type BlockSlotCount = BlockSlotCount;
    type ExtensionWeightInfo = pallet_subspace::extensions::weights::SubstrateWeight<Self>;
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub enum MockBundleVersion {
    V0,
    V1,
    V2,
    V3,
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub enum MockExecutionReceiptVersion {
    V0,
    V1,
    V2,
    V3,
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub struct MockBundleAndExecutionReceiptVersion {
    pub bundle_version: MockBundleVersion,
    pub execution_receipt_version: MockExecutionReceiptVersion,
}

#[frame_support::pallet]
pub(crate) mod pallet_mock_version_store {
    use super::{BlockNumberFor, MockBundleAndExecutionReceiptVersion};
    use frame_support::pallet_prelude::*;
    use std::collections::BTreeMap;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    /// Pallet domain-id to store self domain id.
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type MockPreviousBundleAndExecutionReceiptVersions<T: Config> = StorageValue<
        _,
        BTreeMap<BlockNumberFor<T>, MockBundleAndExecutionReceiptVersion>,
        ValueQuery,
    >;
}

impl pallet_mock_version_store::Config for Test {}
