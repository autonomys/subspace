use crate::block_tree::{BlockTreeNode, verify_execution_receipt};
use crate::domain_registry::{DomainConfig, DomainConfigParams, DomainObject};
use crate::runtime_registry::ScheduledRuntimeUpgrade;
use crate::staking_epoch::do_finalize_domain_current_epoch;
use crate::tests::pallet_mock_version_store::MockPreviousBundleAndExecutionReceiptVersions;
use crate::{
    self as pallet_domains, BalanceOf, BlockSlot, BlockTree, BlockTreeNodes, BundleError, Config,
    ConsensusBlockHash, DomainBlockNumberFor, DomainHashingFor, DomainRegistry,
    DomainRuntimeUpgradeRecords, DomainRuntimeUpgrades, ExecutionInbox, ExecutionReceiptOf,
    FraudProofError, FungibleHoldId, HeadDomainNumber, HeadReceiptNumber, NextDomainId,
    OperatorConfig, RawOrigin as DomainOrigin, RuntimeRegistry, ScheduledRuntimeUpgrades,
};
use core::mem;
use domain_runtime_primitives::BlockNumber as DomainBlockNumber;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use frame_support::dispatch::{DispatchInfo, RawOrigin};
use frame_support::traits::{ConstU64, Currency, Hooks, VariantCount};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{IdentityFee, Weight};
use frame_support::{PalletId, assert_err, assert_ok, derive_impl, parameter_types};
use frame_system::mocking::MockUncheckedExtrinsic;
use frame_system::pallet_prelude::*;
use hex_literal::hex;
use pallet_subspace::NormalEraChange;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_consensus_slots::Slot;
use sp_core::crypto::Pair;
use sp_core::{Get, H256};
use sp_domains::bundle::bundle_v0::{BundleHeaderV0, BundleV0, SealedBundleHeaderV0};
use sp_domains::bundle::{BundleVersion, InboxedBundle, OpaqueBundle};
use sp_domains::bundle_producer_election::make_transcript;
use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use sp_domains::execution_receipt::{ExecutionReceipt, ExecutionReceiptVersion, SingletonReceipt};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::storage::RawGenesis;
use sp_domains::{
    BundleAndExecutionReceiptVersion, ChainId, DomainId, EMPTY_EXTRINSIC_ROOT, OperatorAllowList,
    OperatorId, OperatorPair, OperatorSignature, ProofOfElection, RuntimeId, RuntimeType,
};
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_keystore::Keystore;
use sp_keystore::testing::MemoryKeystore;
use sp_runtime::app_crypto::AppCrypto;
use sp_runtime::generic::{EXTRINSIC_FORMAT_VERSION, Preamble};
use sp_runtime::traits::{
    AccountIdConversion, BlakeTwo256, BlockNumberProvider, Bounded, ConstU16, Hash as HashT,
    IdentityLookup, One, Zero,
};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::type_with_default::TypeWithDefault;
use sp_runtime::{BuildStorage, OpaqueExtrinsic};
use sp_version::{ApiId, RuntimeVersion, create_apis_vec};
use std::num::NonZeroU64;
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::segments::HistorySize;
use subspace_core_primitives::solutions::SolutionRange;
use subspace_core_primitives::{SlotNumber, U256 as P256};
use subspace_runtime_primitives::{
    AI3, BlockHashFor, ConsensusEventSegmentSize, HoldIdentifier, Moment, Nonce, StorageFee,
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlockU32<Test>;
type Balance = u128;

// TODO: Remove when DomainRegistry is usable.
const DOMAIN_ID: DomainId = DomainId::new(0);

// Operator id used for testing
const OPERATOR_ID: OperatorId = 0u64;

// Core Api version ID and default APIs
// RuntimeVersion's Decode is handwritten to accommodate Backward Compatibility for very old
// RuntimeVersion that do not have TransactionVersion or SystemVersion.
// So the Decode function always assume apis being present, at least CoreApi,
// to derive the correct TransactionVersion and SystemVersion.
// So we should always add the TEST_RUNTIME_APIS to the RuntimeVersion to ensure it is decoded correctly.
// More here - https://github.com/paritytech/polkadot-sdk/blob/master/substrate/primitives/version/src/lib.rs#L637
pub(crate) const CORE_API_ID: [u8; 8] = [223, 106, 203, 104, 153, 7, 96, 155];
pub(crate) const TEST_RUNTIME_APIS: [(ApiId, u32); 1] = [(CORE_API_ID, 5)];

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

type BlockNumber = u32;
type Hash = H256;
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
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub struct HoldIdentifierWrapper(HoldIdentifier);

impl pallet_domains::HoldIdentifier<Test> for HoldIdentifierWrapper {
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

impl pallet_domains::Config for Test {
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
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Test>;
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

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    t.into()
}

pub(crate) fn new_test_ext_with_extensions() -> sp_io::TestExternalities {
    let version = RuntimeVersion {
        spec_name: "test".into(),
        impl_name: Default::default(),
        authoring_version: 0,
        spec_version: 1,
        impl_version: 1,
        apis: create_apis_vec!(TEST_RUNTIME_APIS),
        transaction_version: 1,
        system_version: 2,
    };

    let mut ext = new_test_ext();
    ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
        ReadRuntimeVersion(version.encode()),
    ));
    ext
}

pub(crate) fn create_dummy_receipt(
    block_number: BlockNumber,
    consensus_block_hash: Hash,
    parent_domain_block_receipt_hash: H256,
    block_extrinsics_roots: Vec<H256>,
) -> ExecutionReceipt<BlockNumber, Hash, DomainBlockNumber, H256, u128> {
    let (execution_trace, execution_trace_root) = if block_number == 0 {
        (Vec::new(), Default::default())
    } else {
        let execution_trace = vec![H256::random(), H256::random()];
        let trace: Vec<[u8; 32]> = execution_trace
            .iter()
            .map(|r| r.encode().try_into().expect("H256 must fit into [u8; 32]"))
            .collect();
        let execution_trace_root = MerkleTree::from_leaves(trace.as_slice())
            .root()
            .expect("Compute merkle root of trace should success")
            .into();
        (execution_trace, execution_trace_root)
    };
    let inboxed_bundles = block_extrinsics_roots
        .into_iter()
        .map(InboxedBundle::dummy)
        .collect();
    ExecutionReceipt::V0(ExecutionReceiptV0 {
        domain_block_number: block_number as DomainBlockNumber,
        domain_block_hash: H256::random(),
        domain_block_extrinsic_root: Default::default(),
        parent_domain_block_receipt_hash,
        consensus_block_number: block_number,
        consensus_block_hash,
        inboxed_bundles,
        final_state_root: *execution_trace.last().unwrap_or(&Default::default()),
        execution_trace,
        execution_trace_root,
        block_fees: Default::default(),
        transfers: Default::default(),
    })
}

fn create_dummy_bundle(
    domain_id: DomainId,
    block_number: BlockNumber,
    consensus_block_hash: Hash,
) -> OpaqueBundle<BlockNumber, Hash, DomainHeader, u128> {
    let execution_receipt = create_dummy_receipt(
        block_number,
        consensus_block_hash,
        Default::default(),
        vec![],
    );
    create_dummy_bundle_with_receipts(
        domain_id,
        OPERATOR_ID,
        Default::default(),
        execution_receipt,
    )
}

pub(crate) fn create_dummy_bundle_with_receipts(
    domain_id: DomainId,
    operator_id: OperatorId,
    bundle_extrinsics_root: H256,
    receipt: ExecutionReceipt<BlockNumber, Hash, DomainBlockNumber, H256, u128>,
) -> OpaqueBundle<BlockNumber, Hash, DomainHeader, u128> {
    let pair = OperatorPair::from_seed(&[0; 32]);

    let header = BundleHeaderV0::<_, _, DomainHeader, _> {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root,
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle::V0(BundleV0 {
        sealed_header: SealedBundleHeaderV0::new(header, signature),
        extrinsics: Vec::new(),
    })
}

pub(crate) struct ReadRuntimeVersion(pub Vec<u8>);

impl sp_core::traits::ReadRuntimeVersion for ReadRuntimeVersion {
    fn read_runtime_version(
        &self,
        _wasm_code: &[u8],
        _ext: &mut dyn sp_externalities::Externalities,
    ) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

pub(crate) fn run_to_block<T: Config>(block_number: BlockNumberFor<T>, parent_hash: T::Hash) {
    // Finalize the previous block
    // on_finalize() does not run on the genesis block
    if block_number > One::one() {
        crate::Pallet::<T>::on_finalize(block_number - One::one());
    }
    frame_system::Pallet::<T>::finalize();

    // Initialize current block
    frame_system::Pallet::<T>::set_block_number(block_number);
    frame_system::Pallet::<T>::initialize(&block_number, &parent_hash, &Default::default());
    // on_initialize() does not run on the genesis block
    if block_number > Zero::zero() {
        crate::Pallet::<T>::on_initialize(block_number);
    }
}

pub(crate) fn register_genesis_domain(creator: u128, operator_number: usize) -> DomainId {
    let raw_genesis_storage = RawGenesis::dummy(vec![1, 2, 3, 4]).encode();
    assert_ok!(crate::Pallet::<Test>::set_permissioned_action_allowed_by(
        RawOrigin::Root.into(),
        sp_domains::PermissionedActionAllowedBy::Anyone
    ));
    assert_ok!(crate::Pallet::<Test>::register_domain_runtime(
        RawOrigin::Root.into(),
        "evm".to_owned(),
        RuntimeType::Evm,
        raw_genesis_storage,
    ));

    let domain_id = NextDomainId::<Test>::get();
    <Test as Config>::Currency::make_free_balance_be(
        &creator,
        <Test as Config>::DomainInstantiationDeposit::get()
            + operator_number as u128 * <Test as Config>::MinOperatorStake::get()
            + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
    );
    crate::Pallet::<Test>::instantiate_domain(
        RawOrigin::Signed(creator).into(),
        DomainConfigParams {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
            domain_runtime_config: Default::default(),
        },
    )
    .unwrap();

    let pair = OperatorPair::from_seed(&[0; 32]);
    for _ in 0..operator_number {
        crate::Pallet::<Test>::register_operator(
            RawOrigin::Signed(creator).into(),
            domain_id,
            <Test as Config>::MinOperatorStake::get(),
            OperatorConfig {
                signing_key: pair.public(),
                minimum_nominator_stake: AI3,
                nomination_tax: Default::default(),
            },
        )
        .unwrap();
    }
    do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

    domain_id
}

// Submit new head receipt to extend the block tree from the genesis block
pub(crate) fn extend_block_tree_from_zero(
    domain_id: DomainId,
    operator_id: u64,
    to: DomainBlockNumberFor<Test>,
) -> ExecutionReceiptOf<Test> {
    let genesis_receipt = get_block_tree_node_at::<Test>(domain_id, 0)
        .unwrap()
        .execution_receipt;
    extend_block_tree(domain_id, operator_id, to, genesis_receipt)
}

// Submit new head receipt to extend the block tree
pub(crate) fn extend_block_tree(
    domain_id: DomainId,
    operator_id: u64,
    to: DomainBlockNumberFor<Test>,
    mut latest_receipt: ExecutionReceiptOf<Test>,
) -> ExecutionReceiptOf<Test> {
    let current_block_number = frame_system::Pallet::<Test>::current_block_number();
    assert!(current_block_number < to);

    for block_number in (current_block_number + 1)..to {
        // Finilize parent block and initialize block at `block_number`
        run_to_block::<Test>(block_number, *latest_receipt.consensus_block_hash());

        // Submit a bundle with the receipt of the last block
        let bundle_extrinsics_root = H256::random();
        let bundle = create_dummy_bundle_with_receipts(
            domain_id,
            operator_id,
            bundle_extrinsics_root,
            latest_receipt,
        );
        assert_ok!(crate::Pallet::<Test>::submit_bundle(
            DomainOrigin::ValidatedUnsigned.into(),
            bundle,
        ));

        // Construct a `NewHead` receipt of the just submitted bundle, which will be included in the next bundle
        let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
        let parent_block_tree_node =
            get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
        latest_receipt = create_dummy_receipt(
            block_number,
            H256::random(),
            parent_block_tree_node
                .execution_receipt
                .hash::<DomainHashingFor<Test>>(),
            vec![bundle_extrinsics_root],
        );
    }

    // Finilize parent block and initialize block at `to`
    run_to_block::<Test>(to, *latest_receipt.consensus_block_hash());

    latest_receipt
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_block_tree_node_at<T: Config>(
    domain_id: DomainId,
    block_number: DomainBlockNumberFor<T>,
) -> Option<
    BlockTreeNode<BlockNumberFor<T>, T::Hash, DomainBlockNumberFor<T>, T::DomainHash, BalanceOf<T>>,
> {
    BlockTree::<T>::get(domain_id, block_number).and_then(BlockTreeNodes::<T>::get)
}

#[test]
fn test_calculate_tx_range() {
    let cur_tx_range = P256::from(400_u64);

    assert_eq!(
        cur_tx_range,
        pallet_domains::calculate_tx_range(cur_tx_range, 0, 1000)
    );
    assert_eq!(
        cur_tx_range,
        pallet_domains::calculate_tx_range(cur_tx_range, 1000, 0)
    );

    // Lower bound of 1/4 * current range
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 10, 1000)
    );

    // Upper bound of 4 * current range
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 8000, 1000)
    );

    // For anything else in the [0.25, 4.0] range, the change ratio should be same as
    // actual / expected
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 250, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(2_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 500, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(1_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 1000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(2_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 2000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(3_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 3000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 4000, 1000)
    );
}

#[test]
fn test_bundle_format_verification() {
    let opaque_extrinsic = |dest: u128, value: u128| -> OpaqueExtrinsic {
        UncheckedExtrinsic {
            preamble: Preamble::Bare(EXTRINSIC_FORMAT_VERSION),
            function: RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
                dest,
                value,
            }),
        }
        .into()
    };
    new_test_ext().execute_with(|| {
        let domain_id = DomainId::new(0);
        let max_extrinsics_count = 10;
        let max_bundle_size = opaque_extrinsic(0, 0).encoded_size() as u32 * max_extrinsics_count;
        let domain_config = DomainConfig {
            domain_name: "test-domain".to_owned(),
            runtime_id: 0u32,
            max_bundle_size,
            max_bundle_weight: Weight::MAX,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
        };
        let domain_obj = DomainObject {
            owner_account_id: Default::default(),
            created_at: Default::default(),
            genesis_receipt_hash: Default::default(),
            domain_config,
            domain_runtime_info: Default::default(),
            domain_instantiation_deposit: Default::default(),
        };
        DomainRegistry::<Test>::insert(domain_id, domain_obj);

        let mut valid_bundle = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        let mut extrinsics = valid_bundle.extrinsics().to_vec();
        extrinsics.push(opaque_extrinsic(1, 1));
        extrinsics.push(opaque_extrinsic(2, 2));
        valid_bundle.set_extrinsics(extrinsics);
        valid_bundle.set_bundle_extrinsics_root(BlakeTwo256::ordered_trie_root(
            valid_bundle
                .extrinsics()
                .iter()
                .map(|xt| xt.encode())
                .collect(),
            sp_core::storage::StateVersion::V1,
        ));
        assert_ok!(pallet_domains::Pallet::<Test>::check_extrinsics_root(
            &valid_bundle
        ));

        // Bundle exceed max size
        let mut too_large_bundle = valid_bundle.clone();
        let mut extrinsics = too_large_bundle.extrinsics().to_vec();
        for i in 0..max_extrinsics_count {
            extrinsics.push(opaque_extrinsic(i as u128, i as u128));
        }
        too_large_bundle.set_extrinsics(extrinsics);
        assert!(too_large_bundle.size() > max_bundle_size);

        // Bundle with wrong value of `bundle_extrinsics_root`
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        invalid_extrinsic_root_bundle.set_bundle_extrinsics_root(H256::random());
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with wrong value of `extrinsics`
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        let mut extrinsics = valid_bundle.extrinsics().to_vec();
        extrinsics[0] = opaque_extrinsic(3, 3);
        invalid_extrinsic_root_bundle.set_extrinsics(extrinsics);
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with addtional extrinsic
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        let mut extrinsics = valid_bundle.extrinsics().to_vec();
        extrinsics.push(opaque_extrinsic(4, 4));
        invalid_extrinsic_root_bundle.set_extrinsics(extrinsics);
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with missing extrinsic
        let mut invalid_extrinsic_root_bundle = valid_bundle;
        let mut extrinsics = invalid_extrinsic_root_bundle.extrinsics().to_vec();
        extrinsics.pop().unwrap();
        invalid_extrinsic_root_bundle.set_extrinsics(extrinsics);
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );
    });
}

#[test]
fn test_invalid_fraud_proof() {
    let creator = 0u128;
    let operator_id = 0u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, 1);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        // Fraud proof target the genesis ER is invalid
        let bad_receipt_at = 0;
        let bad_receipt_hash = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
            .unwrap()
            .execution_receipt
            .hash::<DomainHashingFor<Test>>();
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::ChallengingGenesisReceipt)
        );

        // Fraud proof target unknown ER is invalid
        let bad_receipt_hash = H256::random();
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::BadReceiptNotFound)
        );
    });
}

#[test]
fn test_basic_fraud_proof_processing() {
    let creator = 0u128;
    let malicious_operator = 0u64;
    let honest_operator = 1u64;
    let head_domain_number = BlockTreePruningDepth::get() - 1;
    let test_cases = vec![
        1,
        2,
        head_domain_number - BlockTreePruningDepth::get() / 2,
        head_domain_number - 1,
        head_domain_number,
    ];
    for bad_receipt_at in test_cases {
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            extend_block_tree_from_zero(domain_id, malicious_operator, head_domain_number + 2);
            assert_eq!(
                HeadReceiptNumber::<Test>::get(domain_id),
                head_domain_number
            );

            // Construct and submit fraud proof that target ER at `head_domain_number - BlockTreePruningDepth::get() / 2`
            let bad_receipt = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
                .unwrap()
                .execution_receipt;
            let bad_receipt_hash = bad_receipt.hash::<DomainHashingFor<Test>>();
            let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
            assert_ok!(Domains::submit_fraud_proof(
                DomainOrigin::ValidatedUnsigned.into(),
                Box::new(fraud_proof)
            ));

            // The head receipt number should be reverted to `bad_receipt_at - 1`
            let head_receipt_number_after_fraud_proof = HeadReceiptNumber::<Test>::get(domain_id);
            assert_eq!(head_receipt_number_after_fraud_proof, bad_receipt_at - 1);

            for block_number in bad_receipt_at..=head_domain_number {
                if block_number == bad_receipt_at {
                    // The targeted ER should be removed from the block tree
                    assert!(BlockTree::<Test>::get(domain_id, block_number).is_none());
                } else {
                    // All the bad ER's descendants should be marked as pending to prune and the submitter
                    // should be marked as pending to slash
                    assert!(BlockTree::<Test>::get(domain_id, block_number).is_some());
                    assert!(Domains::is_bad_er_pending_to_prune(domain_id, block_number));
                    let submitter = get_block_tree_node_at::<Test>(domain_id, block_number)
                        .unwrap()
                        .operator_ids;
                    for operator_id in submitter {
                        assert!(Domains::is_operator_pending_to_slash(
                            domain_id,
                            operator_id
                        ));
                    }
                }

                // The other data that used to verify ER should not be removed, such that the honest
                // operator can re-submit the valid ER
                assert!(
                    !ExecutionInbox::<Test>::get((domain_id, block_number, block_number))
                        .is_empty()
                );
                assert!(ConsensusBlockHash::<Test>::get(domain_id, block_number).is_some());
            }

            // Re-submit the valid ER
            let resubmit_receipt = bad_receipt;
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                honest_operator,
                H256::random(),
                resubmit_receipt,
            );
            assert_ok!(Domains::submit_bundle(
                DomainOrigin::ValidatedUnsigned.into(),
                bundle,
            ));
            assert_eq!(
                HeadReceiptNumber::<Test>::get(domain_id),
                head_receipt_number_after_fraud_proof + 1
            );

            // Submit one more ER, the bad ER at the same domain block should be pruned
            let next_block_number = frame_system::Pallet::<Test>::current_block_number() + 1;
            run_to_block::<Test>(next_block_number, H256::random());
            if let Some(receipt_hash) = BlockTree::<Test>::get(domain_id, bad_receipt_at + 1) {
                let mut receipt = BlockTreeNodes::<Test>::get(receipt_hash)
                    .unwrap()
                    .execution_receipt;
                receipt.set_final_state_root(H256::random());
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    honest_operator,
                    H256::random(),
                    receipt.clone(),
                );
                assert_ok!(Domains::submit_bundle(
                    DomainOrigin::ValidatedUnsigned.into(),
                    bundle
                ));

                assert_eq!(
                    HeadReceiptNumber::<Test>::get(domain_id),
                    head_receipt_number_after_fraud_proof + 2
                );
                assert!(BlockTreeNodes::<Test>::get(receipt_hash).is_none());
                assert!(!Domains::is_bad_er_pending_to_prune(
                    domain_id,
                    *receipt.domain_block_number()
                ));
            }
        });
    }
}

fn schedule_domain_runtime_upgrade<T: Config>(
    runtime_id: RuntimeId,
    scheduled_at: BlockNumberFor<T>,
) {
    let runtime_obj = RuntimeRegistry::<T>::get(runtime_id).expect("Unknow runtime id");
    let scheduled_upgrade = ScheduledRuntimeUpgrade {
        raw_genesis: runtime_obj.raw_genesis,
        version: runtime_obj.version,
        hash: runtime_obj.hash,
    };
    ScheduledRuntimeUpgrades::<T>::insert(scheduled_at, runtime_id, scheduled_upgrade);
}

#[test]
fn test_domain_runtime_upgrade_record() {
    let runtime_id = 0u32;
    let creator = 0u128;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, 1);
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(0));

        // Schedule domain runtime upgrade for the next 2 blocks
        let current_block = frame_system::Pallet::<Test>::current_block_number();
        let (upgrade_1, upgrade_2) = (current_block + 1, current_block + 2);
        schedule_domain_runtime_upgrade::<Test>(runtime_id, upgrade_1);
        schedule_domain_runtime_upgrade::<Test>(runtime_id, upgrade_2);

        // Run to the block that the first upgrade happen, the upgrade should recorded in
        // `DomainRuntimeUpgrades` but not `DomainRuntimeUpgradeRecords`
        run_to_block::<Test>(upgrade_1, H256::random());
        assert_eq!(DomainRuntimeUpgrades::<Test>::get(), vec![runtime_id]);
        assert!(DomainRuntimeUpgradeRecords::<Test>::get(runtime_id).is_empty());

        // In the next block after upgrade, the upgrade is accounted in `missed_domain_runtime_upgrade`
        run_to_block::<Test>(upgrade_1 + 1, H256::random());
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(1));
        run_to_block::<Test>(upgrade_2 + 1, H256::random());
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(2));

        // The upgrade record is moved from `DomainRuntimeUpgrades` to `DomainRuntimeUpgradeRecords`
        assert!(DomainRuntimeUpgrades::<Test>::get().is_empty());
        assert!(DomainRuntimeUpgradeRecords::<Test>::get(runtime_id).contains_key(&upgrade_1));
        assert!(DomainRuntimeUpgradeRecords::<Test>::get(runtime_id).contains_key(&upgrade_2));
    });
}

#[test]
fn test_domain_runtime_upgrade_with_bundle() {
    let runtime_id = 0u32;
    let creator = 0u128;
    let operator_id = 0u64;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, 1);
        assert_eq!(HeadDomainNumber::<Test>::get(domain_id), 0);
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(0));

        // Schedule domain runtime upgrade for the next 2 blocks
        let current_block = frame_system::Pallet::<Test>::current_block_number();
        schedule_domain_runtime_upgrade::<Test>(runtime_id, current_block + 1);
        schedule_domain_runtime_upgrade::<Test>(runtime_id, current_block + 2);
        run_to_block::<Test>(current_block + 1, H256::random());
        run_to_block::<Test>(current_block + 2, H256::random());

        // Run to the next block after the 2 upgrades
        run_to_block::<Test>(current_block + 3, H256::random());
        assert_eq!(HeadDomainNumber::<Test>::get(domain_id), 0);
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(2));

        // Submit a bundle after the upgrades, the domain chain should grow by 3 as 2 domain blocks
        // created for the 2 upgrades and 1 domain block created for the bundle
        let genesis_receipt = get_block_tree_node_at::<Test>(domain_id, 0)
            .unwrap()
            .execution_receipt;
        let bundle_extrinsics_root = H256::random();
        let bundle = create_dummy_bundle_with_receipts(
            domain_id,
            operator_id,
            bundle_extrinsics_root,
            genesis_receipt.clone(),
        );
        assert_ok!(crate::Pallet::<Test>::submit_bundle(
            DomainOrigin::ValidatedUnsigned.into(),
            bundle,
        ));
        assert_eq!(HeadReceiptNumber::<Test>::get(domain_id), 0);
        assert_eq!(HeadDomainNumber::<Test>::get(domain_id), 3);
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(0));

        // Submit bundle that carry the receipt of the domain runtime upgrade block
        let mut parent_receipt = genesis_receipt;
        for i in 1..=2 {
            run_to_block::<Test>(current_block + 3 + i, H256::random());
            let next_receipt = create_dummy_receipt(
                current_block + i,
                frame_system::Pallet::<Test>::block_hash(current_block + i),
                parent_receipt.hash::<DomainHashingFor<Test>>(),
                // empty `bundle_extrinsics_root` since these blocks doesn't contain bundle
                vec![],
            );
            // These receipt must able to pass `verify_execution_receipt`
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &next_receipt.as_execution_receipt_ref()
            ));
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id,
                H256::random(),
                next_receipt.clone(),
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                DomainOrigin::ValidatedUnsigned.into(),
                bundle,
            ));
            parent_receipt = next_receipt;
        }
        assert_eq!(HeadReceiptNumber::<Test>::get(domain_id), 2);
        // The gap between `HeadDomainNumber` and `HeadReceiptNumber` is increased from 1 to 3 as
        // there are 2 domain blocks doesn't contain bundle
        assert_eq!(
            HeadDomainNumber::<Test>::get(domain_id) - HeadReceiptNumber::<Test>::get(domain_id),
            3
        );

        // Schedule another domain runtime upgrade that will happen in a block that also contains bundle
        schedule_domain_runtime_upgrade::<Test>(runtime_id, current_block + 6);
        run_to_block::<Test>(current_block + 6, H256::random());
        let next_receipt = create_dummy_receipt(
            current_block + 3,
            frame_system::Pallet::<Test>::block_hash(current_block + 3),
            parent_receipt.hash::<DomainHashingFor<Test>>(),
            vec![bundle_extrinsics_root],
        );
        assert_ok!(verify_execution_receipt::<Test>(
            domain_id,
            &next_receipt.as_execution_receipt_ref()
        ));
        let bundle =
            create_dummy_bundle_with_receipts(domain_id, operator_id, H256::random(), next_receipt);
        assert_ok!(crate::Pallet::<Test>::submit_bundle(
            DomainOrigin::ValidatedUnsigned.into(),
            bundle,
        ));

        // Since the new domain block contains both runtime upgrade and bundle, the gap between `HeadDomainNumber`
        // and `HeadReceiptNumber` remain the same and there is no `missed_domain_runtime_upgrade`
        run_to_block::<Test>(current_block + 7, H256::random());
        assert!(
            DomainRuntimeUpgradeRecords::<Test>::get(runtime_id).contains_key(&(current_block + 6))
        );
        assert_eq!(Domains::missed_domain_runtime_upgrade(domain_id), Ok(0));
        assert_eq!(HeadReceiptNumber::<Test>::get(domain_id), 3);
        assert_eq!(
            HeadDomainNumber::<Test>::get(domain_id) - HeadReceiptNumber::<Test>::get(domain_id),
            3
        );
    });
}

#[test]
fn test_type_with_default_nonce_encode() {
    #[derive(Debug, TypeInfo)]
    pub struct DefaultNonceProvider;

    impl Get<Nonce> for DefaultNonceProvider {
        fn get() -> Nonce {
            13452234
        }
    }

    let nonce_1_default = 0;
    let nonce_2_default = TypeWithDefault::<Nonce, DefaultNonceProvider>::min_value();
    let encode_1 = nonce_1_default.encode();
    let encode_2 = nonce_2_default.encode();
    assert_eq!(encode_1, encode_2);

    let nonce_1_default = 13452234;
    let nonce_2_default = TypeWithDefault::<Nonce, DefaultNonceProvider>::default();
    let encode_1 = nonce_1_default.encode();
    let encode_2 = nonce_2_default.encode();
    assert_eq!(encode_1, encode_2);

    let nonce_1 = Nonce::MAX;
    let nonce_2 = TypeWithDefault::<Nonce, DefaultNonceProvider>::max_value();
    let encode_1 = nonce_1.encode();
    let encode_2 = nonce_2.encode();
    assert_eq!(encode_1, encode_2);
}

/// Returns mock upgrades.
/// (block_number, current_version)
/// block_number: Consensus block at which `set_code` is executed
/// current_version: Version at the time `set_code` is executed.
/// Code is upgraded from block_number + 1 and any new version from new runtime is considered
/// from that point which is block_number + 1
/// until block_number, previous runtime's version is valid.
fn get_mock_upgrades() -> Vec<(u32, MockBundleAndExecutionReceiptVersion, bool)> {
    vec![
        // version from 0..100
        (
            100u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V0,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
            // this version at this block must exist due to the change in version
            // in the next upgrade
            true,
        ),
        // version change
        // version from 101..121
        (
            121u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
            // this version at this block will not exist since next upgrade
            // carries same version
            false,
        ),
        // same version as previous
        // version from 122..130
        (
            130u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
            // this version at this block must exist due to the change in version
            // in the next upgrade
            true,
        ),
        // version change
        // version from 131..150
        (
            150u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
            // this version at this block will not exist since next upgrade
            // carries same version
            false,
        ),
        // same version as previous
        // version from 151..155
        (
            155u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
            // this version at this block must exist due to the change in version
            // in the next upgrade
            true,
        ),
        // version change
        // version from 156..160
        (
            160u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
            // this version at this block must exist due to the change in version
            // in the next upgrade
            true,
        ),
        // version change
        // version from 161..200
        (
            200u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
            // this version at this block will not exist since next upgrade
            // carries same version
            false,
        ),
        // same version
        // version from 201..250
        (
            250u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
            // this version at this block will not exist since next upgrade
            // carries same version
            false,
        ),
        // same version
        // version from 251..300
        (
            300u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
            // this version at this block must exist due to the change in version
            // in the next upgrade
            true,
        ),
    ]
}

fn get_mock_version_queries() -> Vec<(u32, MockBundleAndExecutionReceiptVersion)> {
    vec![
        // version from 0..100
        (
            90u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V0,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
        ),
        (
            100u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V0,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
        ),
        // version change
        // version from 101..130
        (
            101u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
        ),
        (
            121u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
        ),
        (
            130u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V0,
            },
        ),
        // version change
        // version from 131..155
        (
            131u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
        ),
        (
            155u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V1,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
        ),
        // version change
        // version from 156..160
        (
            156u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
        ),
        (
            160u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V1,
            },
        ),
        // version change
        // version from 161..300
        (
            161u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
        ),
        (
            250u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
        ),
        (
            300u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V2,
                execution_receipt_version: MockExecutionReceiptVersion::V2,
            },
        ),
        // version from >= 301
        (
            301u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V3,
                execution_receipt_version: MockExecutionReceiptVersion::V3,
            },
        ),
        (
            500u32,
            MockBundleAndExecutionReceiptVersion {
                bundle_version: MockBundleVersion::V3,
                execution_receipt_version: MockExecutionReceiptVersion::V3,
            },
        ),
    ]
}

#[test]
fn test_version_store_and_get() {
    let mut ext = new_test_ext_with_extensions();

    let upgrades = get_mock_upgrades();
    ext.execute_with(|| {
        for (upgraded_at, current_version, _) in upgrades.clone() {
            Domains::set_previous_bundle_and_execution_receipt_version(
                upgraded_at,
                MockPreviousBundleAndExecutionReceiptVersions::<Test>::set,
                MockPreviousBundleAndExecutionReceiptVersions::<Test>::get,
                current_version,
            );
        }

        let versions = MockPreviousBundleAndExecutionReceiptVersions::<Test>::get();
        // There should be a total of 5 entries in the set
        assert_eq!(versions.len(), 5);

        for (upgraded_at, version, exists) in upgrades {
            match versions.get(&upgraded_at) {
                None => assert!(!exists),
                Some(stored_version) => {
                    assert!(exists);
                    assert_eq!(version, stored_version.clone());
                }
            }
        }

        // now to test queries for version at any block
        // 0..100 should have (V0, V0)
        // 101..130 should have (V1, V0)
        // 131..155 should have (V1, V1)
        // 156..160 should have (V2, V1)
        // 161..300 should have (V2, V2)
        // >= 301 should have (V3, V3)
        let current_version = MockBundleAndExecutionReceiptVersion {
            bundle_version: MockBundleVersion::V3,
            execution_receipt_version: MockExecutionReceiptVersion::V3,
        };
        for (number, expected_version) in get_mock_version_queries() {
            let got_version = Domains::bundle_and_execution_receipt_version_for_consensus_number(
                number,
                MockPreviousBundleAndExecutionReceiptVersions::<Test>::get,
                current_version,
            )
            .unwrap();
            assert_eq!(expected_version, got_version);
        }
    })
}

/// Test to generate fixtures for the benchmarks
/// - validate_submit_bundle
/// - validate_singleton_receipt
///
/// Run the test, replace old signatures with new ones
/// - proof of election vrf signatures
/// - bundle signature
/// - singleton receipt signature
#[test]
fn generate_fixtures_for_benchmarking() {
    let domain_id = DomainId::new(0);
    let operator_id = 0;
    let keystore = MemoryKeystore::new();
    let signing_key = keystore
        .sr25519_generate_new(OperatorPair::ID, Some("//Alice"))
        .unwrap();
    let (proof_of_time, slot) = (PotOutput::default(), Slot::from(1));
    let global_challenge = proof_of_time
        .derive_global_randomness()
        .derive_global_challenge(slot.into());
    let vrf_sign_data = make_transcript(DomainId::new(0), &global_challenge).into_sign_data();
    let poe_signature = keystore
        .sr25519_vrf_sign(OperatorPair::ID, &signing_key, &vrf_sign_data)
        .unwrap()
        .unwrap();

    let poe = ProofOfElection {
        domain_id,
        slot_number: slot.into(),
        proof_of_time,
        vrf_signature: poe_signature.clone(),
        operator_id,
    };

    let mock_genesis_er_hash = H256::from_slice(
        hex!("5207cc85cfd1f53e11f4b9e85bf2d0a4f33e24d0f0f18b818b935a6aa47d3930").as_slice(),
    );

    let trace: Vec<<Test as Config>::DomainHash> = vec![
        H256::repeat_byte(1),
        H256::repeat_byte(2),
        H256::repeat_byte(3),
    ];
    let execution_trace_root = {
        let trace: Vec<_> = trace
            .iter()
            .map(|t| t.encode().try_into().unwrap())
            .collect();
        MerkleTree::from_leaves(trace.as_slice())
            .root()
            .unwrap()
            .into()
    };
    let er = ExecutionReceipt::V0(ExecutionReceiptV0::<u32, H256, u32, H256, u128> {
        domain_block_number: One::one(),
        domain_block_hash: H256::repeat_byte(7),
        domain_block_extrinsic_root: EMPTY_EXTRINSIC_ROOT,
        parent_domain_block_receipt_hash: mock_genesis_er_hash,
        consensus_block_number: One::one(),
        consensus_block_hash: H256::repeat_byte(9),
        inboxed_bundles: vec![],
        final_state_root: trace[2],
        execution_trace: trace,
        execution_trace_root,
        block_fees: Default::default(),
        transfers: Default::default(),
    });

    let header = BundleHeaderV0::<u32, H256, DomainHeader, Balance> {
        proof_of_election: poe.clone(),
        receipt: er.clone(),
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root: EMPTY_EXTRINSIC_ROOT,
    };

    let to_sign: H256 = header.hash();
    let signature = keystore
        .sr25519_sign(OperatorPair::ID, &signing_key, to_sign.as_ref())
        .unwrap()
        .unwrap();

    let bundle_signature = OperatorSignature::decode(&mut signature.as_ref()).unwrap();

    // generate signatures for singleton ER
    let singleton_receipt = SingletonReceipt::<u32, H256, DomainHeader, Balance> {
        proof_of_election: poe,
        receipt: er,
    };

    let to_sign: BlockHashFor<Block> = singleton_receipt.hash();
    let signature = keystore
        .sr25519_sign(OperatorPair::ID, &signing_key, to_sign.as_ref())
        .unwrap()
        .unwrap();

    let er_signature = OperatorSignature::decode(&mut signature.as_ref()).unwrap();

    _ = (poe_signature, bundle_signature, er_signature);
}
