use crate::block_tree::{BlockTreeNode, verify_execution_receipt};
use crate::domain_registry::{DomainConfig, DomainConfigParams, DomainObject};
use crate::pallet::OperatorIdOwner;
use crate::runtime_registry::ScheduledRuntimeUpgrade;
use crate::staking::Operator;
use crate::{
    self as pallet_domains, BalanceOf, BlockSlot, BlockTree, BlockTreeNodes, BundleError, Config,
    ConsensusBlockHash, DomainBlockNumberFor, DomainHashingFor, DomainRegistry,
    DomainRuntimeUpgradeRecords, DomainRuntimeUpgrades, ExecutionInbox, ExecutionReceiptOf,
    FraudProofError, FungibleHoldId, HeadDomainNumber, HeadReceiptNumber, NextDomainId, Operators,
    RawOrigin as DomainOrigin, RuntimeRegistry, ScheduledRuntimeUpgrades,
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
use pallet_subspace::NormalEraChange;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::crypto::Pair;
use sp_core::{Get, H256};
use sp_domains::bundle::bundle_v1::{BundleHeaderV1, BundleV1, SealedBundleHeaderV1};
use sp_domains::bundle::{BundleVersion, InboxedBundle, OpaqueBundle};
use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use sp_domains::execution_receipt::{ExecutionReceipt, ExecutionReceiptVersion};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::storage::RawGenesis;
use sp_domains::{
    BundleAndExecutionReceiptVersion, ChainId, DomainId, OperatorAllowList, OperatorId,
    OperatorPair, ProofOfElection, RuntimeId, RuntimeType,
};
use sp_domains_fraud_proof::fraud_proof::fraud_proof_v1::FraudProofV1;
use sp_runtime::generic::{EXTRINSIC_FORMAT_VERSION, Preamble};
use sp_runtime::traits::{
    AccountIdConversion, BlakeTwo256, BlockNumberProvider, Bounded, ConstU16, Hash as HashT,
    IdentityLookup, One, Zero,
};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::type_with_default::TypeWithDefault;
use sp_runtime::{BuildStorage, OpaqueExtrinsic};
use sp_std::sync::atomic::{AtomicU8, Ordering};
use sp_version::{ApiId, RuntimeVersion, create_apis_vec};
use std::num::NonZeroU64;
use std::ops::Range;
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::segments::HistorySize;
use subspace_core_primitives::solutions::SolutionRange;
use subspace_core_primitives::{SlotNumber, U256 as P256};
use subspace_runtime_primitives::{
    AI3, ConsensusEventSegmentSize, HoldIdentifier, Moment, Nonce, OnSetCode, StorageFee,
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
        bundle_version: BundleVersion::V1,
        execution_receipt_version: ExecutionReceiptVersion::V0,
    };
}

static MOCK_BUNDLE_VERSION: AtomicU8 = AtomicU8::new(0);
static MOCK_ER_VERSION: AtomicU8 = AtomicU8::new(0);

pub struct MockCurrentBundleAndExecutionReceiptVersion;

impl Get<BundleAndExecutionReceiptVersion> for MockCurrentBundleAndExecutionReceiptVersion {
    fn get() -> BundleAndExecutionReceiptVersion {
        let bundle_version = match MOCK_BUNDLE_VERSION.load(Ordering::SeqCst) {
            0 => BundleVersion::V0,
            1 => BundleVersion::V1,
            _ => unreachable!(),
        };
        let execution_receipt_version = match MOCK_ER_VERSION.load(Ordering::SeqCst) {
            0 => ExecutionReceiptVersion::V0,
            1 => ExecutionReceiptVersion::V1,
            2 => ExecutionReceiptVersion::V2,
            _ => unreachable!(),
        };

        BundleAndExecutionReceiptVersion {
            bundle_version,
            execution_receipt_version,
        }
    }
}

impl MockCurrentBundleAndExecutionReceiptVersion {
    fn set_bundle_version(new_version: u8) {
        MOCK_BUNDLE_VERSION.store(new_version, Ordering::SeqCst)
    }
    fn set_er_version(new_version: u8) {
        MOCK_ER_VERSION.store(new_version, Ordering::SeqCst)
    }
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
    type CurrentBundleAndExecutionReceiptVersion = MockCurrentBundleAndExecutionReceiptVersion;
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

    let header = BundleHeaderV1::<_, _, DomainHeader, _> {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root,
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle::V1(BundleV1 {
        sealed_header: SealedBundleHeaderV1::new(header, signature),
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

pub(crate) fn register_genesis_domain(creator: u128, operator_ids: Vec<OperatorId>) -> DomainId {
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
    for operator_id in operator_ids {
        Operators::<Test>::insert(operator_id, Operator::dummy(domain_id, pair.public(), AI3));
        OperatorIdOwner::<Test>::insert(operator_id, creator);
    }

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
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
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
        let fraud_proof = FraudProofV1::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::ChallengingGenesisReceipt)
        );

        // Fraud proof target unknown ER is invalid
        let bad_receipt_hash = H256::random();
        let fraud_proof = FraudProofV1::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::BadReceiptNotFound)
        );
    });
}

#[test]
fn test_basic_fraud_proof_processing() {
    let creator = 0u128;
    let malicious_operator = 1u64;
    let honest_operator = 2u64;
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
            let domain_id =
                register_genesis_domain(creator, vec![malicious_operator, honest_operator]);
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
            let fraud_proof = FraudProofV1::dummy_fraud_proof(domain_id, bad_receipt_hash);
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
    let operator_id = 1u64;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
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
    let operator_id = 1u64;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
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

#[test]
fn test_bundle_and_er_version_store_and_get() {
    new_test_ext_with_extensions().execute_with(|| {
        assert_eq!(
            <Test as Config>::CurrentBundleAndExecutionReceiptVersion::get(),
            BundleAndExecutionReceiptVersion {
                bundle_version: BundleVersion::V0,
                execution_receipt_version: ExecutionReceiptVersion::V0,
            }
        );
        let expected_er_version_in_range = [(0u32..10u32, ExecutionReceiptVersion::V0)];
        for (range, version) in expected_er_version_in_range {
            for block_number in range {
                assert_eq!(
                    Domains::execution_receipt_version_for_consensus_number(block_number.into())
                        .unwrap(),
                    version,
                );
            }
        }

        // Update bundle version to V1 in block #10
        MockCurrentBundleAndExecutionReceiptVersion::set_bundle_version(1);
        Domains::set_code(10u32.into()).unwrap();
        assert_eq!(
            <Test as Config>::CurrentBundleAndExecutionReceiptVersion::get(),
            BundleAndExecutionReceiptVersion {
                bundle_version: BundleVersion::V1,
                execution_receipt_version: ExecutionReceiptVersion::V0,
            }
        );
        let expected_er_version_in_range = [
            (0u32..10u32, ExecutionReceiptVersion::V0),
            (10u32..20u32, ExecutionReceiptVersion::V0),
        ];
        for (range, version) in expected_er_version_in_range {
            for block_number in range {
                assert_eq!(
                    Domains::execution_receipt_version_for_consensus_number(block_number.into())
                        .unwrap(),
                    version,
                );
            }
        }

        // Update ER version to V1 in block #20
        MockCurrentBundleAndExecutionReceiptVersion::set_er_version(1);
        Domains::set_code(20u32.into()).unwrap();
        assert_eq!(
            <Test as Config>::CurrentBundleAndExecutionReceiptVersion::get(),
            BundleAndExecutionReceiptVersion {
                bundle_version: BundleVersion::V1,
                execution_receipt_version: ExecutionReceiptVersion::V1,
            }
        );
        let expected_er_version_in_range = [
            (0u32..10u32, ExecutionReceiptVersion::V0),
            (10u32..20u32, ExecutionReceiptVersion::V0),
            (20u32..30u32, ExecutionReceiptVersion::V1),
        ];
        for (range, version) in expected_er_version_in_range {
            for block_number in range {
                assert_eq!(
                    Domains::execution_receipt_version_for_consensus_number(block_number.into())
                        .unwrap(),
                    version,
                );
            }
        }

        // Another upgrade at block #30 that doesn't change the bundle/ER version
        Domains::set_code(30u32.into()).unwrap();
        assert_eq!(
            <Test as Config>::CurrentBundleAndExecutionReceiptVersion::get(),
            BundleAndExecutionReceiptVersion {
                bundle_version: BundleVersion::V1,
                execution_receipt_version: ExecutionReceiptVersion::V1,
            }
        );
        let expected_er_version_in_range = [
            (0u32..10u32, ExecutionReceiptVersion::V0),
            (10u32..20u32, ExecutionReceiptVersion::V0),
            (20u32..30u32, ExecutionReceiptVersion::V1),
            (30u32..40u32, ExecutionReceiptVersion::V1),
        ];
        for (range, version) in expected_er_version_in_range {
            for block_number in range {
                assert_eq!(
                    Domains::execution_receipt_version_for_consensus_number(block_number.into())
                        .unwrap(),
                    version,
                );
            }
        }

        // Update ER version to V2 in block #40
        MockCurrentBundleAndExecutionReceiptVersion::set_er_version(2);
        Domains::set_code(40u32.into()).unwrap();
        assert_eq!(
            <Test as Config>::CurrentBundleAndExecutionReceiptVersion::get(),
            BundleAndExecutionReceiptVersion {
                bundle_version: BundleVersion::V1,
                execution_receipt_version: ExecutionReceiptVersion::V2,
            }
        );
        let expected_er_version_in_range = [
            (0u32..10u32, ExecutionReceiptVersion::V0),
            (10u32..20u32, ExecutionReceiptVersion::V0),
            (20u32..30u32, ExecutionReceiptVersion::V1),
            (30u32..40u32, ExecutionReceiptVersion::V1),
            (40u32..50u32, ExecutionReceiptVersion::V2),
        ];
        for (range, version) in expected_er_version_in_range {
            for block_number in range {
                assert_eq!(
                    Domains::execution_receipt_version_for_consensus_number(block_number.into())
                        .unwrap(),
                    version,
                );
            }
        }
    })
}
