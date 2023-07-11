use crate::{self as pallet_domains, FungibleFreezeId};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Hooks};
use frame_support::weights::Weight;
use scale_info::TypeInfo;
use sp_core::crypto::Pair;
use sp_core::{Get, H256, U256};
use sp_domains::v2::{BundleHeader, ExecutionReceipt, OpaqueBundle, SealedBundleHeader};
use sp_domains::{
    BundleSolution, DomainId, DomainsFreezeIdentifier, GenerateGenesisStateRoot, OperatorId,
    OperatorPair, RuntimeType,
};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use std::sync::atomic::{AtomicU64, Ordering};
use subspace_core_primitives::U256 as P256;
use subspace_runtime_primitives::SSC;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type Balance = u128;

// TODO: Remove when DomainRegistry is usable.
const DOMAIN_ID: DomainId = DomainId::new(0);

// Operator id used for testing
const OPERATOR_ID: OperatorId = 0u64;

frame_support::construct_runtime!(
    pub struct Test
    where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Balances: pallet_balances,
        Domains: pallet_domains,
    }
);

type BlockNumber = u64;
type Hash = H256;

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<2>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const MaximumReceiptDrift: BlockNumber = 128;
    pub const InitialDomainTxRange: u64 = 10;
    pub const DomainTxRangeAdjustmentInterval: u64 = 100;
    pub const ExpectedBundlesPerInterval: u64 = 600;
    pub const DomainRuntimeUpgradeDelay: BlockNumber = 100;
    pub const MaxBundlesPerBlock: u32 = 10;
    pub const MaxDomainBlockSize: u32 = 1024 * 1024;
    pub const MaxDomainBlockWeight: Weight = Weight::from_parts(1024 * 1024, 0);
    pub const DomainInstantiationDeposit: Balance = 100;
    pub const MaxDomainNameLength: u32 = 16;
    pub const BlockTreePruningDepth: u32 = 256;
}

static CONFIRMATION_DEPTH_K: AtomicU64 = AtomicU64::new(10);

pub struct ConfirmationDepthK;

impl ConfirmationDepthK {
    fn set(new: BlockNumber) {
        CONFIRMATION_DEPTH_K.store(new, Ordering::SeqCst);
    }

    fn get() -> BlockNumber {
        CONFIRMATION_DEPTH_K.load(Ordering::SeqCst)
    }
}

impl Get<BlockNumber> for ConfirmationDepthK {
    fn get() -> BlockNumber {
        Self::get()
    }
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum FreezeIdentifier {
    Domains(DomainsFreezeIdentifier),
}

impl pallet_domains::FreezeIdentifier<Test> for FreezeIdentifier {
    fn staking_freeze_id(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsFreezeIdentifier::Staking(operator_id))
    }

    fn domain_instantiation_id(domain_id: DomainId) -> FungibleFreezeId<Test> {
        Self::Domains(DomainsFreezeIdentifier::DomainInstantiation(domain_id))
    }
}

parameter_types! {
    pub const MaxFreezes: u32 = 10;
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = FreezeIdentifier;
    type MaxFreezes = MaxFreezes;
    type RuntimeHoldReason = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const MinOperatorStake: Balance = 100 * SSC;
}

impl pallet_domains::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DomainNumber = BlockNumber;
    type DomainHash = sp_core::H256;
    type ConfirmationDepthK = ConfirmationDepthK;
    type DomainRuntimeUpgradeDelay = DomainRuntimeUpgradeDelay;
    type Currency = Balances;
    type FreezeIdentifier = FreezeIdentifier;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Test>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type ExpectedBundlesPerInterval = ExpectedBundlesPerInterval;
    type MinOperatorStake = MinOperatorStake;
    type MaxDomainBlockSize = MaxDomainBlockSize;
    type MaxDomainBlockWeight = MaxDomainBlockWeight;
    type MaxBundlesPerBlock = MaxBundlesPerBlock;
    type DomainInstantiationDeposit = DomainInstantiationDeposit;
    type MaxDomainNameLength = MaxDomainNameLength;
    type Share = Balance;
    type BlockTreePruningDepth = BlockTreePruningDepth;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    t.into()
}

pub(crate) fn create_dummy_receipt(
    block_number: BlockNumber,
    consensus_block_hash: Hash,
    parent_domain_block_receipt_hash: H256,
    block_extrinsics_roots: Vec<H256>,
) -> ExecutionReceipt<BlockNumber, Hash, BlockNumber, H256, u128> {
    ExecutionReceipt {
        domain_block_number: block_number,
        parent_domain_block_receipt_hash,
        consensus_block_number: block_number,
        consensus_block_hash,
        block_extrinsics_roots,
        final_state_root: Default::default(),
        execution_trace_root: Default::default(),
        total_rewards: 0,
    }
}

fn create_dummy_bundle(
    domain_id: DomainId,
    block_number: BlockNumber,
    consensus_block_hash: Hash,
) -> OpaqueBundle<BlockNumber, Hash, BlockNumber, H256, u128> {
    let execution_receipt = create_dummy_receipt(
        block_number,
        consensus_block_hash,
        Default::default(),
        vec![],
    );
    create_dummy_bundle_with_receipts(
        domain_id,
        block_number,
        OPERATOR_ID,
        Default::default(),
        execution_receipt,
    )
}

pub(crate) fn create_dummy_bundle_with_receipts(
    domain_id: DomainId,
    block_number: BlockNumber,
    operator_id: OperatorId,
    bundle_extrinsics_root: H256,
    receipt: ExecutionReceipt<BlockNumber, Hash, BlockNumber, H256, u128>,
) -> OpaqueBundle<BlockNumber, Hash, BlockNumber, H256, u128> {
    let pair = OperatorPair::from_seed(&U256::from(0u32).into());

    let header = BundleHeader {
        operator_id,
        consensus_block_number: block_number,
        bundle_solution: BundleSolution::dummy(domain_id, pair.public()),
        receipt,
        bundle_size: 0u32,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root,
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle {
        sealed_header: SealedBundleHeader::new(header, signature),
        extrinsics: Vec::new(),
        execution_trace: if block_number == 0 {
            Vec::new()
        } else {
            vec![H256::random(), H256::random()]
        },
    }
}

pub(crate) struct GenesisStateRootGenerater;

impl GenerateGenesisStateRoot for GenesisStateRootGenerater {
    fn generate_genesis_state_root(
        &self,
        _runtime_type: RuntimeType,
        _runtime_code: Vec<u8>,
    ) -> Option<H256> {
        Some(Default::default())
    }
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

#[test]
fn test_stale_bundle_should_be_rejected() {
    // Small macro in order to be more readable.
    //
    // We only care about whether the error type is `StaleBundle`.
    macro_rules! assert_stale {
        ($validate_bundle_result:expr) => {
            assert_eq!(
                $validate_bundle_result,
                Err(pallet_domains::BundleError::StaleBundle)
            )
        };
    }

    macro_rules! assert_not_stale {
        ($validate_bundle_result:expr) => {
            assert_ne!(
                $validate_bundle_result,
                Err(pallet_domains::BundleError::StaleBundle)
            )
        };
    }

    ConfirmationDepthK::set(1);
    new_test_ext().execute_with(|| {
        // Create a bundle at genesis block -> #1
        let bundle0 = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));

        // Create a bundle at block #1 -> #2
        let block_hash1 = Hash::random();
        let bundle1 = create_dummy_bundle(DOMAIN_ID, 1, block_hash1);
        System::initialize(&2, &block_hash1, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(2);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));
    });

    ConfirmationDepthK::set(2);
    new_test_ext().execute_with(|| {
        // Create a bundle at genesis block -> #1
        let bundle0 = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));

        // Create a bundle at block #1 -> #2
        let block_hash1 = Hash::random();
        let bundle1 = create_dummy_bundle(DOMAIN_ID, 1, block_hash1);
        System::initialize(&2, &block_hash1, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(2);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));

        // Create a bundle at block #2 -> #3
        let block_hash2 = Hash::random();
        let bundle2 = create_dummy_bundle(DOMAIN_ID, 2, block_hash2);
        System::initialize(&3, &block_hash2, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(3);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle2));
    });

    ConfirmationDepthK::set(10);
    let confirmation_depth_k = ConfirmationDepthK::get();
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1..=confirmation_depth_k + 2)
        .map(|n| {
            let consensus_block_hash = Hash::random();
            (
                create_dummy_bundle(DOMAIN_ID, n, consensus_block_hash),
                consensus_block_hash,
            )
        })
        .unzip();

    let run_to_block = |n: BlockNumber, block_hashes: Vec<Hash>| {
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        System::finalize();

        for b in 2..=n {
            System::set_block_number(b);
            System::initialize(&b, &block_hashes[b as usize - 2], &Default::default());
            <Domains as Hooks<BlockNumber>>::on_initialize(b);
            System::finalize();
        }
    };

    new_test_ext().execute_with(|| {
        run_to_block(confirmation_depth_k + 2, block_hashes);
        for bundle in dummy_bundles.iter().take(2) {
            assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(bundle));
        }
        for bundle in dummy_bundles.iter().skip(2) {
            assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(bundle));
        }
    });
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
