use crate::{self as pallet_domains};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Hooks};
use frame_support::{assert_ok, parameter_types};
use pallet_settlement::{PrimaryBlockHash, ReceiptVotes};
use sp_core::crypto::Pair;
use sp_core::{Get, H256, U256};
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::{
    create_dummy_bundle_with_receipts_generic, BundleHeader, BundleSolution, DomainId,
    ExecutionReceipt, ExecutorPair, OpaqueBundle, SealedBundleHeader,
};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_trie::StorageProof;
use std::sync::atomic::{AtomicU64, Ordering};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// TODO: Remove when DomainRegistry is usable.
const DOMAIN_ID: DomainId = DomainId::new(0);

frame_support::construct_runtime!(
    pub struct Test
    where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Settlement: pallet_settlement,
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
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const ReceiptsPruningDepth: BlockNumber = 256;
    pub const MaximumReceiptDrift: BlockNumber = 128;
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

impl pallet_domains::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ConfirmationDepthK = ConfirmationDepthK;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Test>;
}

impl pallet_settlement::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DomainHash = H256;
    type MaximumReceiptDrift = MaximumReceiptDrift;
    type ReceiptsPruningDepth = ReceiptsPruningDepth;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    t.into()
}

fn create_dummy_receipt(
    primary_number: BlockNumber,
    primary_hash: Hash,
) -> ExecutionReceipt<BlockNumber, Hash, H256> {
    ExecutionReceipt {
        primary_number,
        primary_hash,
        domain_hash: H256::random(),
        trace: if primary_number == 0 {
            Vec::new()
        } else {
            vec![H256::random(), H256::random()]
        },
        trace_root: Default::default(),
    }
}

fn create_dummy_bundle(
    domain_id: DomainId,
    primary_number: BlockNumber,
    primary_hash: Hash,
) -> OpaqueBundle<BlockNumber, Hash, H256> {
    let pair = ExecutorPair::from_seed(&U256::from(0u32).into());

    let execution_receipt = create_dummy_receipt(primary_number, primary_hash);

    let header = BundleHeader {
        primary_number,
        primary_hash,
        slot_number: 0u64,
        extrinsics_root: Default::default(),
        bundle_solution: BundleSolution::dummy(domain_id, pair.public()),
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle {
        sealed_header: SealedBundleHeader::new(header, signature),
        receipt: execution_receipt,
        extrinsics: Vec::new(),
    }
}

#[allow(dead_code)]
fn create_dummy_bundle_with_receipts(
    domain_id: DomainId,
    primary_number: BlockNumber,
    primary_hash: Hash,
    receipt: ExecutionReceipt<BlockNumber, Hash, H256>,
) -> OpaqueBundle<BlockNumber, Hash, H256> {
    create_dummy_bundle_with_receipts_generic::<BlockNumber, Hash, H256>(
        domain_id,
        primary_number,
        primary_hash,
        receipt,
    )
}

#[test]
fn submit_fraud_proof_should_work() {
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1u64..=256u64)
        .map(|n| {
            let primary_hash = Hash::random();
            (
                create_dummy_bundle(DOMAIN_ID, n, primary_hash),
                primary_hash,
            )
        })
        .unzip();

    let dummy_proof = |domain_id| {
        FraudProof::InvalidStateTransition(InvalidStateTransitionProof {
            domain_id,
            bad_receipt_hash: Hash::random(),
            parent_number: 99,
            primary_parent_hash: block_hashes[98],
            pre_state_root: H256::random(),
            post_state_root: H256::random(),
            proof: StorageProof::empty(),
            execution_phase: ExecutionPhase::FinalizeBlock {
                total_extrinsics: 0,
            },
        })
    };

    new_test_ext().execute_with(|| {
        (0usize..256usize).for_each(|index| {
            let block_hash = block_hashes[index];
            PrimaryBlockHash::<Test>::insert(DOMAIN_ID, (index + 1) as u64, block_hash);

            assert_ok!(Domains::submit_bundle(
                RuntimeOrigin::none(),
                dummy_bundles[index].clone(),
            ));

            let receipt_hash = dummy_bundles[index].clone().receipt.hash();
            assert!(Settlement::receipts(DOMAIN_ID, receipt_hash).is_some());
            let mut votes = ReceiptVotes::<Test>::iter_prefix((DOMAIN_ID, block_hash));
            assert_eq!(votes.next(), Some((receipt_hash, 1)));
            assert_eq!(votes.next(), None);
        });

        // non-system domain fraud proof should be ignored
        assert_ok!(Domains::submit_fraud_proof(
            RuntimeOrigin::none(),
            dummy_proof(DomainId::new(100))
        ));
        assert_eq!(Settlement::head_receipt_number(DOMAIN_ID), 256);
        let receipt_hash = dummy_bundles[255].clone().receipt.hash();
        assert!(Settlement::receipts(DOMAIN_ID, receipt_hash).is_some());

        assert_ok!(Domains::submit_fraud_proof(
            RuntimeOrigin::none(),
            dummy_proof(DOMAIN_ID)
        ));
        assert_eq!(Settlement::head_receipt_number(DOMAIN_ID), 99);
        let receipt_hash = dummy_bundles[98].clone().receipt.hash();
        assert!(Settlement::receipts(DOMAIN_ID, receipt_hash).is_some());
        // Receipts for block [100, 256] should be removed as being invalid.
        (100..=256).for_each(|block_number| {
            let receipt_hash = dummy_bundles[block_number as usize - 1]
                .clone()
                .receipt
                .hash();
            assert!(Settlement::receipts(DOMAIN_ID, receipt_hash).is_none());
            let block_hash = block_hashes[block_number as usize - 1];
            assert!(ReceiptVotes::<Test>::iter_prefix((DOMAIN_ID, block_hash))
                .next()
                .is_none());
        });
    });
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
            let primary_hash = Hash::random();
            (
                create_dummy_bundle(DOMAIN_ID, n, primary_hash),
                primary_hash,
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
