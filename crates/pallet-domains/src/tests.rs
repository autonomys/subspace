use crate::{self as pallet_domains, BlockHash, OldestReceiptNumber, ReceiptVotes, Receipts};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Hooks};
use frame_support::{assert_noop, assert_ok, parameter_types};
use sp_core::crypto::Pair;
use sp_core::{H256, U256};
use sp_domains::{
    Bundle, BundleHeader, ExecutionPhase, ExecutionReceipt, ExecutorPair, FraudProof,
    InvalidTransactionCode, ProofOfElection, SignedOpaqueBundle,
};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup, ValidateUnsigned};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_trie::StorageProof;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test
    where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
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
    pub const ConfirmationDepthK: u32 = 10;
}

impl pallet_domains::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type SecondaryHash = H256;
    type ReceiptsPruningDepth = ReceiptsPruningDepth;
    type MaximumReceiptDrift = MaximumReceiptDrift;
    type ConfirmationDepthK = ConfirmationDepthK;
}

fn new_test_ext() -> sp_io::TestExternalities {
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
        secondary_hash: H256::random(),
        trace: if primary_number == 0 {
            Vec::new()
        } else {
            vec![H256::random(), H256::random()]
        },
        trace_root: Default::default(),
    }
}

fn create_dummy_bundle(
    primary_number: BlockNumber,
    primary_hash: Hash,
) -> SignedOpaqueBundle<BlockNumber, Hash, H256> {
    let pair = ExecutorPair::from_seed(&U256::from(0u32).into());

    let execution_receipt = create_dummy_receipt(primary_number, primary_hash);

    let bundle = Bundle {
        header: BundleHeader {
            primary_hash,
            slot_number: 0u64,
            extrinsics_root: Default::default(),
        },
        receipts: vec![execution_receipt],
        extrinsics: Vec::new(),
    };

    let signature = pair.sign(bundle.hash().as_ref());

    SignedOpaqueBundle {
        bundle,
        proof_of_election: ProofOfElection::with_public_key(pair.public()),
        signature,
    }
}

fn create_dummy_bundle_with_receipts(
    primary_hash: Hash,
    receipts: Vec<ExecutionReceipt<BlockNumber, Hash, H256>>,
) -> SignedOpaqueBundle<BlockNumber, Hash, H256> {
    let pair = ExecutorPair::from_seed(&U256::from(0u32).into());

    let header = BundleHeader {
        primary_hash,
        slot_number: 0u64,
        extrinsics_root: Default::default(),
    };

    let bundle = Bundle {
        header,
        receipts,
        extrinsics: Vec::new(),
    };

    let signature = pair.sign(bundle.hash().as_ref());

    SignedOpaqueBundle {
        bundle,
        proof_of_election: ProofOfElection::with_public_key(pair.public()),
        signature,
    }
}

#[test]
fn submit_execution_receipt_incrementally_should_work() {
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1u64..=256u64 + 3u64)
        .map(|n| {
            let primary_hash = Hash::random();
            (create_dummy_bundle(n, primary_hash), primary_hash)
        })
        .unzip();

    let receipt_hash = |block_number| {
        dummy_bundles[block_number as usize - 1]
            .clone()
            .bundle
            .receipts[0]
            .hash()
    };

    new_test_ext().execute_with(|| {
        let genesis_hash = frame_system::Pallet::<Test>::block_hash(0);
        BlockHash::<Test>::insert(0, genesis_hash);
        Domains::initialize_genesis_receipt(genesis_hash);

        (0..256).for_each(|index| {
            let block_hash = block_hashes[index];
            BlockHash::<Test>::insert((index + 1) as u64, block_hash);

            assert_ok!(pallet_domains::Pallet::<Test>::pre_dispatch(
                &pallet_domains::Call::submit_bundle {
                    signed_opaque_bundle: dummy_bundles[index].clone()
                }
            ));
            assert_ok!(Domains::submit_bundle(
                RuntimeOrigin::none(),
                dummy_bundles[index].clone(),
            ));

            assert_eq!(Domains::finalized_receipt_number(), 0);
        });

        assert!(Receipts::<Test>::get(receipt_hash(257)).is_none());
        assert_ok!(Domains::submit_bundle(
            RuntimeOrigin::none(),
            dummy_bundles[256].clone(),
        ));
        // The oldest ER should be deleted.
        assert!(Receipts::<Test>::get(receipt_hash(1)).is_none());
        assert_eq!(Domains::finalized_receipt_number(), 1);
        assert!(Receipts::<Test>::get(receipt_hash(257)).is_some());

        assert!(Receipts::<Test>::get(receipt_hash(2)).is_some());
        assert!(Receipts::<Test>::get(receipt_hash(258)).is_none());

        assert_noop!(
            pallet_domains::Pallet::<Test>::pre_dispatch(&pallet_domains::Call::submit_bundle {
                signed_opaque_bundle: dummy_bundles[258].clone()
            }),
            TransactionValidityError::Invalid(InvalidTransactionCode::ExecutionReceipt.into())
        );

        assert_ok!(Domains::submit_bundle(
            RuntimeOrigin::none(),
            dummy_bundles[257].clone(),
        ));
        assert!(Receipts::<Test>::get(receipt_hash(2)).is_none());
        assert_eq!(Domains::finalized_receipt_number(), 2);
        assert!(Receipts::<Test>::get(receipt_hash(258)).is_some());
    });
}

#[test]
fn submit_execution_receipt_with_huge_gap_should_work() {
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1u64..=256u64 + 2)
        .map(|n| {
            let primary_hash = Hash::random();
            (create_dummy_bundle(n, primary_hash), primary_hash)
        })
        .unzip();

    let run_to_block = |n: BlockNumber, block_hashes: Vec<Hash>| {
        System::set_block_number(1);
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
        run_to_block(256 + 2, block_hashes);

        // Submit ancient receipts still works even the block hash mapping for [1, 256)
        // in System has been removed.
        assert!(!frame_system::BlockHash::<Test>::contains_key(1));
        assert!(!frame_system::BlockHash::<Test>::contains_key(255));
        (0..255).for_each(|index| {
            assert_ok!(Domains::submit_bundle(
                RuntimeOrigin::none(),
                dummy_bundles[index].clone(),
            ));
        });

        // Reaching the receipts pruning depth, block hash mapping will be pruned as well.
        assert!(BlockHash::<Test>::contains_key(0));
        assert_ok!(Domains::submit_bundle(
            RuntimeOrigin::none(),
            dummy_bundles[255].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(0));

        assert!(BlockHash::<Test>::contains_key(1));
        assert_ok!(Domains::submit_bundle(
            RuntimeOrigin::none(),
            dummy_bundles[256].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(1));

        assert!(BlockHash::<Test>::contains_key(2));
        assert_ok!(Domains::submit_bundle(
            RuntimeOrigin::none(),
            dummy_bundles[257].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(2));
        assert_eq!(Domains::finalized_receipt_number(), 2);
    });
}

#[test]
fn submit_bundle_with_many_reeipts_should_work() {
    let (receipts, mut block_hashes): (Vec<_>, Vec<_>) = (1u64..=255u64)
        .map(|n| {
            let primary_hash = Hash::random();
            (create_dummy_receipt(n, primary_hash), primary_hash)
        })
        .unzip();

    let primary_hash_255 = *block_hashes.last().unwrap();
    let bundle1 = create_dummy_bundle_with_receipts(primary_hash_255, receipts);

    let primary_hash_256 = Hash::random();
    block_hashes.push(primary_hash_256);
    let bundle2 = create_dummy_bundle(256, primary_hash_256);

    let primary_hash_257 = Hash::random();
    block_hashes.push(primary_hash_257);
    let bundle3 = create_dummy_bundle(257, primary_hash_257);

    let primary_hash_258 = Hash::random();
    block_hashes.push(primary_hash_258);
    let bundle4 = create_dummy_bundle(258, primary_hash_258);

    let run_to_block = |n: BlockNumber, block_hashes: Vec<Hash>| {
        System::set_block_number(1);
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
        run_to_block(256 + 2, block_hashes);

        // Submit ancient receipts still works even the block hash mapping for [1, 256)
        // in System has been removed.
        assert!(!frame_system::BlockHash::<Test>::contains_key(1));
        assert!(!frame_system::BlockHash::<Test>::contains_key(255));
        assert_ok!(Domains::submit_bundle(RuntimeOrigin::none(), bundle1));
        assert_eq!(Domains::best_execution_chain_number(), 255);

        // Reaching the receipts pruning depth, block hash mapping will be pruned as well.
        assert!(BlockHash::<Test>::contains_key(0));
        assert_ok!(Domains::submit_bundle(RuntimeOrigin::none(), bundle2));
        assert!(!BlockHash::<Test>::contains_key(0));
        assert_eq!(OldestReceiptNumber::<Test>::get(), 1);

        assert!(BlockHash::<Test>::contains_key(1));
        assert_ok!(Domains::submit_bundle(RuntimeOrigin::none(), bundle3));
        assert!(!BlockHash::<Test>::contains_key(1));
        assert_eq!(OldestReceiptNumber::<Test>::get(), 2);

        assert!(BlockHash::<Test>::contains_key(2));
        assert_ok!(Domains::submit_bundle(RuntimeOrigin::none(), bundle4));
        assert!(!BlockHash::<Test>::contains_key(2));
        assert_eq!(OldestReceiptNumber::<Test>::get(), 3);
        assert_eq!(Domains::finalized_receipt_number(), 2);
        assert_eq!(Domains::best_execution_chain_number(), 258);
    });
}

#[test]
fn submit_fraud_proof_should_work() {
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1u64..=256u64)
        .map(|n| {
            let primary_hash = Hash::random();
            (create_dummy_bundle(n, primary_hash), primary_hash)
        })
        .unzip();

    let dummy_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: 99,
        parent_hash: block_hashes[98],
        pre_state_root: H256::random(),
        post_state_root: H256::random(),
        proof: StorageProof::empty(),
        execution_phase: ExecutionPhase::FinalizeBlock,
    };

    new_test_ext().execute_with(|| {
        (0usize..256usize).for_each(|index| {
            let block_hash = block_hashes[index];
            BlockHash::<Test>::insert((index + 1) as u64, block_hash);

            assert_ok!(Domains::submit_bundle(
                RuntimeOrigin::none(),
                dummy_bundles[index].clone(),
            ));

            let receipt_hash = dummy_bundles[index].clone().bundle.receipts[0].hash();
            assert!(Receipts::<Test>::get(receipt_hash).is_some());
            let mut votes = ReceiptVotes::<Test>::iter_prefix(block_hash);
            assert_eq!(votes.next(), Some((receipt_hash, 1)));
            assert_eq!(votes.next(), None);
        });

        assert_ok!(Domains::submit_fraud_proof(
            RuntimeOrigin::none(),
            dummy_proof
        ));
        assert_eq!(Domains::best_execution_chain_number(), 99);
        let receipt_hash = dummy_bundles[98].clone().bundle.receipts[0].hash();
        assert!(Receipts::<Test>::get(receipt_hash).is_some());
        // Receipts for block [100, 256] should be removed as being invalid.
        (100..=256).for_each(|block_number| {
            let receipt_hash = dummy_bundles[block_number as usize - 1]
                .clone()
                .bundle
                .receipts[0]
                .hash();
            assert!(Receipts::<Test>::get(receipt_hash).is_none());
            let block_hash = block_hashes[block_number as usize - 1];
            assert!(ReceiptVotes::<Test>::iter_prefix(block_hash)
                .next()
                .is_none());
        });
    });
}
