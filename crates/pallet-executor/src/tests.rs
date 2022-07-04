use crate::{
    self as pallet_executor, BlockHash, ExecutionChainBestNumber, OldestReceiptNumber, Receipts,
};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, GenesisBuild, Hooks};
use frame_support::{assert_noop, assert_ok, parameter_types};
use sp_core::crypto::Pair;
use sp_core::{H256, U256};
use sp_executor::{
    ExecutionPhase, ExecutionReceipt, ExecutorPair, FraudProof, SignedExecutionReceipt,
};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup, ValidateUnsigned};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
use sp_trie::StorageProof;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Executor: pallet_executor,
    }
);

type BlockNumber = u64;
type Hash = H256;

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
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

impl pallet_executor::Config for Test {
    type Event = Event;
    type SecondaryHash = H256;
    type ReceiptsPruningDepth = ReceiptsPruningDepth;
    type MaximumReceiptDrift = MaximumReceiptDrift;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    pallet_executor::GenesisConfig::<Test> {
        executor: Some((
            100,
            ExecutorPair::from_seed(&U256::from(100u32).into()).public(),
        )),
    }
    .assimilate_storage(&mut t)
    .unwrap();

    t.into()
}

fn create_dummy_receipt(
    primary_number: BlockNumber,
    primary_hash: Hash,
) -> SignedExecutionReceipt<BlockNumber, Hash, H256> {
    let pair = ExecutorPair::from_seed(&U256::from(0u32).into());
    let signer = pair.public();

    let execution_receipt = ExecutionReceipt {
        primary_number,
        primary_hash,
        secondary_hash: H256::random(),
        trace: Vec::new(),
        trace_root: Default::default(),
    };

    let signature = pair.sign(execution_receipt.hash().as_ref());

    SignedExecutionReceipt {
        execution_receipt,
        signature,
        signer,
    }
}

#[test]
fn submit_execution_receipt_should_work() {
    let dummy_receipts = (1u64..=256u64 + 3u64)
        .map(|n| create_dummy_receipt(n, Hash::random()))
        .collect::<Vec<_>>();

    new_test_ext().execute_with(|| {
        (0..256).for_each(|index| {
            assert_ok!(pallet_executor::Pallet::<Test>::pre_dispatch(
                &pallet_executor::Call::submit_execution_receipt {
                    signed_execution_receipt: dummy_receipts[index].clone()
                }
            ));
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index].clone(),
            ));
            assert_eq!(OldestReceiptNumber::<Test>::get(), 1);
        });

        assert!(Receipts::<Test>::get(257).is_none());
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[256].clone(),
        ));
        // The oldest ER should be deleted.
        assert!(Receipts::<Test>::get(1).is_none());
        assert_eq!(OldestReceiptNumber::<Test>::get(), 2);
        assert!(Receipts::<Test>::get(257).is_some());

        assert!(Receipts::<Test>::get(2).is_some());
        assert!(Receipts::<Test>::get(258).is_none());

        assert_noop!(
            pallet_executor::Pallet::<Test>::pre_dispatch(
                &pallet_executor::Call::submit_execution_receipt {
                    signed_execution_receipt: dummy_receipts[258].clone()
                }
            ),
            TransactionValidityError::Invalid(InvalidTransaction::Future)
        );

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[257].clone(),
        ));
        assert!(Receipts::<Test>::get(2).is_none());
        assert_eq!(OldestReceiptNumber::<Test>::get(), 3);
        assert!(Receipts::<Test>::get(258).is_some());
    });
}

#[test]
fn submit_execution_receipt_with_huge_gap_should_work() {
    let (dummy_receipts, block_hashes): (Vec<_>, Vec<_>) = (1u64..=256u64 + 2)
        .map(|n| {
            let primary_hash = Hash::random();
            (create_dummy_receipt(n, primary_hash), primary_hash)
        })
        .unzip();

    let run_to_block = |n: BlockNumber, block_hashes: Vec<Hash>| {
        System::set_block_number(1);
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Executor as Hooks<BlockNumber>>::on_initialize(1);
        System::finalize();

        for b in 2..=n {
            System::set_block_number(b);
            System::initialize(&b, &block_hashes[b as usize - 2], &Default::default());
            <Executor as Hooks<BlockNumber>>::on_initialize(b);
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
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index].clone(),
            ));
        });

        // Reaching the receipts pruning depth, block hash mapping will be pruned as well.
        assert!(BlockHash::<Test>::contains_key(0));
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[255].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(0));

        assert!(BlockHash::<Test>::contains_key(1));
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[256].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(1));

        assert!(BlockHash::<Test>::contains_key(2));
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[257].clone(),
        ));
        assert!(!BlockHash::<Test>::contains_key(2));
        assert_eq!(OldestReceiptNumber::<Test>::get(), 3);
    });
}

#[test]
fn submit_fraud_proof_should_work() {
    let dummy_receipts = (1u64..=256u64)
        .map(|n| create_dummy_receipt(n, Hash::random()))
        .collect::<Vec<_>>();

    let dummy_proof = FraudProof {
        bad_signed_receipt_hash: Hash::random(),
        parent_number: 99,
        parent_hash: H256::random(),
        pre_state_root: H256::random(),
        post_state_root: H256::random(),
        proof: StorageProof::empty(),
        execution_phase: ExecutionPhase::FinalizeBlock,
    };

    new_test_ext().execute_with(|| {
        (0u64..256u64).for_each(|index| {
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index as usize].clone(),
            ));
            assert!(Receipts::<Test>::get(index + 1).is_some());
        });

        assert_ok!(Executor::submit_fraud_proof(Origin::none(), dummy_proof));
        assert_eq!(<ExecutionChainBestNumber<Test>>::get(), 99);
        assert!(Receipts::<Test>::get(99).is_some());
        // Receipts for block [100, 256] should be removed as being invalid.
        (100..=256).for_each(|block_number| {
            assert!(Receipts::<Test>::get(block_number).is_none());
        });
    });
}
