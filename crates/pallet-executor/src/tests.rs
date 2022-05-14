use crate::{
    self as pallet_executor, Error, ExecutionChainBestNumber, ExecutionReceiptError,
    OldestReceiptNumber, Receipts,
};
use frame_support::{
    assert_noop, assert_ok, parameter_types,
    traits::{ConstU16, ConstU32, ConstU64, GenesisBuild},
};
use sp_core::{crypto::Pair, H256, U256};
use sp_executor::{
    ExecutionPhase, ExecutionReceipt, ExecutorPair, FraudProof, SignedExecutionReceipt,
};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
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
    type BlockHashCount = ConstU64<10>;
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
) -> SignedExecutionReceipt<BlockNumber, Hash, H256> {
    let pair = ExecutorPair::from_seed(&U256::from(0u32).into());
    let signer = pair.public();

    let execution_receipt = ExecutionReceipt {
        primary_number,
        primary_hash: H256::random(),
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
        .map(create_dummy_receipt)
        .collect::<Vec<_>>();

    new_test_ext().execute_with(|| {
        (0..256).for_each(|index| {
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
            Executor::submit_execution_receipt(Origin::none(), dummy_receipts[258].clone(),),
            Error::<Test>::ExecutionReceipt(ExecutionReceiptError::MissingParent)
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
fn submit_fraud_proof_should_work() {
    let dummy_receipts = (1u64..=256u64)
        .map(create_dummy_receipt)
        .collect::<Vec<_>>();

    let dummy_proof = FraudProof {
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
