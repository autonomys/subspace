use crate::{self as pallet_executor, Error, Receipts};
use frame_support::{
    assert_noop, assert_ok,
    traits::{ConstU16, ConstU32, ConstU64, GenesisBuild},
};
use sp_core::{crypto::Pair, H256, U256};
use sp_executor::{ExecutionReceipt, ExecutorPair, SignedExecutionReceipt};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};

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

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
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

impl pallet_executor::Config for Test {
    type Event = Event;
    type SecondaryHash = H256;
    type ReceiptsPruningDepth = ConstU32<256>;
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

fn create_dummy_receipt(primary_number: u32) -> SignedExecutionReceipt<H256> {
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
    let dummy_receipts = (1..=256 + 3)
        .map(|i| create_dummy_receipt(i))
        .collect::<Vec<_>>();

    new_test_ext().execute_with(|| {
        (0..256).for_each(|index| {
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index].clone(),
            ));
        });

        assert!(Receipts::<Test>::get(257).is_none());
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[256].clone(),
        ));
        // The oldest ER should be deleted.
        assert!(Receipts::<Test>::get(1).is_none());
        assert!(Receipts::<Test>::get(257).is_some());

        assert!(Receipts::<Test>::get(2).is_some());
        assert!(Receipts::<Test>::get(258).is_none());
        assert_noop!(
            Executor::submit_execution_receipt(Origin::none(), dummy_receipts[258].clone(),),
            Error::<Test>::MissingParentReceipt
        );
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[257].clone(),
        ));
        assert!(Receipts::<Test>::get(2).is_none());
        assert!(Receipts::<Test>::get(258).is_some());
    });
}
