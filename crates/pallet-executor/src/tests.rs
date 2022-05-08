use crate::{self as pallet_executor, Error, Receipts, ReceiptsRange};
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
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (1, 257));

        assert!(Receipts::<Test>::get(257).is_none());
        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[256].clone(),
        ));
        // Delete the old ER.
        assert!(Receipts::<Test>::get(1).is_none());
        assert!(Receipts::<Test>::get(257).is_some());
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (2, 258));

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
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (3, 259));
    });
}

#[test]
fn set_new_receipts_pruning_depth_should_work() {
    let dummy_receipts = (1..=1280)
        .map(|i| create_dummy_receipt(i))
        .collect::<Vec<_>>();

    new_test_ext().execute_with(|| {
        (0..256).for_each(|index| {
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index].clone(),
            ));
        });

        // Set a smaller pruning depth.
        assert_ok!(Executor::set_receipts_pruning_depth(Origin::root(), 128));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[256].clone(),
        ));
        assert!(Receipts::<Test>::get(129).is_none());
        assert!(Receipts::<Test>::get(130).is_some());
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (130, 258));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[257].clone(),
        ));
        assert!(Receipts::<Test>::get(130).is_none());
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (131, 259));

        // Set a larger pruning depth.
        assert_ok!(Executor::set_receipts_pruning_depth(Origin::root(), 1024));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[258].clone(),
        ));
        assert!(Receipts::<Test>::get(130).is_none());
        assert!(Receipts::<Test>::get(131).is_some());
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (131, 260));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[259].clone(),
        ));
        assert!(Receipts::<Test>::get(130).is_none());
        assert!(Receipts::<Test>::get(131).is_some());
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (131, 261));

        (260..1154).for_each(|index| {
            assert_ok!(Executor::submit_execution_receipt(
                Origin::none(),
                dummy_receipts[index].clone(),
            ));
        });
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (131, 1155));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[1154].clone(),
        ));
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (132, 1156));

        assert_ok!(Executor::submit_execution_receipt(
            Origin::none(),
            dummy_receipts[1155].clone(),
        ));
        assert_eq!(ReceiptsRange::<Test>::get().unwrap(), (133, 1157));
    });
}
