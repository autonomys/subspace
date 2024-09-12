use crate::{self as pallet_history_seeding, Error};
use frame_support::traits::BuildGenesisConfig;
use frame_support::{assert_noop, assert_ok, construct_runtime, derive_impl};
use frame_system as system;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
    pub struct Test {
        System: frame_system,
        HistorySeeding: pallet_history_seeding,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_history_seeding::Config for Test {
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    t.into()
}

#[test]
fn genesis_config_works() {
    new_test_ext().execute_with(|| {
        let genesis_config = pallet_history_seeding::GenesisConfig::<Test> {
            history_seeder: Some(1),
        };
        genesis_config.build();
        assert_eq!(HistorySeeding::history_seeder(), Some(1));
    });
}

#[test]
fn set_history_seeder_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(HistorySeeding::set_history_seeder(RuntimeOrigin::root(), 1));
        assert_eq!(HistorySeeding::history_seeder(), Some(1));

        // Ensure only root can set the history seeder
        assert_noop!(
            HistorySeeding::set_history_seeder(RuntimeOrigin::signed(1), 2),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn seed_history_works() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        // Set the history seeder
        assert_ok!(HistorySeeding::set_history_seeder(RuntimeOrigin::root(), 1));

        // Seed history
        let remark = vec![1, 2, 3];
        assert_ok!(HistorySeeding::seed_history(
            RuntimeOrigin::signed(1),
            remark.clone()
        ));

        // Ensure unauthorized account cannot seed history
        assert_noop!(
            HistorySeeding::seed_history(RuntimeOrigin::signed(2), remark),
            Error::<Test>::NotAuthorized
        );
    });
}

#[test]
fn seed_history_fails_when_no_seeder_set() {
    new_test_ext().execute_with(|| {
        let remark = vec![1, 2, 3];
        assert_noop!(
            HistorySeeding::seed_history(RuntimeOrigin::signed(1), remark.clone()),
            Error::<Test>::NotAuthorized
        );
        assert_noop!(
            HistorySeeding::seed_history(RuntimeOrigin::root(), remark),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}
