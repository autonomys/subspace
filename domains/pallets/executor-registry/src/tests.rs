use crate::{
    self as pallet_executor_registry, Error, ExecutorConfig, Executors, KeyOwner,
    TotalActiveExecutors, TotalActiveStake, Withdrawal,
};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, GenesisBuild};
use frame_support::{assert_noop, assert_ok, bounded_vec, parameter_types};
use pallet_balances::AccountData;
use sp_core::crypto::Pair;
use sp_core::{H256, U256};
use sp_domains::{ExecutorPair, StakeWeight};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};

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
        Balances: pallet_balances,
        ExecutorRegistry: pallet_executor_registry,
    }
);

type AccountId = u64;
type BlockNumber = u64;
type Balance = u128;
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
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = ConstU64<2>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub static ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
}

parameter_types! {
    pub const MinExecutorStake: Balance = 10;
    pub const MaxExecutorStake: Balance = 1000;
    pub const MinExecutors: u32 = 1;
    pub const MaxExecutors: u32 = 10;
    pub const EpochDuration: BlockNumber = 3;
    pub const MaxWithdrawals: u32 = 1;
    pub const WithdrawalDuration: BlockNumber = 10;
}

impl pallet_executor_registry::Config for Test {
    type Event = Event;
    type Currency = Balances;
    type StakeWeight = StakeWeight;
    type MinExecutorStake = MinExecutorStake;
    type MaxExecutorStake = MaxExecutorStake;
    type MinExecutors = MinExecutors;
    type MaxExecutors = MaxExecutors;
    type EpochDuration = EpochDuration;
    type MaxWithdrawals = MaxWithdrawals;
    type WithdrawalDuration = WithdrawalDuration;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1000), (2, 2000), (3, 3000), (4, 4000)],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    pallet_executor_registry::GenesisConfig::<Test> {
        executors: vec![(
            1,
            100,
            1 + 10000,
            ExecutorPair::from_seed(&U256::from(1u32).into()).public(),
        )],
        slot_probability: (1u64, 1u64),
    }
    .assimilate_storage(&mut t)
    .unwrap();

    t.into()
}

#[test]
fn register_should_work() {
    new_test_ext().execute_with(|| {
        // Check the registration of genesis executors.
        let genesis_executor_public_key =
            ExecutorPair::from_seed(&U256::from(1u32).into()).public();
        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 1);
        assert_eq!(
            KeyOwner::<Test>::get(&genesis_executor_public_key).unwrap(),
            1
        );

        let public_key = ExecutorPair::from_seed(&U256::from(2u32).into()).public();
        let reward_address = 2 + 10_000;
        let is_active = true;
        let stake = 200;

        assert_noop!(
            ExecutorRegistry::register(
                Origin::signed(1),
                public_key.clone(),
                reward_address,
                is_active,
                100_000,
            ),
            Error::<Test>::StakeTooLarge
        );
        assert_noop!(
            ExecutorRegistry::register(
                Origin::signed(1),
                public_key.clone(),
                reward_address,
                true,
                1
            ),
            Error::<Test>::StakeTooSmall
        );
        assert_noop!(
            ExecutorRegistry::register(
                Origin::signed(8),
                public_key.clone(),
                reward_address,
                true,
                100
            ),
            Error::<Test>::InsufficientBalance
        );
        assert_noop!(
            ExecutorRegistry::register(
                Origin::signed(1),
                public_key.clone(),
                reward_address,
                true,
                stake
            ),
            Error::<Test>::AlreadyExecutor
        );

        assert_ok!(ExecutorRegistry::register(
            Origin::signed(2),
            public_key.clone(),
            reward_address,
            is_active,
            stake,
        ));
        assert_eq!(
            frame_system::Account::<Test>::get(&2).data,
            AccountData {
                free: 2000,
                reserved: 0,
                misc_frozen: stake,
                fee_frozen: stake
            }
        );
        assert_eq!(KeyOwner::<Test>::get(&public_key).unwrap(), 2);
        assert_eq!(
            Executors::<Test>::get(&2),
            Some(ExecutorConfig {
                public_key,
                reward_address,
                is_active,
                stake,
                withdrawals: Default::default()
            })
        );
        assert_eq!(TotalActiveStake::<Test>::get(), 100 + stake);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 2);
    });
}

#[test]
fn stake_extra_should_work() {
    new_test_ext().execute_with(|| {
        let executor_config = Executors::<Test>::get(&1).unwrap();
        assert_eq!(
            frame_system::Account::<Test>::get(&1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                misc_frozen: 100,
                fee_frozen: 100
            }
        );
        let extra = 200;
        assert_ok!(ExecutorRegistry::increase_stake(Origin::signed(1), extra));
        assert_eq!(
            Executors::<Test>::get(&1).unwrap(),
            ExecutorConfig {
                stake: executor_config.stake + extra,
                ..executor_config
            }
        );
        assert_eq!(
            frame_system::Account::<Test>::get(&1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                misc_frozen: 100 + extra,
                fee_frozen: 100 + extra
            }
        );
    });
}

#[test]
fn decrease_and_withdraw_stake_should_work() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        assert_eq!(
            frame_system::Account::<Test>::get(&1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                misc_frozen: 100,
                fee_frozen: 100
            }
        );
        assert_noop!(
            ExecutorRegistry::decrease_stake(Origin::signed(1), 1000),
            Error::<Test>::InsufficientStake
        );
        assert_noop!(
            ExecutorRegistry::decrease_stake(Origin::signed(1), Balance::MAX),
            Error::<Test>::InsufficientStake
        );
        let executor_config = Executors::<Test>::get(&1).unwrap();
        let to_decrease = 10;

        assert_ok!(ExecutorRegistry::decrease_stake(
            Origin::signed(1),
            to_decrease
        ));

        assert_eq!(
            frame_system::Account::<Test>::get(&1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                misc_frozen: 100,
                fee_frozen: 100
            }
        );

        assert_eq!(
            Executors::<Test>::get(&1).unwrap(),
            ExecutorConfig {
                withdrawals: bounded_vec![Withdrawal {
                    amount: 10,
                    locked_until: 11
                }],
                stake: executor_config.stake - to_decrease,
                ..executor_config
            }
        );

        System::set_block_number(11);
        assert_noop!(
            ExecutorRegistry::withdraw_decreased_stake(Origin::signed(1), 0),
            Error::<Test>::PrematureWithdrawal
        );

        System::set_block_number(12);
        let executor_config = Executors::<Test>::get(&1).unwrap();
        assert_ok!(ExecutorRegistry::withdraw_decreased_stake(
            Origin::signed(1),
            0
        ));
        assert_eq!(
            Executors::<Test>::get(&1).unwrap(),
            ExecutorConfig {
                withdrawals: Default::default(),
                ..executor_config
            }
        );
        assert_eq!(
            frame_system::Account::<Test>::get(&1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                misc_frozen: 90,
                fee_frozen: 90
            }
        );
    });
}

#[test]
fn pause_and_resume_execution_should_work() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ExecutorRegistry::pause_execution(Origin::signed(1)),
            Error::<Test>::TooFewActiveExecutors
        );

        let public_key = ExecutorPair::from_seed(&U256::from(2u32).into()).public();
        let reward_address = 2 + 10_000;
        let is_active = false;
        let stake = 200;

        assert_ok!(ExecutorRegistry::register(
            Origin::signed(2),
            public_key,
            reward_address,
            is_active,
            stake
        ));

        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 1);

        assert_ok!(ExecutorRegistry::resume_execution(Origin::signed(2)));

        assert_eq!(TotalActiveStake::<Test>::get(), 100 + 200);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 2);

        assert_ok!(ExecutorRegistry::pause_execution(Origin::signed(2)));

        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 1);
    });
}

#[test]
fn update_reward_address_should_work() {
    new_test_ext().execute_with(|| {
        let executor_config = Executors::<Test>::get(&1).unwrap();
        assert_ok!(ExecutorRegistry::update_reward_address(
            Origin::signed(1),
            888
        ));
        assert_eq!(
            Executors::<Test>::get(&1).unwrap(),
            ExecutorConfig {
                reward_address: 888,
                ..executor_config
            }
        );
    });
}
