use crate::{
    self as pallet_executor_registry, Error, ExecutorConfig, Executors, KeyOwner,
    TotalActiveExecutors, TotalActiveStake, TotalStakeWeight, Withdrawal,
};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, GenesisBuild, Hooks};
use frame_support::{assert_noop, assert_ok, bounded_vec, parameter_types};
use frame_system::RawOrigin;
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
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
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
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type HoldIdentifier = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const MinExecutorStake: Balance = 10;
    pub const MaxExecutorStake: Balance = StakeWeight::MAX - 1;
    pub const MinExecutors: u32 = 1;
    pub const MaxExecutors: u32 = 10;
    pub const EpochDuration: BlockNumber = 3;
    pub const MaxWithdrawals: u32 = 1;
    pub const WithdrawalDuration: BlockNumber = 10;
}

impl pallet_executor_registry::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type StakeWeight = StakeWeight;
    type MinExecutorStake = MinExecutorStake;
    type MaxExecutorStake = MaxExecutorStake;
    type MinExecutors = MinExecutors;
    type MaxExecutors = MaxExecutors;
    type MaxWithdrawals = MaxWithdrawals;
    type WithdrawalDuration = WithdrawalDuration;
    type EpochDuration = EpochDuration;
    type OnNewEpoch = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
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
            KeyOwner::<Test>::get(genesis_executor_public_key).unwrap(),
            1
        );

        let public_key = ExecutorPair::from_seed(&U256::from(2u32).into()).public();
        let reward_address = 2 + 10_000;
        let is_active = true;
        let stake = 200;

        assert_noop!(
            ExecutorRegistry::register(
                RuntimeOrigin::signed(1),
                public_key.clone(),
                reward_address,
                is_active,
                StakeWeight::MAX,
            ),
            Error::<Test>::StakeTooLarge
        );
        assert_noop!(
            ExecutorRegistry::register(
                RuntimeOrigin::signed(1),
                public_key.clone(),
                reward_address,
                true,
                1
            ),
            Error::<Test>::StakeTooSmall
        );
        assert_noop!(
            ExecutorRegistry::register(
                RuntimeOrigin::signed(8),
                public_key.clone(),
                reward_address,
                true,
                100
            ),
            Error::<Test>::InsufficientBalance
        );
        assert_noop!(
            ExecutorRegistry::register(
                RuntimeOrigin::signed(1),
                public_key.clone(),
                reward_address,
                true,
                stake
            ),
            Error::<Test>::AlreadyExecutor
        );

        assert_ok!(ExecutorRegistry::register(
            RuntimeOrigin::signed(2),
            public_key.clone(),
            reward_address,
            is_active,
            stake,
        ));
        assert_eq!(
            frame_system::Account::<Test>::get(2).data,
            AccountData {
                free: 2000,
                reserved: 0,
                frozen: stake,
                ..AccountData::default()
            }
        );
        assert_eq!(KeyOwner::<Test>::get(&public_key).unwrap(), 2);
        assert_eq!(
            Executors::<Test>::get(2),
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
        let executor_config = Executors::<Test>::get(1).unwrap();
        assert_eq!(
            frame_system::Account::<Test>::get(1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                frozen: 100,
                ..AccountData::default()
            }
        );
        let extra = 200;
        assert_ok!(ExecutorRegistry::increase_stake(
            RuntimeOrigin::signed(1),
            extra
        ));
        assert_eq!(
            Executors::<Test>::get(1).unwrap(),
            ExecutorConfig {
                stake: executor_config.stake + extra,
                ..executor_config
            }
        );
        assert_eq!(
            frame_system::Account::<Test>::get(1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                frozen: 100 + extra,
                ..AccountData::default()
            }
        );
    });
}

#[test]
fn decrease_and_withdraw_stake_should_work() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        assert_eq!(
            frame_system::Account::<Test>::get(1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                frozen: 100,
                ..AccountData::default()
            }
        );
        assert_noop!(
            ExecutorRegistry::decrease_stake(RuntimeOrigin::signed(1), 1000),
            Error::<Test>::InsufficientStake
        );
        assert_noop!(
            ExecutorRegistry::decrease_stake(RuntimeOrigin::signed(1), Balance::MAX),
            Error::<Test>::InsufficientStake
        );
        let executor_config = Executors::<Test>::get(1).unwrap();
        let to_decrease = 10;

        assert_ok!(ExecutorRegistry::decrease_stake(
            RuntimeOrigin::signed(1),
            to_decrease
        ));

        assert_eq!(
            frame_system::Account::<Test>::get(1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                frozen: 100,
                ..AccountData::default()
            }
        );

        assert_eq!(
            Executors::<Test>::get(1).unwrap(),
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
            ExecutorRegistry::withdraw_stake(RuntimeOrigin::signed(1), 0),
            Error::<Test>::PrematureWithdrawal
        );

        System::set_block_number(12);
        let executor_config = Executors::<Test>::get(1).unwrap();
        assert_ok!(ExecutorRegistry::withdraw_stake(
            RuntimeOrigin::signed(1),
            0
        ));
        assert_eq!(
            Executors::<Test>::get(1).unwrap(),
            ExecutorConfig {
                withdrawals: Default::default(),
                ..executor_config
            }
        );
        assert_eq!(
            frame_system::Account::<Test>::get(1).data,
            AccountData {
                free: 1000,
                reserved: 0,
                frozen: 90,
                ..AccountData::default()
            }
        );
    });
}

#[test]
fn pause_and_resume_execution_should_work() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ExecutorRegistry::pause_execution(RuntimeOrigin::signed(1)),
            Error::<Test>::TooFewActiveExecutors
        );

        let public_key = ExecutorPair::from_seed(&U256::from(2u32).into()).public();
        let reward_address = 2 + 10_000;
        let is_active = false;
        let stake = 200;

        assert_ok!(ExecutorRegistry::register(
            RuntimeOrigin::signed(2),
            public_key,
            reward_address,
            is_active,
            stake
        ));

        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 1);

        assert_ok!(ExecutorRegistry::resume_execution(RuntimeOrigin::signed(2)));

        assert_eq!(TotalActiveStake::<Test>::get(), 100 + 200);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 2);

        assert_ok!(ExecutorRegistry::pause_execution(RuntimeOrigin::signed(2)));

        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalActiveExecutors::<Test>::get(), 1);
    });
}

#[test]
fn update_public_key_should_work() {
    new_test_ext().execute_with(|| {
        let new_public_key = ExecutorPair::from_seed(&U256::from(10u32).into()).public();
        assert_noop!(
            ExecutorRegistry::update_public_key(RuntimeOrigin::signed(10), new_public_key),
            Error::<Test>::NotExecutor
        );

        let executor_config_1 = Executors::<Test>::get(1).unwrap();
        assert_noop!(
            ExecutorRegistry::update_public_key(
                RuntimeOrigin::signed(1),
                executor_config_1.public_key.clone()
            ),
            Error::<Test>::DuplicatedKey
        );

        let public_key = ExecutorPair::from_seed(&U256::from(2u32).into()).public();
        let reward_address = 2 + 10_000;
        let is_active = true;
        let stake = 200;

        assert_ok!(ExecutorRegistry::register(
            RuntimeOrigin::signed(2),
            public_key,
            reward_address,
            is_active,
            stake,
        ));

        assert_noop!(
            ExecutorRegistry::update_public_key(
                RuntimeOrigin::signed(2),
                executor_config_1.public_key
            ),
            Error::<Test>::DuplicatedKey
        );
    });
}

#[test]
fn update_reward_address_should_work() {
    new_test_ext().execute_with(|| {
        let executor_config = Executors::<Test>::get(1).unwrap();
        assert_ok!(ExecutorRegistry::update_reward_address(
            RuntimeOrigin::signed(1),
            888
        ));
        assert_eq!(
            Executors::<Test>::get(1).unwrap(),
            ExecutorConfig {
                reward_address: 888,
                ..executor_config
            }
        );
    });
}

#[test]
fn test_total_stake_overflow() {
    new_test_ext().execute_with(|| {
        Balances::force_set_balance(RawOrigin::Root.into(), 2, StakeWeight::MAX / 2).unwrap();
        Balances::force_set_balance(RawOrigin::Root.into(), 3, StakeWeight::MAX / 2).unwrap();

        assert_eq!(TotalActiveStake::<Test>::get(), 100);
        assert_eq!(TotalStakeWeight::<Test>::get(), 100);

        // `register` trigger overflow error
        assert_ok!(ExecutorRegistry::register(
            RuntimeOrigin::signed(2),
            ExecutorPair::from_seed(&U256::from(2u32).into()).public(),
            2 + 10000,
            true,
            StakeWeight::MAX / 2,
        ));
        assert_noop!(
            ExecutorRegistry::register(
                RuntimeOrigin::signed(3),
                ExecutorPair::from_seed(&U256::from(3u32).into()).public(),
                3 + 10000,
                true,
                StakeWeight::MAX / 2,
            ),
            Error::<Test>::ArithmeticOverflow
        );

        // `increase_stake` trigger overflow error
        Balances::force_set_balance(RawOrigin::Root.into(), 1, StakeWeight::MAX / 2).unwrap();
        assert_noop!(
            ExecutorRegistry::increase_stake(RuntimeOrigin::signed(1), StakeWeight::MAX / 2),
            Error::<Test>::ArithmeticOverflow
        );

        // `resume_execution` trigger overflow error
        assert_ok!(ExecutorRegistry::pause_execution(RuntimeOrigin::signed(2)));
        assert_ok!(ExecutorRegistry::increase_stake(
            RuntimeOrigin::signed(1),
            StakeWeight::MAX / 2
        ));
        assert_noop!(
            ExecutorRegistry::resume_execution(RuntimeOrigin::signed(2),),
            Error::<Test>::ArithmeticOverflow
        );

        // `TotalStakeWeight` should be updated correctly
        ExecutorRegistry::on_initialize(0);
        assert_eq!(TotalStakeWeight::<Test>::get(), StakeWeight::MAX / 2 + 100);
    });
}
