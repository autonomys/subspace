#![allow(missing_debug_implementations)]

use frame_support::traits::{ConstU128, ConstU16, ConstU32, ConstU64};
use sp_core::H256;
use sp_runtime::traits::{parameter_types, BlakeTwo256, IdentityLookup};
use subspace_runtime_primitives::{
    FindBlockRewardAddress, FindVotingRewardAddresses, RewardsEnabled,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Balances: pallet_balances,
        Rewards: crate,
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = RuntimeTask;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u128>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

impl pallet_balances::Config for Test {
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = u128;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const ProposerTaxOnVotes: (u32, u32) = (1, 10);
}

pub struct MockRewardsEnabled;

impl RewardsEnabled for MockRewardsEnabled {
    fn rewards_enabled() -> bool {
        true
    }
}

pub struct MockFindBlockRewardAddress;

impl<RewardAddress> FindBlockRewardAddress<RewardAddress> for MockFindBlockRewardAddress {
    fn find_block_reward_address() -> Option<RewardAddress> {
        None
    }
}

pub struct MockFindVotingRewardAddresses;

impl<RewardAddress> FindVotingRewardAddresses<RewardAddress> for MockFindVotingRewardAddresses {
    fn find_voting_reward_addresses() -> Vec<RewardAddress> {
        Vec::new()
    }
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AvgBlockspaceUsageNumBlocks = ConstU32<10>;
    type TransactionByteFee = ConstU128<1>;
    type MaxRewardPoints = ConstU32<20>;
    type ProposerTaxOnVotes = ProposerTaxOnVotes;
    type RewardsEnabled = MockRewardsEnabled;
    type FindBlockRewardAddress = MockFindBlockRewardAddress;
    type FindVotingRewardAddresses = MockFindVotingRewardAddresses;
    type WeightInfo = ();
    type OnReward = ();
}
