use frame_support::derive_impl;
use frame_support::traits::{ConstU128, ConstU32};
use sp_runtime::traits::parameter_types;
use subspace_runtime_primitives::{
    ConsensusEventSegmentSize, FindBlockRewardAddress, FindVotingRewardAddresses, RewardsEnabled,
};

type Block = frame_system::mocking::MockBlock<Test>;
type Balance = u128;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Balances: pallet_balances,
        Rewards: crate,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<Balance>;
    type EventSegmentSize = ConsensusEventSegmentSize;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type RuntimeHoldReason = ();
    type DustRemoval = ();
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
