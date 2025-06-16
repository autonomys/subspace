//! Pallet for issuing rewards to block producers.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![feature(array_windows, try_blocks)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;
pub mod weights;

use frame_support::pallet_prelude::*;
use frame_support::traits::Currency;
use frame_system::pallet_prelude::*;
use log::warn;
pub use pallet::*;
use serde::{Deserialize, Serialize};
use sp_core::U256;
use sp_runtime::Saturating;
use sp_runtime::traits::{CheckedSub, Zero};
use subspace_runtime_primitives::{BlockNumber, FindBlockRewardAddress, FindVotingRewardAddresses};
pub use weights::WeightInfo;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

/// Hooks to notify when there are any rewards for specific account.
pub trait OnReward<AccountId, Balance> {
    fn on_reward(account: AccountId, reward: Balance);
}

impl<AccountId, Balance> OnReward<AccountId, Balance> for () {
    fn on_reward(_account: AccountId, _reward: Balance) {}
}

#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Encode,
    Decode,
    MaxEncodedLen,
    TypeInfo,
    Serialize,
    Deserialize,
)]
pub struct RewardPoint<BlockNumber, Balance> {
    pub block: BlockNumber,
    pub subsidy: Balance,
}

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use crate::{BalanceOf, OnReward, RewardPoint};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Currency;
    use frame_system::pallet_prelude::*;
    use subspace_runtime_primitives::{FindBlockRewardAddress, FindVotingRewardAddresses};

    /// Pallet rewards for issuing rewards to block producers.
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-rewards` events
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: Currency<Self::AccountId>;

        /// Number of blocks over which to compute average blockspace usage
        #[pallet::constant]
        type AvgBlockspaceUsageNumBlocks: Get<u32>;

        /// Cost of one byte of blockspace
        #[pallet::constant]
        type TransactionByteFee: Get<BalanceOf<Self>>;

        /// Max number of reward points
        #[pallet::constant]
        type MaxRewardPoints: Get<u32>;

        /// Tax of the proposer on vote rewards
        #[pallet::constant]
        type ProposerTaxOnVotes: Get<(u32, u32)>;

        /// Determine whether rewards are enabled or not
        type RewardsEnabled: subspace_runtime_primitives::RewardsEnabled;

        /// Reward address of block producer
        type FindBlockRewardAddress: FindBlockRewardAddress<Self::AccountId>;

        /// Reward addresses of all receivers of voting rewards
        type FindVotingRewardAddresses: FindVotingRewardAddresses<Self::AccountId>;

        type WeightInfo: WeightInfo;

        type OnReward: OnReward<Self::AccountId, BalanceOf<Self>>;
    }

    #[pallet::genesis_config]
    #[derive(Debug)]
    pub struct GenesisConfig<T>
    where
        T: Config,
    {
        /// Tokens left to issue to farmers at any given time
        pub remaining_issuance: BalanceOf<T>,
        /// Block proposer subsidy parameters
        pub proposer_subsidy_points:
            BoundedVec<RewardPoint<BlockNumberFor<T>, BalanceOf<T>>, T::MaxRewardPoints>,
        /// Voter subsidy parameters
        pub voter_subsidy_points:
            BoundedVec<RewardPoint<BlockNumberFor<T>, BalanceOf<T>>, T::MaxRewardPoints>,
    }

    impl<T> Default for GenesisConfig<T>
    where
        T: Config,
    {
        #[inline]
        fn default() -> Self {
            Self {
                remaining_issuance: Default::default(),
                proposer_subsidy_points: Default::default(),
                voter_subsidy_points: Default::default(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T> BuildGenesisConfig for GenesisConfig<T>
    where
        T: Config,
    {
        fn build(&self) {
            RemainingIssuance::<T>::put(self.remaining_issuance);
            if !self.proposer_subsidy_points.is_empty() {
                ProposerSubsidyPoints::<T>::put(self.proposer_subsidy_points.clone());
            }
            if !self.voter_subsidy_points.is_empty() {
                VoterSubsidyPoints::<T>::put(self.voter_subsidy_points.clone());
            }
        }
    }

    /// Utilization of blockspace (in bytes) by the normal extrinsics used to adjust issuance
    #[pallet::storage]
    pub(crate) type AvgBlockspaceUsage<T> = StorageValue<_, u32, ValueQuery>;

    /// Whether rewards are enabled
    #[pallet::storage]
    pub type RewardsEnabled<T> = StorageValue<_, bool, ValueQuery>;

    /// Tokens left to issue to farmers at any given time
    #[pallet::storage]
    pub type RemainingIssuance<T> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Block proposer subsidy parameters
    #[pallet::storage]
    pub type ProposerSubsidyPoints<T: Config> = StorageValue<
        _,
        BoundedVec<RewardPoint<BlockNumberFor<T>, BalanceOf<T>>, T::MaxRewardPoints>,
        ValueQuery,
    >;

    /// Voter subsidy parameters
    #[pallet::storage]
    pub type VoterSubsidyPoints<T: Config> = StorageValue<
        _,
        BoundedVec<RewardPoint<BlockNumberFor<T>, BalanceOf<T>>, T::MaxRewardPoints>,
        ValueQuery,
    >;

    /// `pallet-rewards` events
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Issued reward for the block author
        BlockReward {
            block_author: T::AccountId,
            reward: BalanceOf<T>,
        },
        /// Issued reward for the voter
        VoteReward {
            voter: T::AccountId,
            reward: BalanceOf<T>,
        },
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(now: BlockNumberFor<T>) {
            Self::do_finalize(now);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Update dynamic issuance parameters
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::update_issuance_params(proposer_subsidy_points.len() as u32, voter_subsidy_points.len() as u32))]
        pub fn update_issuance_params(
            origin: OriginFor<T>,
            proposer_subsidy_points: BoundedVec<
                RewardPoint<BlockNumberFor<T>, BalanceOf<T>>,
                T::MaxRewardPoints,
            >,
            voter_subsidy_points: BoundedVec<
                RewardPoint<BlockNumberFor<T>, BalanceOf<T>>,
                T::MaxRewardPoints,
            >,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ProposerSubsidyPoints::<T>::put(proposer_subsidy_points);
            VoterSubsidyPoints::<T>::put(voter_subsidy_points);

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn do_finalize(block_number: BlockNumberFor<T>) {
        if !<T::RewardsEnabled as subspace_runtime_primitives::RewardsEnabled>::rewards_enabled() {
            return;
        }

        if !RewardsEnabled::<T>::get() {
            RewardsEnabled::<T>::put(true);

            // When rewards are enabled for the first time, adjust points to start with current
            // block number
            ProposerSubsidyPoints::<T>::mutate(|reward_points| {
                reward_points.iter_mut().for_each(|point| {
                    point.block += block_number;
                });
            });
            VoterSubsidyPoints::<T>::mutate(|reward_points| {
                reward_points.iter_mut().for_each(|point| {
                    point.block += block_number;
                });
            });
        }

        let avg_blockspace_usage = Self::update_avg_blockspace_usage(
            frame_system::Pallet::<T>::all_extrinsics_len(),
            AvgBlockspaceUsage::<T>::get(),
            T::AvgBlockspaceUsageNumBlocks::get(),
            frame_system::Pallet::<T>::block_number(),
        );
        AvgBlockspaceUsage::<T>::put(avg_blockspace_usage);

        let old_remaining_issuance = RemainingIssuance::<T>::get();
        let mut new_remaining_issuance = old_remaining_issuance;
        let mut block_reward = Zero::zero();

        // Block author may equivocate, in which case they'll not be present here
        let maybe_block_author = T::FindBlockRewardAddress::find_block_reward_address();
        if maybe_block_author.is_some() {
            // Can't exceed remaining issuance
            block_reward = Self::block_reward(
                &ProposerSubsidyPoints::<T>::get(),
                block_number,
                avg_blockspace_usage,
            )
            .min(new_remaining_issuance);
            new_remaining_issuance -= block_reward;

            // Issue reward later once all voters were taxed
        }

        let voters = T::FindVotingRewardAddresses::find_voting_reward_addresses();
        if !voters.is_empty() {
            let vote_reward = Self::vote_reward(&VoterSubsidyPoints::<T>::get(), block_number);
            // Tax voter
            let proposer_tax = vote_reward / T::ProposerTaxOnVotes::get().1.into()
                * T::ProposerTaxOnVotes::get().0.into();
            // Subtract tax from vote reward
            let vote_reward = vote_reward - proposer_tax;

            for voter in voters {
                // Can't exceed remaining issuance
                let mut reward = vote_reward.min(new_remaining_issuance);
                new_remaining_issuance -= reward;
                // Can't exceed remaining issuance
                let proposer_reward = proposer_tax.min(new_remaining_issuance);
                new_remaining_issuance -= proposer_reward;
                // In case block author equivocated, give full reward to voter
                if maybe_block_author.is_some() {
                    block_reward += proposer_reward;
                } else {
                    reward += proposer_reward;
                }

                if !reward.is_zero() {
                    let _imbalance = T::Currency::deposit_creating(&voter, reward);
                    T::OnReward::on_reward(voter.clone(), reward);

                    Self::deposit_event(Event::VoteReward { voter, reward });
                }
            }
        }

        if let Some(block_author) = maybe_block_author
            && !block_reward.is_zero()
        {
            let _imbalance = T::Currency::deposit_creating(&block_author, block_reward);
            T::OnReward::on_reward(block_author.clone(), block_reward);

            Self::deposit_event(Event::BlockReward {
                block_author,
                reward: block_reward,
            });
        }

        if old_remaining_issuance != new_remaining_issuance {
            RemainingIssuance::<T>::put(new_remaining_issuance);
        }
    }

    /// Returns new updated average blockspace usage based on given parameters
    fn update_avg_blockspace_usage(
        used_blockspace: u32,
        old_avg_blockspace_usage: u32,
        avg_blockspace_usage_num_blocks: u32,
        block_height: BlockNumberFor<T>,
    ) -> u32 {
        if avg_blockspace_usage_num_blocks == 0 {
            used_blockspace
        } else if block_height <= avg_blockspace_usage_num_blocks.into() {
            (old_avg_blockspace_usage + used_blockspace) / 2
        } else {
            // Multiplier is `a / b` stored as `(a, b)`
            let multiplier = (2, u64::from(avg_blockspace_usage_num_blocks) + 1);

            // Equivalent to `multiplier * used_blockspace + (1 - multiplier) * old_avg_blockspace_usage`
            // using integer math
            let a = multiplier.0 * u64::from(used_blockspace);
            let b = (multiplier.1 - multiplier.0) * u64::from(old_avg_blockspace_usage);

            u32::try_from((a + b) / multiplier.1).expect(
                "Average of blockspace usage can't overflow if individual components do not \
                overflow; qed",
            )
        }
    }

    fn block_reward(
        proposer_subsidy_points: &[RewardPoint<BlockNumberFor<T>, BalanceOf<T>>],
        block_height: BlockNumberFor<T>,
        avg_blockspace_usage: u32,
    ) -> BalanceOf<T> {
        let reference_subsidy =
            Self::reference_subsidy_for_block(proposer_subsidy_points, block_height);
        let max_normal_block_length = *T::BlockLength::get().max.get(DispatchClass::Normal);
        let max_block_fee = BalanceOf::<T>::from(max_normal_block_length)
            .saturating_mul(T::TransactionByteFee::get());
        // Reward decrease based on chain utilization
        let reward_decrease = Self::block_number_to_balance(avg_blockspace_usage)
            * reference_subsidy.min(max_block_fee)
            / Self::block_number_to_balance(max_normal_block_length);
        reference_subsidy.saturating_sub(reward_decrease)
    }

    fn vote_reward(
        voter_subsidy_points: &[RewardPoint<BlockNumberFor<T>, BalanceOf<T>>],
        block_height: BlockNumberFor<T>,
    ) -> BalanceOf<T> {
        Self::reference_subsidy_for_block(voter_subsidy_points, block_height)
    }

    fn reference_subsidy_for_block(
        points: &[RewardPoint<BlockNumberFor<T>, BalanceOf<T>>],
        block_height: BlockNumberFor<T>,
    ) -> BalanceOf<T> {
        points
            // Find two points between which current block lies
            .array_windows::<2>()
            .find(|&[from, to]| block_height >= from.block && block_height < to.block)
            .map(|&[from, to]| {
                // Calculate reference subsidy
                Some(
                    from.subsidy
                        - from.subsidy.checked_sub(&to.subsidy)?
                            / Self::block_number_to_balance(to.block - from.block)
                            * Self::block_number_to_balance(block_height - from.block),
                )
            })
            .unwrap_or_else(|| {
                // If no matching points are found and current block number is beyond last block,
                // use last point's subsidy
                points
                    .last()
                    .and_then(|point| (block_height >= point.block).then_some(point.subsidy))
            })
            .unwrap_or_default()
    }

    fn block_number_to_balance<N>(n: N) -> BalanceOf<T>
    where
        N: Into<BlockNumberFor<T>>,
    {
        let n = Into::<BlockNumberFor<T>>::into(n);
        BalanceOf::<T>::from(
            BlockNumber::try_from(Into::<U256>::into(n))
                .expect("Block number fits into block number; qed"),
        )
    }
}
