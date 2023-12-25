// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Runtime primitives for Subspace Network.

#![cfg_attr(not(feature = "std"), no_std)]

use pallet_transaction_payment::{Multiplier, TargetedFeeAdjustment};
use sp_core::parameter_types;
use sp_runtime::traits::{Bounded, IdentifyAccount, Verify};
use sp_runtime::{FixedPointNumber, MultiSignature, Perquintill};
use sp_std::vec::Vec;
pub use subspace_core_primitives::BlockNumber;

/// Minimum desired number of replicas of the blockchain to be stored by the network,
/// impacts storage fees.
pub const MIN_REPLICATION_FACTOR: u16 = 50;
/// How much (ratio) of storage fees escrow should be given to farmer each block as a reward.
// TODO: Proper value here
pub const STORAGE_FEES_ESCROW_BLOCK_REWARD: (u64, u64) = (1, 10000);
/// How much (ratio) of storage fees collected in a block should be put into storage fees escrow
/// (with remaining issued to farmer immediately).
// TODO: Proper value here
pub const STORAGE_FEES_ESCROW_BLOCK_TAX: (u64, u64) = (1, 10);

/// The smallest unit of the token is called Shannon.
pub const SHANNON: Balance = 1;
/// Subspace Credits have 18 decimal places.
pub const DECIMAL_PLACES: u8 = 18;
/// One Subspace Credit.
pub const SSC: Balance = (10 * SHANNON).pow(DECIMAL_PLACES as u32);

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// Type used for expressing timestamp.
pub type Moment = u64;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::BlockNumber;
    use sp_runtime::generic;
    use sp_runtime::traits::BlakeTwo256;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
}

/// A trait for finding the address for a block reward based on the `PreRuntime` digests contained within it.
pub trait FindBlockRewardAddress<RewardAddress> {
    /// Find the address for a block rewards based on the pre-runtime digests.
    fn find_block_reward_address() -> Option<RewardAddress>;
}

/// A trait for finding the addresses for voting reward based on transactions found in the block.
pub trait FindVotingRewardAddresses<RewardAddress> {
    /// Find the addresses for voting rewards based on transactions found in the block.
    fn find_voting_reward_addresses() -> Vec<RewardAddress>;
}

parameter_types! {
    /// The portion of the `NORMAL_DISPATCH_RATIO` that we adjust the fees with. Blocks filled less
    /// than this will decrease the weight and more will increase.
    pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(50);
    /// The adjustment variable of the runtime. Higher values will cause `TargetBlockFullness` to
    /// change the fees more rapidly.
    pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(75, 1_000_000);
    /// Minimum amount of the multiplier. This value cannot be too low. A test case should ensure
    /// that combined with `AdjustmentVariable`, we can recover from the minimum.
    /// See `multiplier_can_grow_from_zero`.
    pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 10u128);
    /// The maximum amount of the multiplier.
    pub MaximumMultiplier: Multiplier = Bounded::max_value();
}

/// Parameterized slow adjusting fee updated based on
/// <https://research.web3.foundation/Polkadot/overview/token-economics#2-slow-adjusting-mechanism>
pub type SlowAdjustingFeeUpdate<R> = TargetedFeeAdjustment<
    R,
    TargetBlockFullness,
    AdjustmentVariable,
    MinimumMultiplier,
    MaximumMultiplier,
>;

#[cfg(feature = "testing")]
pub mod tests_utils {
    use frame_support::dispatch::DispatchClass;
    use frame_support::weights::Weight;
    use frame_system::limits::BlockWeights;
    use pallet_transaction_payment::{Multiplier, MultiplierUpdate};
    use sp_runtime::traits::{Convert, Get};
    use sp_runtime::BuildStorage;
    use std::marker::PhantomData;

    pub struct FeeMultiplierUtils<Runtime, BlockWeightsGetter>(
        PhantomData<(Runtime, BlockWeightsGetter)>,
    );

    impl<Runtime, BlockWeightsGetter> FeeMultiplierUtils<Runtime, BlockWeightsGetter>
    where
        Runtime: frame_system::Config + pallet_transaction_payment::Config,
        BlockWeightsGetter: Get<BlockWeights>,
    {
        fn max_normal() -> Weight {
            let block_weights = BlockWeightsGetter::get();
            block_weights
                .get(DispatchClass::Normal)
                .max_total
                .unwrap_or(block_weights.max_block)
        }

        fn min_multiplier() -> Multiplier {
            <<Runtime as pallet_transaction_payment::Config>::FeeMultiplierUpdate as MultiplierUpdate>::min()
        }

        fn target() -> Weight {
            <<Runtime as pallet_transaction_payment::Config>::FeeMultiplierUpdate as MultiplierUpdate>::target() * Self::max_normal()
        }

        // update based on runtime impl.
        fn runtime_multiplier_update(fm: Multiplier) -> Multiplier {
            <<Runtime as pallet_transaction_payment::Config>::FeeMultiplierUpdate as Convert<
                Multiplier,
                Multiplier,
            >>::convert(fm)
        }

        fn run_with_system_weight<F>(w: Weight, assertions: F)
        where
            F: Fn(),
        {
            let mut t: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
                .build_storage()
                .unwrap()
                .into();
            t.execute_with(|| {
                frame_system::Pallet::<Runtime>::set_block_consumed_resources(w, 0);
                assertions()
            });
        }

        // The following function is taken from test with same name from
        // https://github.com/paritytech/polkadot-sdk/blob/91851951856b8effe627fb1d151fe336a51eef2d/substrate/bin/node/runtime/src/impls.rs#L234
        // with some small surface changes.
        pub fn multiplier_can_grow_from_zero()
        where
            Runtime: pallet_transaction_payment::Config,
            BlockWeightsGetter: Get<BlockWeights>,
        {
            // if the min is too small, then this will not change, and we are doomed forever.
            // the block ref time is 1/100th bigger than target.
            Self::run_with_system_weight(
                Self::target().set_ref_time((Self::target().ref_time() / 100) * 101),
                || {
                    let next = Self::runtime_multiplier_update(Self::min_multiplier());
                    assert!(
                        next > Self::min_multiplier(),
                        "{:?} !> {:?}",
                        next,
                        Self::min_multiplier()
                    );
                },
            );

            // the block proof size is 1/100th bigger than target.
            Self::run_with_system_weight(
                Self::target().set_proof_size((Self::target().proof_size() / 100) * 101),
                || {
                    let next = Self::runtime_multiplier_update(Self::min_multiplier());
                    assert!(
                        next > Self::min_multiplier(),
                        "{:?} !> {:?}",
                        next,
                        Self::min_multiplier()
                    );
                },
            )
        }
    }
}
