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

use sp_runtime::traits::{IdentifyAccount, Verify};
use sp_runtime::MultiSignature;
use sp_std::vec::Vec;
pub use subspace_core_primitives::BlockNumber;

// TODO: Proper value here
pub const CONFIRMATION_DEPTH_K: BlockNumber = 100;
/// Maximum plot size in bytes
// TODO: Proper value here
pub const MAX_PLOT_SIZE: u64 = 100 * 1024 * 1024 * 1024;
/// Minimum desired number of replicas of the blockchain to be stored by the network,
/// impacts storage fees.
// TODO: Proper value here
pub const MIN_REPLICATION_FACTOR: u16 = 1;
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
pub type Index = u32;

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
    use parity_scale_codec::{Decode, Encode};
    #[cfg(feature = "std")]
    use serde::{Deserialize, Serialize};
    use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
    use sp_runtime::{generic, DigestItem, OpaqueExtrinsic};
    use sp_std::prelude::*;
    use subspace_core_primitives::RECORDED_HISTORY_SEGMENT_SIZE;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.

    /// Abstraction over a substrate block.
    #[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
    #[cfg_attr(
        feature = "std",
        derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf)
    )]
    #[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
    #[cfg_attr(feature = "std", serde(deny_unknown_fields))]
    pub struct Block {
        /// The block header.
        pub header: Header,
        /// The accompanying extrinsics.
        pub extrinsics: Vec<OpaqueExtrinsic>,
    }

    impl BlockT for Block {
        type Extrinsic = OpaqueExtrinsic;
        type Header = Header;
        type Hash = <Header as HeaderT>::Hash;

        fn header(&self) -> &Self::Header {
            &self.header
        }
        fn extrinsics(&self) -> &[Self::Extrinsic] {
            &self.extrinsics[..]
        }
        fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>) {
            (self.header, self.extrinsics)
        }
        fn new(mut header: Self::Header, extrinsics: Vec<Self::Extrinsic>) -> Self {
            if header.number == 0 {
                // This check is necessary in case block was deconstructed and constructed again.
                if header.digest.logs.is_empty() {
                    // We fill genesis block with extra data such that the very first archived
                    // segment can be produced right away, bootstrapping the farming process.
                    let ballast = vec![0; RECORDED_HISTORY_SEGMENT_SIZE as usize];
                    header.digest.logs.push(DigestItem::Other(ballast));
                }
                Block { header, extrinsics }
            } else {
                Block { header, extrinsics }
            }
        }
        fn encode_from(header: &Self::Header, extrinsics: &[Self::Extrinsic]) -> Vec<u8> {
            (header, extrinsics).encode()
        }
    }
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
