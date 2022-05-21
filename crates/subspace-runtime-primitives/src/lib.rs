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
#![feature(int_log)]

use sp_runtime::traits::{IdentifyAccount, Verify};
use sp_runtime::MultiSignature;
use sp_std::vec::Vec;
pub use subspace_core_primitives::BlockNumber;
use subspace_core_primitives::{PIECE_SIZE, SHA256_HASH_SIZE};

// TODO: Proper value here
pub const CONFIRMATION_DEPTH_K: BlockNumber = 100;
/// 128 data records and 128 parity records (as a result of erasure coding) together form a perfect
/// Merkle Tree and will result in witness size of `log2(MERKLE_NUM_LEAVES) * SHA256_HASH_SIZE`.
///
/// This number is a tradeoff:
/// * as this number goes up, fewer [`RootBlock`]s are required to be stored for verifying archival
///   history of the network, which makes sync quicker and more efficient, but also more data in
///   each [`Piece`] will be occupied with witness, thus wasting space that otherwise could have
///   been used for storing data (record part of a Piece)
/// * as this number goes down, witness get smaller leading to better piece utilization, but the
///   number of root blocks goes up making sync less efficient and less records are needed to be
///   lost before part of the archived history become unrecoverable, reducing reliability of the
///   data stored on the network
const MERKLE_NUM_LEAVES: u32 = 256;
/// Size of witness for a segment record (in bytes).
const WITNESS_SIZE: u32 = SHA256_HASH_SIZE as u32 * MERKLE_NUM_LEAVES.log2();
/// Size of a segment record given the global piece size (in bytes).
pub const RECORD_SIZE: u32 = PIECE_SIZE as u32 - WITNESS_SIZE;
///Maximum number of pieces in each plot
// TODO: Proper value here
pub const MAX_PLOT_SIZE: u64 = 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64;
/// Recorded History Segment Size includes half of the records (just data records) that will later
/// be erasure coded and together with corresponding witnesses will result in `MERKLE_NUM_LEAVES`
/// pieces of archival history.
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;
/// Minimum desired number of replicas of the blockchain to be stored by the network,
/// impacts storage fees.
// TODO: Proper value here
pub const MIN_REPLICATION_FACTOR: u16 = 1;
/// How much (ratio) of storage fees escrow should be given to farmer each block as a reward.
// TODO: Proper value here
pub const STORAGE_FEES_ESCROW_BLOCK_REWARD: (u64, u64) = (1, 100);
/// How much (ratio) of storage fees collected in a block should be put into storage fees escrow
/// (with remaining issued to farmer immediately).
// TODO: Proper value here
pub const STORAGE_FEES_ESCROW_BLOCK_TAX: (u64, u64) = (1, 2);

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
    use super::{BlockNumber, RECORDED_HISTORY_SEGMENT_SIZE};
    use parity_scale_codec::{Decode, Encode};
    #[cfg(feature = "std")]
    use serde::{Deserialize, Serialize};
    use sp_core::RuntimeDebug;
    use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
    use sp_runtime::{generic, DigestItem, OpaqueExtrinsic};
    use sp_std::prelude::*;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.

    /// Abstraction over a substrate block.
    #[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug)]
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
    fn find_block_reward_address<'a, I>(digests: I) -> Option<RewardAddress>
    where
        I: 'a + IntoIterator<Item = (sp_runtime::ConsensusEngineId, &'a [u8])>;
}

/// A trait for finding the addresses for voting reward based on transactions found in the block.
pub trait FindVotingRewardAddresses<RewardAddress> {
    /// Find the addresses for voting rewards based on transactions found in the block.
    fn find_voting_reward_addresses() -> Vec<RewardAddress>;
}
