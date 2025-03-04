#![cfg_attr(not(feature = "std"), no_std)]
//! Test primitive crates that expose necessary extensions that are used in tests.

use codec::{Decode, Encode};
use sp_core::H256;
use sp_messenger::messages::{ChainId, ChannelId};
use sp_runtime::traits::NumberFor;
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrLeaf};

/// Test domain runtime upgrade period for lower-level runtime tests.
pub const TEST_DOMAIN_RUNTIME_UPGRADE_DELAY: u32 = 10;

/// Test domains block pruning depth, also used as the test challenge period.
/// In operator instance tests, also used as the staking withdrawal period and domain runtime upgrade delay.
pub const TEST_DOMAINS_BLOCK_PRUNING_DEPTH: u32 = 16;

/// Test staking withdrawal period for lower-level runtime tests.
pub const TEST_STAKE_WITHDRAWAL_LOCKING_PERIOD: u32 = 20;

sp_api::decl_runtime_apis! {
    /// Api for querying onchain state in the test
    pub trait OnchainStateApi<AccountId, Balance>
    where
        AccountId: Encode + Decode,
        Balance: Encode + Decode
    {
        /// Api to get the free balance of the given account
        fn free_balance(account_id: AccountId) -> Balance;

        /// Returns the last open channel for a given domain.
        fn get_open_channel_for_chain(dst_chain_id: ChainId) -> Option<ChannelId>;

        /// Verify the mmr proof statelessly and extract the state root.
        fn verify_proof_and_extract_leaf(proof: ConsensusChainMmrLeafProof<NumberFor<Block>, Block::Hash, H256>) -> Option<MmrLeaf<NumberFor<Block>, Block::Hash>>;
    }
}
