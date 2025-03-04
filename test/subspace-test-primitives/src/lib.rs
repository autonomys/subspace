#![cfg_attr(not(feature = "std"), no_std)]
//! Test primitive crates that expose necessary extensions that are used in tests.

use parity_scale_codec::{Decode, Encode};
use sp_core::H256;
use sp_messenger::messages::{ChainId, ChannelId};
use sp_runtime::traits::NumberFor;
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrLeaf};

/// Domains Block pruning depth.
pub const DOMAINS_BLOCK_PRUNING_DEPTH: u32 = 10;

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
