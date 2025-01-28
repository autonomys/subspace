#![cfg_attr(not(feature = "std"), no_std)]
//! Test primitive crates that expose necessary extensions that are used in tests.

use codec::{Decode, Encode};
use sp_messenger::messages::{ChainId, ChannelId};
use subspace_runtime_primitives::Moment;

sp_api::decl_runtime_apis! {
    /// Api that returns the timestamp
    pub trait TimestampApi {
        /// Api to construct inherent timestamp extrinsic from given time
        fn domain_timestamp() -> Moment;
    }
}

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

        /// Api to get the current domain transaction byte fee
        fn consensus_transaction_byte_fee() -> Balance;

        /// Get the storage root
        fn storage_root() -> [u8; 32];
    }
}
