#![cfg_attr(not(feature = "std"), no_std)]

use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    /// API necessary for executor.
    pub trait ExecutorApi {
        /// Submits an unsigned extrinsic to submit a candidate receipt.
        fn submit_candidate_receipt_unsigned(
            head_number: <<Block as BlockT>::Header as HeaderT>::Number,
            head_hash: <Block as BlockT>::Hash,
        ) -> Option<()>;

        /// Returns the block hash for given block `number`.
        fn head_hash(
            number: <<Block as BlockT>::Header as HeaderT>::Number,
        ) -> Option<<Block as BlockT>::Hash>;

        /// Returns the pending head of executor chain.
        fn pending_head() -> Option<<Block as BlockT>::Hash>;
    }
}
