#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{BlockFees, DomainAllowlistUpdates, Transfers};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::{
    opaque, Balance, CheckExtrinsicsValidityError, DecodeExtrinsicError,
};
use sp_runtime::generic::Era;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::Digest;
use sp_weights::Weight;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::Moment;

sp_api::decl_runtime_apis! {
    /// Base API that every domain runtime must implement.
    #[api_version(2)]
    // `allow(clippy::ptr_arg` is needed because Clippy complains to replace `&Vec<T>` with `&[T]`
    // but the latter fails to compile.
    #[allow(clippy::ptr_arg)]
    pub trait DomainCoreApi {
        /// Extracts the optional signer per extrinsic.
        fn extract_signer(
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<(Option<opaque::AccountId>, Block::Extrinsic)>;

        fn is_within_tx_range(
            extrinsic: &Block::Extrinsic,
            bundle_vrf_hash: &U256,
            tx_range: &U256,
        ) -> bool;

        /// Extract signer of a given list of extrinsic if all of them are within the
        /// tx range, otherwise return the index if the first tx not in the tx range.
        fn extract_signer_if_all_within_tx_range(
            extrinsic: &Vec<Block::Extrinsic>,
            bundle_vrf_hash: &U256,
            tx_range: &U256,
        ) -> Result<Vec<Option<opaque::AccountId>> , u32>;

        /// Returns the storage root after initializing the block.
        fn initialize_block_with_post_state_root(header: &Block::Header) -> Vec<u8>;

        /// Returns the storage root after applying the extrinsic.
        fn apply_extrinsic_with_post_state_root(extrinsic: Block::Extrinsic) -> Vec<u8>;

        /// Returns an encoded extrinsic aiming to upgrade the runtime using given code.
        fn construct_set_code_extrinsic(code: Vec<u8>) -> Vec<u8>;

        /// Returns an encoded extrinsic to set timestamp.
        fn construct_timestamp_extrinsic(moment: Moment) -> Block::Extrinsic;

        /// Returns an encoded extrinsic to set domain transaction byte fee.
        fn construct_consensus_chain_byte_fee_extrinsic(consensus_chain_byte_fee: Balance) -> Block::Extrinsic;

        /// Returns an extrinsic to update chain allowlist.
        fn construct_domain_update_chain_allowlist_extrinsic(updates: DomainAllowlistUpdates) -> Block::Extrinsic;

        /// Returns true if the extrinsic is an inherent extrinsic.
        fn is_inherent_extrinsic(extrinsic: &Block::Extrinsic) -> bool;

        /// Find the first inherent extrinsic
        fn find_first_inherent_extrinsic(extrinsics: &Vec<Block::Extrinsic>) -> Option<u32>;

        /// Checks the validity of array of extrinsics + pre_dispatch
        /// returning failure on first extrinsic that fails runtime call.
        /// IMPORTANT: Change `CHECK_EXTRINSICS_AND_DO_PRE_DISPATCH_METHOD_NAME` constant when this method name is changed
        fn check_extrinsics_and_do_pre_dispatch(uxts: Vec<Block::Extrinsic>, block_number: NumberFor<Block>,
            block_hash: Block::Hash) -> Result<(), CheckExtrinsicsValidityError>;

        /// Decodes the domain specific extrinsic from the opaque extrinsic.
        fn decode_extrinsic(
            opaque_extrinsic: sp_runtime::OpaqueExtrinsic,
        ) -> Result<Block::Extrinsic, DecodeExtrinsicError>;

        /// Decodes a list of domain extrinsics from opaque extrinsic, when an undecodable tx is met,
        /// stop and return the decoded extrinsics before the undecodable tx.
        fn decode_extrinsics_prefix(
            opaque_extrinsics: Vec<sp_runtime::OpaqueExtrinsic>,
        ) -> Vec<Block::Extrinsic>;

        /// Returns extrinsic Era if present.
        fn extrinsic_era(
          extrinsic: &Block::Extrinsic
        ) -> Option<Era>;

        /// Returns the extrinsic weight.
        fn extrinsic_weight(ext: &Block::Extrinsic) -> Weight;

        /// Returns the sum of a given set of extrinsics weight.
        fn extrinsics_weight(ext: &Vec<Block::Extrinsic>) -> Weight;

        /// The accumulated transaction fee of all transactions included in the block.
        fn block_fees() -> BlockFees<Balance>;

        /// Returns the block digest.
        fn block_digest() -> Digest;

        /// Returns the consumed weight of the block.
        fn block_weight() -> Weight;

        /// Returns the transfers for this domain in the block.
        fn transfers() -> Transfers<Balance>;

        /// Returns the storage key for the Transfers on Domain.
        fn transfers_storage_key() -> Vec<u8>;

        /// Returns the storage key for the `CollectedBlockFees` on Domain.
        fn block_fees_storage_key() -> Vec<u8>;
    }
}
