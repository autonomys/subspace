//! Primitives for Objects.

#![cfg_attr(not(feature = "std"), no_std)]
// TODO: Suppression because of https://github.com/paritytech/polkadot-sdk/issues/3533
#![allow(clippy::multiple_bound_locations)]

use subspace_core_primitives::objects::BlockObjectMapping;

sp_api::decl_runtime_apis! {
    pub trait ObjectsApi {
        /// Extract block object mapping for a given block
        fn extract_block_object_mapping(block: Block) -> BlockObjectMapping;
    }
}
