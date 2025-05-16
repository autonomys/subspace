use sp_core::H256;
use sp_mmr_primitives::utils::NodesUtils;
use sp_mmr_primitives::{INDEXING_PREFIX, NodeIndex};
use subspace_runtime_primitives::opaque::Header;

pub(crate) mod request_handler;
pub(crate) mod sync;

pub(crate) fn get_offchain_key(index: NodeIndex) -> Vec<u8> {
    NodesUtils::node_canon_offchain_key(INDEXING_PREFIX, index)
}

pub(crate) fn get_temp_key(index: NodeIndex, hash: H256) -> Vec<u8> {
    NodesUtils::node_temp_offchain_key::<Header>(INDEXING_PREFIX, index, hash)
}
