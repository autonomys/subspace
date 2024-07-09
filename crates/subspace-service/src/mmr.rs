use sp_mmr_primitives::utils::NodesUtils;
use sp_mmr_primitives::{NodeIndex, INDEXING_PREFIX};

pub(crate) mod request_handler;
pub(crate) mod sync;

pub(crate) fn get_offchain_key(index: NodeIndex) -> Vec<u8> {
    NodesUtils::node_canon_offchain_key(INDEXING_PREFIX, index)
}
