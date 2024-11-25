use subspace_core_primitives::BlockNumber;

#[test]
fn leaf_index_that_added_node_fits_block_number() {
    // Must not panic
    super::leaf_index_that_added_node(BlockNumber::MAX);
}
