// TODO: Find a better place and architecture for this module
use libp2p::multihash::Multihash;
use subspace_core_primitives::Sha256Hash;

/// Start of Subspace Network multicodec namespace:
/// https://github.com/multiformats/multicodec/blob/master/table.csv
const SUBSPACE_MULTICODEC_NAMESPACE_START: usize = 0xb39910;

#[repr(usize)]
pub enum MultihashCode {
    Piece = SUBSPACE_MULTICODEC_NAMESPACE_START,
}

pub fn create_piece_multihash(records_root: &Sha256Hash, piece_index: u64) -> Multihash {
    let piece_index_bytes = piece_index.to_le_bytes();
    let mut input = Vec::with_capacity(records_root.len() + piece_index_bytes.len());
    input.extend_from_slice(records_root);
    input.extend_from_slice(&piece_index_bytes);
    Multihash::wrap(MultihashCode::Piece as u64, &input)
        .expect("Input never exceeds allocated size; qed")
}
