// TODO: Find a better place and architecture for this module
use libp2p::multihash::Multihash;
use subspace_core_primitives::Blake2b256Hash;

/// Start of Subspace Network multicodec namespace (+1000 to distinguish from future stable values):
/// https://github.com/multiformats/multicodec/blob/master/table.csv
const SUBSPACE_MULTICODEC_NAMESPACE_START: u64 = 0xb39910 + 1000;

#[repr(u64)]
pub enum MultihashCode {
    PieceIndex = SUBSPACE_MULTICODEC_NAMESPACE_START + 1,
    Piece = SUBSPACE_MULTICODEC_NAMESPACE_START,
}

impl From<MultihashCode> for u64 {
    fn from(code: MultihashCode) -> Self {
        code as u64
    }
}

pub fn create_piece_index_fake_multihash(piece_index: u64) -> Multihash {
    // TODO: Switch to hash once we have mapping from hashes on the farmer
    // let piece_index_bytes = crypto::sha256_hash(piece_index.to_le_bytes());
    let piece_index_bytes = piece_index.to_le_bytes();
    Multihash::wrap(u64::from(MultihashCode::PieceIndex), &piece_index_bytes)
        .expect("Input never exceeds allocated size; qed")
}

pub fn create_piece_multihash(records_root: &Blake2b256Hash, piece_index: u64) -> Multihash {
    let piece_index_bytes = piece_index.to_le_bytes();
    let mut input = Vec::with_capacity(records_root.len() + piece_index_bytes.len());
    input.extend_from_slice(records_root);
    input.extend_from_slice(&piece_index_bytes);
    Multihash::wrap(u64::from(MultihashCode::Piece), &input)
        .expect("Input never exceeds allocated size; qed")
}
