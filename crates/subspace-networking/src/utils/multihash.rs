use libp2p::multihash::Multihash;
use subspace_core_primitives::{Blake2b256Hash, PieceIndexHash};

/// Start of Subspace Network multicodec namespace (+1000 to distinguish from future stable values):
/// https://github.com/multiformats/multicodec/blob/master/table.csv
const SUBSPACE_MULTICODEC_NAMESPACE_START: u64 = 0xb39910 + 1000;

#[repr(u64)]
pub enum MultihashCode {
    Piece = SUBSPACE_MULTICODEC_NAMESPACE_START,
    PieceIndex = SUBSPACE_MULTICODEC_NAMESPACE_START + 1,
    Sector = SUBSPACE_MULTICODEC_NAMESPACE_START + 2,
}

impl From<MultihashCode> for u64 {
    fn from(code: MultihashCode) -> Self {
        code as u64
    }
}

pub fn create_multihash_by_piece_index(piece_index: u64) -> Multihash {
    let piece_index_hash = PieceIndexHash::from_index(piece_index);

    piece_index_hash.to_multihash()
}

pub fn create_multihash_by_piece(records_root: &Blake2b256Hash, piece_index: u64) -> Multihash {
    let piece_index_bytes = piece_index.to_le_bytes();
    let mut input = Vec::with_capacity(records_root.len() + piece_index_bytes.len());
    input.extend_from_slice(records_root);
    input.extend_from_slice(&piece_index_bytes);
    Multihash::wrap(u64::from(MultihashCode::Piece), &input)
        .expect("Input never exceeds allocated size; qed")
}

pub trait ToMultihash {
    fn to_multihash(&self) -> Multihash;
    fn to_multihash_by_code(&self, code: MultihashCode) -> Multihash;
}

impl ToMultihash for PieceIndexHash {
    fn to_multihash(&self) -> Multihash {
        self.to_multihash_by_code(MultihashCode::PieceIndex)
    }

    fn to_multihash_by_code(&self, code: MultihashCode) -> Multihash {
        Multihash::wrap(u64::from(code), self.as_ref())
            .expect("Input never exceeds allocated size; qed")
    }
}
