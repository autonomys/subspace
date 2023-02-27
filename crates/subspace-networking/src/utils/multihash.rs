use libp2p::multihash::Multihash;
use std::error::Error;
use subspace_core_primitives::PieceIndexHash;

/// Start of Subspace Network multicodec namespace (+1000 to distinguish from future stable values):
/// https://github.com/multiformats/multicodec/blob/master/table.csv
const SUBSPACE_MULTICODEC_NAMESPACE_START: u64 = 0xb39910 + 1000;

#[derive(Debug, Clone, PartialEq)]
#[repr(u64)]
pub enum MultihashCode {
    PieceIndexHash = SUBSPACE_MULTICODEC_NAMESPACE_START,
}

impl From<MultihashCode> for u64 {
    fn from(code: MultihashCode) -> Self {
        code as u64
    }
}

impl TryFrom<u64> for MultihashCode {
    type Error = Box<dyn Error>;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == MultihashCode::PieceIndexHash as u64 => Ok(MultihashCode::PieceIndexHash),
            _ => Err("Unexpected multihash code".into()),
        }
    }
}

pub fn create_multihash_by_piece_index(piece_index: u64) -> Multihash {
    let piece_index_hash = PieceIndexHash::from_index(piece_index);

    piece_index_hash.to_multihash()
}

pub trait ToMultihash {
    fn to_multihash(&self) -> Multihash;
    fn to_multihash_by_code(&self, code: MultihashCode) -> Multihash;
}

impl ToMultihash for PieceIndexHash {
    fn to_multihash(&self) -> Multihash {
        self.to_multihash_by_code(MultihashCode::PieceIndexHash)
    }

    fn to_multihash_by_code(&self, code: MultihashCode) -> Multihash {
        Multihash::wrap(u64::from(code), self.as_ref())
            .expect("Input never exceeds allocated size; qed")
    }
}
