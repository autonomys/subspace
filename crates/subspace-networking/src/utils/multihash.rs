//! Defines multihash codes for Subspace DSN.

use std::error::Error;
use subspace_core_primitives::PieceIndexHash;

/// Type alias for libp2p Multihash. Constant 64 was copied from libp2p protocols.
pub type Multihash = libp2p::multihash::Multihash<64>;

/// Start of Subspace Network multicodec namespace (+1000 to distinguish from future stable values):
/// https://github.com/multiformats/multicodec/blob/master/table.csv
const SUBSPACE_MULTICODEC_NAMESPACE_START: u64 = 0xb39910 + 1000;

/// Subspace Network multihash codes.
#[derive(Debug, Clone, PartialEq)]
#[repr(u64)]
pub enum MultihashCode {
    /// Piece index hash code.
    PieceIndexHash = SUBSPACE_MULTICODEC_NAMESPACE_START,
}

impl From<MultihashCode> for u64 {
    #[inline]
    fn from(code: MultihashCode) -> Self {
        code as u64
    }
}

impl TryFrom<u64> for MultihashCode {
    type Error = Box<dyn Error>;

    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == MultihashCode::PieceIndexHash as u64 => Ok(MultihashCode::PieceIndexHash),
            _ => Err("Unexpected multihash code".into()),
        }
    }
}

/// Helper trait for converting to multihash.
pub trait ToMultihash {
    /// Convert to multihash by the default multihash code.
    fn to_multihash(&self) -> Multihash;
    /// Convert to multihash by the specified multihash code.
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
