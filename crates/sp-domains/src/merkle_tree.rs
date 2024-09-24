#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::OperatorPublicKey;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake2::digest::FixedOutput;
use blake2::{Blake2b, Digest};
use parity_scale_codec::{Decode, Encode};
use rs_merkle::Hasher;
use scale_info::TypeInfo;
use sp_runtime::traits::{BlakeTwo256, Hash};

/// Merkle tree using [`Blake2b256Algorithm`].
pub type MerkleTree = rs_merkle::MerkleTree<Blake2b256Algorithm>;

/// Merkle proof using [`Blake2b256Algorithm`].
pub type MerkleProof = rs_merkle::MerkleProof<Blake2b256Algorithm>;

/// Merke proof based Witness.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Default)]
pub struct Witness {
    /// Index of the leaf the proof is for.
    pub leaf_index: u32,
    /// Merkle proof in bytes.
    pub proof: Vec<u8>,
    /// Number of leaves in the original tree.
    pub number_of_leaves: u32,
}

#[derive(Clone)]
pub struct Blake2b256Algorithm;

impl Default for Blake2b256Algorithm {
    #[inline]
    fn default() -> Self {
        Self
    }
}

impl Hasher for Blake2b256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = Blake2b::new();
        hasher.update(data);
        hasher.finalize_fixed().into()
    }
}

/// Constructs a merkle tree from given authorities.
pub fn authorities_merkle_tree<StakeWeight: Encode>(
    authorities: &[(OperatorPublicKey, StakeWeight)],
) -> MerkleTree {
    let leaves = authorities
        .iter()
        .map(|x| BlakeTwo256::hash_of(&x.encode()).to_fixed_bytes())
        .collect::<Vec<_>>();
    MerkleTree::from_leaves(&leaves)
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;

    #[test]
    fn test_merkle_tree() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];

        let merkle_tree = MerkleTree::from_leaves(&leaves);

        let indices_to_prove = (0..leaves.len()).collect::<Vec<_>>();
        let leaves_to_prove = leaves
            .get(0..leaves.len())
            .expect("can't get leaves to prove");

        let proof = merkle_tree.proof(&indices_to_prove);
        let root = merkle_tree.root().expect("couldn't get the merkle root");

        assert!(proof.verify(root, &indices_to_prove, leaves_to_prove, leaves.len()));
    }
}
