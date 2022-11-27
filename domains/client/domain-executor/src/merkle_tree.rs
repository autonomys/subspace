use blake2_rfc::blake2b::Blake2b;
use merkletree::hash::Algorithm;
use std::hash::Hasher;
use subspace_core_primitives::{Blake2b256Hash, BLAKE2B_256_HASH_SIZE};

#[derive(Clone)]
pub(super) struct Blake2b256Algorithm(Blake2b);

impl Default for Blake2b256Algorithm {
    fn default() -> Self {
        Self(Blake2b::new(BLAKE2B_256_HASH_SIZE))
    }
}

impl Hasher for Blake2b256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<Blake2b256Hash> for Blake2b256Algorithm {
    #[inline]
    fn hash(&mut self) -> Blake2b256Hash {
        self.0
            .clone()
            .finalize()
            .as_bytes()
            .try_into()
            .expect("Initialized with correct length; qed")
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Merkle tree type for execution trace.
pub(super) type MerkleTree = merkletree::merkle::MerkleTree<
    Blake2b256Hash,
    Blake2b256Algorithm,
    merkletree::store::VecStore<Blake2b256Hash>,
>;

pub(super) fn construct_trace_merkle_tree(
    roots: Vec<[u8; 32]>,
) -> Result<MerkleTree, sp_blockchain::Error> {
    let mut roots = roots;

    let roots_len = roots.len();
    // roots contains at least [storage_root_after_initializing_block, state_root].
    assert!(
        roots_len >= 2,
        "Execution trace must at least contain 2 storage roots"
    );

    let ideal_len = merkletree::merkle::next_pow2(roots_len);

    if ideal_len > roots_len {
        // Fill in a full tree by replicating the last element.
        if let Some(state_root) = roots.last().copied() {
            roots.resize(ideal_len, state_root);
        }
    }

    MerkleTree::new(roots).map_err(|e| {
        tracing::error!(error = ?e, "Failed to construct a trace Merkle tree");
        sp_blockchain::Error::Application(e.into())
    })
}

#[cfg(test)]
mod tests {
    use super::construct_trace_merkle_tree;

    #[test]
    fn construct_trace_merkle_tree_should_work() {
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let root3 = [3u8; 32];

        let roots = vec![root1, root2];
        construct_trace_merkle_tree(roots).unwrap();

        let roots = vec![root1, root2, root3];
        construct_trace_merkle_tree(roots).unwrap();
    }
}
