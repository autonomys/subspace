use merkletree::hash::Algorithm;
use sha2::{Digest, Sha256};
use std::hash::Hasher;
use subspace_core_primitives::Sha256Hash;

#[derive(Default, Clone)]
pub(super) struct Sha256Algorithm(Sha256);

impl Hasher for Sha256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<Sha256Hash> for Sha256Algorithm {
    #[inline]
    fn hash(&mut self) -> Sha256Hash {
        self.0
            .clone()
            .finalize()
            .as_slice()
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

/// Merkle tree type for execution trace.
pub(super) type MerkleTree = merkletree::merkle::MerkleTree<
    Sha256Hash,
    Sha256Algorithm,
    merkletree::store::VecStore<Sha256Hash>,
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
		tracing::error!(target: crate::LOG_TARGET, error = ?e, "Failed to construct a trace Merkle tree");
		sp_blockchain::Error::Application(e.into())
	})
}
