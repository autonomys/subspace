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
