use sha2::{Digest, Sha256};
use subspace_core_primitives::{crypto, Sha256Hash, SHA256_HASH_SIZE};

/// Derives a single object blob of a given size from given seed and index, which is intended to be
/// used as pre-genesis object (blockchain seed data)
pub fn from_seed<S: AsRef<[u8]>>(seed: S, index: u32, size: u32) -> Vec<u8> {
    let size = size as usize;
    let mut object = Vec::with_capacity(size);
    let mut acc: Sha256Hash = {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_ref());
        hasher.update(index.to_le_bytes().as_ref());

        hasher.finalize()[..]
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
    };
    for _ in 0..size / SHA256_HASH_SIZE {
        object.extend_from_slice(&acc);
        acc = crypto::sha256_hash(&acc);
    }

    let remainder = size % SHA256_HASH_SIZE;
    if remainder > 0 {
        object.extend_from_slice(&acc[..remainder]);
    }

    assert_eq!(object.len(), size);

    object
}
