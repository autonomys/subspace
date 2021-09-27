use subspace_core_primitives::{crypto, SHA256_HASH_SIZE};

/// Derives a single object blob of a given size from given seed, which is intended to be used as
/// pre-genesis blockchain seed data
pub fn from_seed(seed: &[u8], size: usize) -> Vec<u8> {
    let mut object = Vec::with_capacity(size);
    let mut acc = crypto::sha256_hash(seed);
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
