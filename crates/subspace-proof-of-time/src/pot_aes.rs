//! AES related functionality.

extern crate alloc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;
#[cfg(any(feature = "parallel", test))]
use rayon::prelude::*;
use subspace_core_primitives::{PotBytes, PotCheckpoint, PotKey, PotSeed};

/// Creates the AES based proof.
pub(crate) fn create(
    seed: &PotSeed,
    key: &PotKey,
    num_checkpoints: u8,
    checkpoint_iterations: u32,
) -> Vec<PotCheckpoint> {
    let key = GenericArray::from(PotBytes::from(*key));
    let cipher = Aes128::new(&key);
    let mut cur_block = GenericArray::from(PotBytes::from(*seed));

    let mut checkpoints = Vec::with_capacity(num_checkpoints as usize);
    for _ in 0..num_checkpoints {
        for _ in 0..checkpoint_iterations {
            // Encrypt in place to produce the next block.
            cipher.encrypt_block(&mut cur_block);
        }
        checkpoints.push(PotCheckpoint::from(PotBytes::from(cur_block)));
    }
    checkpoints
}

/// Verifies the AES based proof sequentially.
#[cfg(any(not(feature = "parallel"), test))]
pub(crate) fn verify_sequential(
    seed: &PotSeed,
    key: &PotKey,
    checkpoints: &[PotCheckpoint],
    checkpoint_iterations: u32,
) -> bool {
    let key = GenericArray::from(PotBytes::from(*key));
    let cipher = Aes128::new(&key);

    let mut inputs = Vec::with_capacity(checkpoints.len());
    inputs.push(GenericArray::from(PotBytes::from(*seed)));
    for checkpoint in checkpoints.iter().rev().skip(1).rev() {
        inputs.push(GenericArray::from(PotBytes::from(*checkpoint)));
    }

    for _ in 0..checkpoint_iterations {
        cipher.encrypt_blocks(&mut inputs);
    }

    inputs
        .iter()
        .zip(checkpoints)
        .all(|(a, b)| a.as_slice() == b.as_ref())
}

/// Verifies the AES based proof in parallel.
#[cfg(any(feature = "parallel", test))]
pub(crate) fn verify_parallel(
    seed: &PotSeed,
    key: &PotKey,
    checkpoints: &[PotCheckpoint],
    checkpoint_iterations: u32,
) -> bool {
    let key = GenericArray::from(PotBytes::from(*key));
    let cipher = Aes128::new(&key);

    // Create the cipher pairs to be evaluated
    let mut pairs = Vec::new();
    let mut cur_block = GenericArray::from(PotBytes::from(*seed));
    for checkpoint in checkpoints {
        let checkpoint_block = GenericArray::from(PotBytes::from(*checkpoint));
        pairs.push((cur_block, checkpoint_block));
        cur_block = checkpoint_block;
    }

    // Evaluate the pairs in parallel.
    let results: Vec<bool> = pairs
        .par_iter_mut()
        .map(|(input, expected)| {
            let mut input = *input;
            // Encrypt in place checkpoint_iterations times
            // and compare with the expected output.
            for _ in 0..checkpoint_iterations {
                cipher.encrypt_block(&mut input);
            }
            input == *expected
        })
        .collect();

    results.iter().all(|result| *result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subspace_core_primitives::{PotCheckpoint, PotKey, PotSeed};

    const SEED: [u8; 16] = [
        0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1,
        0x3a,
    ];
    const SEED_1: [u8; 16] = [
        0xd7, 0xd6, 0xdc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1,
        0x3a,
    ];
    const KEY: [u8; 16] = [
        0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e, 0xa2,
        0x7a,
    ];
    const KEY_1: [u8; 16] = [
        0x9b, 0x8b, 0x9b, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e, 0xa2,
        0x7a,
    ];
    const BAD_CIPHER: [u8; 16] = [22; 16];

    #[test]
    fn test_encrypt_decrypt_sequential() {
        let seed = PotSeed::from(SEED);
        let key = PotKey::from(KEY);
        let num_checkpoints = 10;
        let checkpoint_iterations = 100;

        // Can encrypt/decrypt.
        let checkpoints = create(&seed, &key, num_checkpoints, checkpoint_iterations);
        assert_eq!(checkpoints.len(), num_checkpoints as usize);
        assert!(verify_sequential(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations
        ));

        // Decryption of invalid cipher text fails.
        let mut checkpoints_1 = checkpoints.clone();
        checkpoints_1[0] = PotCheckpoint::from(BAD_CIPHER);
        assert!(!verify_sequential(
            &seed,
            &key,
            &checkpoints_1,
            checkpoint_iterations
        ));

        // Decryption with wrong number of iterations fails.
        assert!(!verify_sequential(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations + 1
        ));
        assert!(!verify_sequential(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations - 1
        ));

        // Decryption with wrong seed fails.
        assert!(!verify_sequential(
            &PotSeed::from(SEED_1),
            &key,
            &checkpoints,
            checkpoint_iterations
        ));

        // Decryption with wrong key fails.
        assert!(!verify_sequential(
            &seed,
            &PotKey::from(KEY_1),
            &checkpoints,
            checkpoint_iterations
        ));
    }

    #[test]
    fn test_encrypt_decrypt_parallel() {
        let seed = PotSeed::from(SEED);
        let key = PotKey::from(KEY);
        let num_checkpoints = 10;
        let checkpoint_iterations = 100;

        // Can encrypt/decrypt.
        let checkpoints = create(&seed, &key, num_checkpoints, checkpoint_iterations);
        assert_eq!(checkpoints.len(), num_checkpoints as usize);
        assert!(verify_parallel(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations
        ));

        // Decryption of invalid cipher text fails.
        let mut checkpoints_1 = checkpoints.clone();
        checkpoints_1[0] = PotCheckpoint::from(BAD_CIPHER);
        assert!(!verify_parallel(
            &seed,
            &key,
            &checkpoints_1,
            checkpoint_iterations
        ));

        // Decryption with wrong number of iterations fails.
        assert!(!verify_parallel(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations + 1
        ));
        assert!(!verify_parallel(
            &seed,
            &key,
            &checkpoints,
            checkpoint_iterations - 1
        ));

        // Decryption with wrong seed fails.
        assert!(!verify_parallel(
            &PotSeed::from(SEED_1),
            &key,
            &checkpoints,
            checkpoint_iterations
        ));

        // Decryption with wrong key fails.
        assert!(!verify_parallel(
            &seed,
            &PotKey::from(KEY_1),
            &checkpoints,
            checkpoint_iterations
        ));
    }
}
