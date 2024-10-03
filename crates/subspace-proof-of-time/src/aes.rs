//! AES related functionality.

#[cfg(all(feature = "std", target_arch = "x86_64"))]
mod x86_64;

#[cfg(not(feature = "std"))]
extern crate alloc;

use aes::cipher::array::Array;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use subspace_core_primitives::pot::{PotCheckpoints, PotKey, PotOutput, PotSeed};

/// Creates the AES based proof.
#[inline(always)]
pub(crate) fn create(seed: PotSeed, key: PotKey, checkpoint_iterations: u32) -> PotCheckpoints {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if std::is_x86_feature_detected!("aes") {
        return unsafe { x86_64::create(seed.as_ref(), key.as_ref(), checkpoint_iterations) };
    }

    create_generic(seed, key, checkpoint_iterations)
}

fn create_generic(seed: PotSeed, key: PotKey, checkpoint_iterations: u32) -> PotCheckpoints {
    let key = Array::from(*key);
    let cipher = Aes128::new(&key);
    let mut cur_block = Array::from(*seed);

    let mut checkpoints = PotCheckpoints::default();
    for checkpoint in checkpoints.iter_mut() {
        for _ in 0..checkpoint_iterations {
            // Encrypt in place to produce the next block.
            cipher.encrypt_block(&mut cur_block);
        }
        checkpoint.copy_from_slice(&cur_block);
    }

    checkpoints
}

/// Verifies the AES based proof sequentially.
///
/// Panics if `checkpoint_iterations` is not a multiple of `2`.
#[inline(always)]
pub(crate) fn verify_sequential(
    seed: PotSeed,
    key: PotKey,
    checkpoints: &[PotOutput],
    checkpoint_iterations: u32,
) -> bool {
    assert_eq!(checkpoint_iterations % 2, 0);

    let key = Array::from(*key);
    let cipher = Aes128::new(&key);

    let mut inputs = Vec::with_capacity(checkpoints.len());
    inputs.push(Array::from(*seed));
    for &checkpoint in checkpoints.iter().rev().skip(1).rev() {
        inputs.push(Array::from(*checkpoint));
    }
    let mut outputs = checkpoints
        .iter()
        .map(|&checkpoint| Array::from(*checkpoint))
        .collect::<Vec<_>>();

    for _ in 0..checkpoint_iterations / 2 {
        cipher.encrypt_blocks(&mut inputs);
        cipher.decrypt_blocks(&mut outputs);
    }

    inputs == outputs
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_create_verify() {
        let seed = PotSeed::from(SEED);
        let key = PotKey::from(KEY);
        let checkpoint_iterations = 100;

        // Can encrypt/decrypt.
        let checkpoints = create(seed, key, checkpoint_iterations);
        {
            let generic_checkpoints = create_generic(seed, key, checkpoint_iterations);
            assert_eq!(checkpoints, generic_checkpoints);
        }

        assert!(verify_sequential(
            seed,
            key,
            &*checkpoints,
            checkpoint_iterations,
        ));

        // Decryption of invalid cipher text fails.
        let mut checkpoints_1 = checkpoints;
        checkpoints_1[0] = PotOutput::from(BAD_CIPHER);
        assert!(!verify_sequential(
            seed,
            key,
            &*checkpoints_1,
            checkpoint_iterations,
        ));

        // Decryption with wrong number of iterations fails.
        assert!(!verify_sequential(
            seed,
            key,
            &*checkpoints,
            checkpoint_iterations + 2,
        ));
        assert!(!verify_sequential(
            seed,
            key,
            &*checkpoints,
            checkpoint_iterations - 2,
        ));

        // Decryption with wrong seed fails.
        assert!(!verify_sequential(
            PotSeed::from(SEED_1),
            key,
            &*checkpoints,
            checkpoint_iterations,
        ));

        // Decryption with wrong key fails.
        assert!(!verify_sequential(
            seed,
            PotKey::from(KEY_1),
            &*checkpoints,
            checkpoint_iterations,
        ));
    }
}
