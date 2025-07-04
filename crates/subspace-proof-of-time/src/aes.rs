//! AES related functionality.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use aes::Aes128;
use aes::cipher::array::Array;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use subspace_core_primitives::pot::{PotCheckpoints, PotKey, PotOutput, PotSeed};

/// Creates the AES based proof.
#[inline(always)]
pub(crate) fn create(seed: PotSeed, key: PotKey, checkpoint_iterations: u32) -> PotCheckpoints {
    #[cfg(target_arch = "x86_64")]
    {
        cpufeatures::new!(has_aes, "aes");
        if has_aes::get() {
            // SAFETY: Checked `aes` feature
            return unsafe { x86_64::create(seed.as_ref(), key.as_ref(), checkpoint_iterations) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        cpufeatures::new!(has_aes, "aes");
        if has_aes::get() {
            // SAFETY: Checked `aes` feature
            return unsafe { aarch64::create(seed.as_ref(), key.as_ref(), checkpoint_iterations) };
        }
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
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    assert_eq!(checkpoint_iterations % 2, 0);

    #[cfg(target_arch = "x86_64")]
    {
        cpufeatures::new!(has_avx512f_vaes, "avx512f", "vaes");
        if has_avx512f_vaes::get() {
            // SAFETY: Checked `avx512f` and `vaes` features
            return unsafe {
                x86_64::verify_sequential_avx512f_vaes(
                    &seed,
                    &key,
                    checkpoints,
                    checkpoint_iterations,
                )
            };
        }

        cpufeatures::new!(has_avx2_vaes, "avx2", "vaes");
        if has_avx2_vaes::get() {
            // SAFETY: Checked `avx2` and `vaes` features
            return unsafe {
                x86_64::verify_sequential_avx2_vaes(&seed, &key, checkpoints, checkpoint_iterations)
            };
        }

        cpufeatures::new!(has_aes_sse41, "aes", "sse4.1");
        if has_aes_sse41::get() {
            // SAFETY: Checked `aes` and `sse4.1` features
            return unsafe {
                x86_64::verify_sequential_aes_sse41(&seed, &key, checkpoints, checkpoint_iterations)
            };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        cpufeatures::new!(has_aes, "aes");
        if has_aes::get() {
            // SAFETY: Checked `aes` feature
            return unsafe {
                aarch64::verify_sequential_aes(&seed, &key, checkpoints, checkpoint_iterations)
            };
        }
    }

    verify_sequential_generic(seed, key, checkpoints, checkpoint_iterations)
}

fn verify_sequential_generic(
    seed: PotSeed,
    key: PotKey,
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let key = Array::from(*key);
    let cipher = Aes128::new(&key);

    let mut inputs = [[0u8; 16]; PotCheckpoints::NUM_CHECKPOINTS.get() as usize];
    inputs[0] = *seed;
    inputs[1..].copy_from_slice(PotOutput::repr_from_slice(
        &checkpoints[..PotCheckpoints::NUM_CHECKPOINTS.get() as usize - 1],
    ));

    let mut outputs = [[0u8; 16]; PotCheckpoints::NUM_CHECKPOINTS.get() as usize];
    outputs.copy_from_slice(PotOutput::repr_from_slice(checkpoints.as_slice()));

    for _ in 0..checkpoint_iterations / 2 {
        cipher.encrypt_blocks(Array::cast_slice_from_core_mut(&mut inputs));
        cipher.decrypt_blocks(Array::cast_slice_from_core_mut(&mut outputs));
    }

    inputs == outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use subspace_core_primitives::pot::PotOutput;

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

    fn verify_test(
        seed: PotSeed,
        key: PotKey,
        checkpoints: &PotCheckpoints,
        checkpoint_iterations: u32,
    ) -> bool {
        let sequential = verify_sequential(seed, key, checkpoints, checkpoint_iterations);
        let generic = verify_sequential_generic(seed, key, checkpoints, checkpoint_iterations);
        assert_eq!(sequential, generic);

        #[cfg(target_arch = "x86_64")]
        {
            cpufeatures::new!(has_avx512f_vaes, "avx512f", "vaes");
            if has_avx512f_vaes::get() {
                // SAFETY: Checked `avx512f` and `vaes` features
                let avx512f_vaes = unsafe {
                    x86_64::verify_sequential_avx512f_vaes(
                        &seed,
                        &key,
                        checkpoints,
                        checkpoint_iterations,
                    )
                };
                assert_eq!(sequential, avx512f_vaes);
            }

            cpufeatures::new!(has_avx2_vaes, "avx2", "vaes");
            if has_avx2_vaes::get() {
                // SAFETY: Checked `avx2` and `vaes` features
                let avx2_vaes = unsafe {
                    x86_64::verify_sequential_avx2_vaes(
                        &seed,
                        &key,
                        checkpoints,
                        checkpoint_iterations,
                    )
                };
                assert_eq!(sequential, avx2_vaes);
            }

            cpufeatures::new!(has_aes_sse41, "aes", "sse4.1");
            if has_aes_sse41::get() {
                // SAFETY: Checked `aes` and `sse4.1` features
                let aes_sse41 = unsafe {
                    x86_64::verify_sequential_aes_sse41(
                        &seed,
                        &key,
                        checkpoints,
                        checkpoint_iterations,
                    )
                };
                assert_eq!(sequential, aes_sse41);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            cpufeatures::new!(has_aes, "aes");
            if has_aes::get() {
                // SAFETY: Checked `aes` feature
                let aes = unsafe {
                    aarch64::verify_sequential_aes(&seed, &key, checkpoints, checkpoint_iterations)
                };
                assert_eq!(sequential, aes);
            }
        }

        sequential
    }

    #[test]
    fn test_create_verify() {
        let seed = PotSeed::from(SEED);
        let key = PotKey::from(KEY);
        let checkpoint_iterations = 20;

        // Can encrypt/decrypt.
        let checkpoints = create(seed, key, checkpoint_iterations);
        {
            let generic_checkpoints = create_generic(seed, key, checkpoint_iterations);
            assert_eq!(checkpoints, generic_checkpoints);
        }

        assert!(verify_test(seed, key, &checkpoints, checkpoint_iterations,));

        // Decryption of invalid cipher text fails.
        let mut checkpoints_1 = checkpoints;
        checkpoints_1[0] = PotOutput::from(BAD_CIPHER);
        assert!(!verify_test(
            seed,
            key,
            &checkpoints_1,
            checkpoint_iterations,
        ));

        // Decryption with wrong number of iterations fails.
        assert!(!verify_test(
            seed,
            key,
            &checkpoints,
            checkpoint_iterations + 2,
        ));
        assert!(!verify_test(
            seed,
            key,
            &checkpoints,
            checkpoint_iterations - 2,
        ));

        // Decryption with wrong seed fails.
        assert!(!verify_test(
            PotSeed::from(SEED_1),
            key,
            &checkpoints,
            checkpoint_iterations,
        ));

        // Decryption with wrong key fails.
        assert!(!verify_test(
            seed,
            PotKey::from(KEY_1),
            &checkpoints,
            checkpoint_iterations,
        ));
    }
}
