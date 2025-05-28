use core::arch::x86_64::*;
use core::{array, mem};
use subspace_core_primitives::pot::{PotCheckpoints, PotOutput};

const NUM_ROUND_KEYS: usize = 11;

/// Create PoT proof with checkpoints
#[target_feature(enable = "aes")]
#[inline]
pub(super) unsafe fn create(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoint_iterations: u32,
) -> PotCheckpoints {
    let mut checkpoints = PotCheckpoints::default();

    unsafe {
        let keys_reg = expand_key(key);
        let xor_key = _mm_xor_si128(keys_reg[10], keys_reg[0]);
        let mut seed_reg = _mm_loadu_si128(seed.as_ptr() as *const __m128i);
        seed_reg = _mm_xor_si128(seed_reg, keys_reg[0]);
        for checkpoint in checkpoints.iter_mut() {
            for _ in 0..checkpoint_iterations {
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[1]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[2]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[3]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[4]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[5]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[6]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[7]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[8]);
                seed_reg = _mm_aesenc_si128(seed_reg, keys_reg[9]);
                seed_reg = _mm_aesenclast_si128(seed_reg, xor_key);
            }

            let checkpoint_reg = _mm_xor_si128(seed_reg, keys_reg[0]);
            _mm_storeu_si128(checkpoint.as_mut_ptr() as *mut __m128i, checkpoint_reg);
        }
    }

    checkpoints
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "avx512f,vaes")]
#[inline]
pub(super) unsafe fn verify_sequential_avx512f(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let checkpoints = PotOutput::repr_from_slice(checkpoints.as_slice());

    unsafe {
        let keys_reg = expand_key(key);
        let xor_key = _mm_xor_si128(keys_reg[10], keys_reg[0]);
        let xor_key_512 = _mm512_broadcast_i32x4(xor_key);

        // Invert keys for decryption
        let mut inv_keys = keys_reg;
        for i in 1..10 {
            inv_keys[i] = _mm_aesimc_si128(keys_reg[10 - i]);
        }

        let keys_512 = array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm512_broadcast_i32x4(keys_reg[i]));
        let inv_keys_512 =
            array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm512_broadcast_i32x4(inv_keys[i]));

        let mut input_0 = [[0u8; 16]; 4];
        input_0[0] = *seed;
        input_0[1..].copy_from_slice(&checkpoints[..3]);
        let mut input_0 = _mm512_loadu_si512(input_0.as_ptr() as *const __m512i);
        let mut input_1 = _mm512_loadu_si512(checkpoints[3..7].as_ptr() as *const __m512i);

        let mut output_0 = _mm512_loadu_si512(checkpoints[0..4].as_ptr() as *const __m512i);
        let mut output_1 = _mm512_loadu_si512(checkpoints[4..8].as_ptr() as *const __m512i);

        input_0 = _mm512_xor_si512(input_0, keys_512[0]);
        input_1 = _mm512_xor_si512(input_1, keys_512[0]);

        output_0 = _mm512_xor_si512(output_0, keys_512[10]);
        output_1 = _mm512_xor_si512(output_1, keys_512[10]);

        for _ in 0..checkpoint_iterations / 2 {
            for i in 1..10 {
                input_0 = _mm512_aesenc_epi128(input_0, keys_512[i]);
                input_1 = _mm512_aesenc_epi128(input_1, keys_512[i]);

                output_0 = _mm512_aesdec_epi128(output_0, inv_keys_512[i]);
                output_1 = _mm512_aesdec_epi128(output_1, inv_keys_512[i]);
            }

            input_0 = _mm512_aesenclast_epi128(input_0, xor_key_512);
            input_1 = _mm512_aesenclast_epi128(input_1, xor_key_512);

            output_0 = _mm512_aesdeclast_epi128(output_0, xor_key_512);
            output_1 = _mm512_aesdeclast_epi128(output_1, xor_key_512);
        }

        // Code below is a more efficient version of this:
        // input_0 = _mm512_xor_si512(input_0, keys_512[0]);
        // input_1 = _mm512_xor_si512(input_1, keys_512[0]);
        // output_0 = _mm512_xor_si512(output_0, keys_512[10]);
        // output_1 = _mm512_xor_si512(output_1, keys_512[10]);
        //
        // let mask0 = _mm512_cmpeq_epu64_mask(input_0, output_0);
        // let mask1 = _mm512_cmpeq_epu64_mask(input_1, output_1);

        let diff_0 = _mm512_xor_si512(input_0, output_0);
        let diff_1 = _mm512_xor_si512(input_1, output_1);

        let mask0 = _mm512_cmpeq_epu64_mask(diff_0, xor_key_512);
        let mask1 = _mm512_cmpeq_epu64_mask(diff_1, xor_key_512);

        // All inputs match outputs
        (mask0 & mask1) == u8::MAX
    }
}

// Below code copied with minor changes from following place under MIT/Apache-2.0 license by Artyom
// Pavlov:
// https://github.com/RustCrypto/block-ciphers/blob/9413fcadd28d53854954498c0589b747d8e4ade2/aes/src/ni/aes128.rs

/// AES-128 round keys
type RoundKeys = [__m128i; NUM_ROUND_KEYS];

macro_rules! expand_round {
    ($keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $keys[$pos - 1];
        let mut t2;
        let mut t3;

        t2 = _mm_aeskeygenassist_si128(t1, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t3 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);

        $keys[$pos] = t1;
    };
}

#[target_feature(enable = "aes")]
#[inline]
unsafe fn expand_key(key: &[u8; 16]) -> RoundKeys {
    // SAFETY: `RoundKeys` is a `[__m128i; 11]` which can be initialized
    // with all zeroes.
    let mut keys: RoundKeys = unsafe { mem::zeroed() };

    // SAFETY: No alignment requirement in `_mm_loadu_si128`
    let k = unsafe { _mm_loadu_si128(key.as_ptr() as *const __m128i) };
    keys[0] = k;

    expand_round!(keys, 1, 0x01);
    expand_round!(keys, 2, 0x02);
    expand_round!(keys, 3, 0x04);
    expand_round!(keys, 4, 0x08);
    expand_round!(keys, 5, 0x10);
    expand_round!(keys, 6, 0x20);
    expand_round!(keys, 7, 0x40);
    expand_round!(keys, 8, 0x80);
    expand_round!(keys, 9, 0x1B);
    expand_round!(keys, 10, 0x36);

    keys
}
