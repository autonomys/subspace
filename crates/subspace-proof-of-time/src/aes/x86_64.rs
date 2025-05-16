use core::arch::x86_64::*;
use core::mem;
use subspace_core_primitives::pot::PotCheckpoints;

/// Create PoT proof with checkpoints
#[target_feature(enable = "aes")]
#[inline]
pub(super) unsafe fn create(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoint_iterations: u32,
) -> PotCheckpoints { unsafe {
    let mut checkpoints = PotCheckpoints::default();

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
        _mm_storeu_si128(
            checkpoint.as_mut().as_mut_ptr() as *mut __m128i,
            checkpoint_reg,
        );
    }

    checkpoints
}}

// Below code copied with minor changes from following place under MIT/Apache-2.0 license by Artyom
// Pavlov:
// https://github.com/RustCrypto/block-ciphers/blob/9413fcadd28d53854954498c0589b747d8e4ade2/aes/src/ni/aes128.rs

/// AES-128 round keys
type RoundKeys = [__m128i; 11];

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
unsafe fn expand_key(key: &[u8; 16]) -> RoundKeys { unsafe {
    // SAFETY: `RoundKeys` is a `[__m128i; 11]` which can be initialized
    // with all zeroes.
    let mut keys: RoundKeys = mem::zeroed();

    let k = _mm_loadu_si128(key.as_ptr() as *const __m128i);
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
}}
