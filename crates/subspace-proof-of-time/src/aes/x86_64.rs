use core::arch::x86_64::*;
use core::array;
use core::simd::{u8x16, u8x64};
use subspace_core_primitives::pot::{PotCheckpoints, PotOutput};

const NUM_ROUND_KEYS: usize = 11;

/// Create PoT proof with checkpoints
#[target_feature(enable = "aes")]
#[inline]
pub(super) fn create(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoint_iterations: u32,
) -> PotCheckpoints {
    let mut checkpoints = PotCheckpoints::default();

    let keys_reg = expand_key(key);
    let xor_key = _mm_xor_si128(keys_reg[10], keys_reg[0]);
    let mut seed_reg = __m128i::from(u8x16::from_array(*seed));
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
        **checkpoint = u8x16::from(checkpoint_reg).to_array();
    }

    checkpoints
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "avx512f,vaes")]
#[inline]
pub(super) fn verify_sequential_avx512f(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let checkpoints = PotOutput::repr_from_slice(checkpoints.as_slice());

    let keys = expand_key(key);
    let xor_key = _mm_xor_si128(keys[10], keys[0]);
    let xor_key_512 = _mm512_broadcast_i32x4(xor_key);

    // Invert keys for decryption, the first and last element is not used below, hence they are
    // copied as is from encryption keys (otherwise the first and last element would need to be
    // swapped)
    let mut inv_keys = keys;
    for i in 1..10 {
        inv_keys[i] = _mm_aesimc_si128(keys[10 - i]);
    }

    let keys_512 = array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm512_broadcast_i32x4(keys[i]));
    let inv_keys_512 =
        array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm512_broadcast_i32x4(inv_keys[i]));

    let mut input_0 = [[0u8; 16]; 4];
    input_0[0] = *seed;
    input_0[1..].copy_from_slice(&checkpoints[..3]);
    let mut input_0 = __m512i::from(u8x64::from_slice(input_0.as_flattened()));
    let mut input_1 = __m512i::from(u8x64::from_slice(checkpoints[3..7].as_flattened()));

    let mut output_0 = __m512i::from(u8x64::from_slice(checkpoints[0..4].as_flattened()));
    let mut output_1 = __m512i::from(u8x64::from_slice(checkpoints[4..8].as_flattened()));

    input_0 = _mm512_xor_si512(input_0, keys_512[0]);
    input_1 = _mm512_xor_si512(input_1, keys_512[0]);

    output_0 = _mm512_xor_si512(output_0, keys_512[10]);
    output_1 = _mm512_xor_si512(output_1, keys_512[10]);

    for _ in 0..checkpoint_iterations / 2 {
        // TODO: Shouldn't be unsafe: https://github.com/rust-lang/rust/issues/141718
        unsafe {
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

// Below code copied with minor changes from the following place under MIT/Apache-2.0 license by
// Artyom Pavlov:
// https://github.com/RustCrypto/block-ciphers/blob/fbb68f40b122909d92e40ee8a50112b6e5d0af8f/aes/src/ni/expand.rs

#[target_feature(enable = "aes")]
fn expand_key(key: &[u8; 16]) -> [__m128i; NUM_ROUND_KEYS] {
    #[target_feature(enable = "aes")]
    fn expand_round<const RK: i32>(keys: &mut [__m128i; NUM_ROUND_KEYS], pos: usize) {
        let mut t1 = keys[pos - 1];
        let mut t2;
        let mut t3;

        t2 = _mm_aeskeygenassist_si128::<RK>(t1);
        t2 = _mm_shuffle_epi32::<0xff>(t2);
        t3 = _mm_slli_si128::<0x4>(t1);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128::<0x4>(t3);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128::<0x4>(t3);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);

        keys[pos] = t1;
    }

    let mut keys = [_mm_setzero_si128(); NUM_ROUND_KEYS];
    keys[0] = __m128i::from(u8x16::from(*key));

    let kr = &mut keys;
    expand_round::<0x01>(kr, 1);
    expand_round::<0x02>(kr, 2);
    expand_round::<0x04>(kr, 3);
    expand_round::<0x08>(kr, 4);
    expand_round::<0x10>(kr, 5);
    expand_round::<0x20>(kr, 6);
    expand_round::<0x40>(kr, 7);
    expand_round::<0x80>(kr, 8);
    expand_round::<0x1B>(kr, 9);
    expand_round::<0x36>(kr, 10);

    keys
}
