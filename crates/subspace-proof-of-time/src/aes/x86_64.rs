use core::arch::x86_64::*;
use core::array;
use core::simd::{u8x16, u8x32, u8x64};
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

    let keys = expand_key(key);
    let xor_key = _mm_xor_si128(keys[10], keys[0]);
    let mut seed = __m128i::from(u8x16::from_array(*seed));
    seed = _mm_xor_si128(seed, keys[0]);
    for checkpoint in checkpoints.iter_mut() {
        for _ in 0..checkpoint_iterations {
            seed = _mm_aesenc_si128(seed, keys[1]);
            seed = _mm_aesenc_si128(seed, keys[2]);
            seed = _mm_aesenc_si128(seed, keys[3]);
            seed = _mm_aesenc_si128(seed, keys[4]);
            seed = _mm_aesenc_si128(seed, keys[5]);
            seed = _mm_aesenc_si128(seed, keys[6]);
            seed = _mm_aesenc_si128(seed, keys[7]);
            seed = _mm_aesenc_si128(seed, keys[8]);
            seed = _mm_aesenc_si128(seed, keys[9]);
            seed = _mm_aesenclast_si128(seed, xor_key);
        }

        let checkpoint_reg = _mm_xor_si128(seed, keys[0]);
        **checkpoint = u8x16::from(checkpoint_reg).to_array();
    }

    checkpoints
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "aes,sse4.1")]
#[inline]
pub(super) fn verify_sequential_aes_sse41(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let checkpoints = PotOutput::repr_from_slice(checkpoints.as_slice());

    let keys = expand_key(key);
    let xor_key = _mm_xor_si128(keys[10], keys[0]);

    // Invert keys for decryption, the first and last element is not used below, hence they are
    // copied as is from encryption keys (otherwise the first and last element would need to be
    // swapped)
    let mut inv_keys = keys;
    for i in 1..10 {
        inv_keys[i] = _mm_aesimc_si128(keys[10 - i]);
    }

    let mut inputs: [__m128i; PotCheckpoints::NUM_CHECKPOINTS.get() as usize] = [
        __m128i::from(u8x16::from(*seed)),
        __m128i::from(u8x16::from(checkpoints[0])),
        __m128i::from(u8x16::from(checkpoints[1])),
        __m128i::from(u8x16::from(checkpoints[2])),
        __m128i::from(u8x16::from(checkpoints[3])),
        __m128i::from(u8x16::from(checkpoints[4])),
        __m128i::from(u8x16::from(checkpoints[5])),
        __m128i::from(u8x16::from(checkpoints[6])),
    ];

    let mut outputs: [__m128i; PotCheckpoints::NUM_CHECKPOINTS.get() as usize] = [
        __m128i::from(u8x16::from(checkpoints[0])),
        __m128i::from(u8x16::from(checkpoints[1])),
        __m128i::from(u8x16::from(checkpoints[2])),
        __m128i::from(u8x16::from(checkpoints[3])),
        __m128i::from(u8x16::from(checkpoints[4])),
        __m128i::from(u8x16::from(checkpoints[5])),
        __m128i::from(u8x16::from(checkpoints[6])),
        __m128i::from(u8x16::from(checkpoints[7])),
    ];

    inputs = inputs.map(|input| _mm_xor_si128(input, keys[0]));
    outputs = outputs.map(|output| _mm_xor_si128(output, keys[10]));

    for _ in 0..checkpoint_iterations / 2 {
        for i in 1..10 {
            inputs = inputs.map(|input| _mm_aesenc_si128(input, keys[i]));
            outputs = outputs.map(|output| _mm_aesdec_si128(output, inv_keys[i]));
        }

        inputs = inputs.map(|input| _mm_aesenclast_si128(input, xor_key));
        outputs = outputs.map(|output| _mm_aesdeclast_si128(output, xor_key));
    }

    // All bits set
    let all_ones = _mm_set1_epi8(-1);

    inputs.into_iter().zip(outputs).all(|(input, output)| {
        let diff = _mm_xor_si128(input, output);
        let cmp = _mm_xor_si128(diff, xor_key);
        _mm_test_all_zeros(cmp, all_ones) == 1
    })
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "avx2,vaes")]
#[inline]
pub(super) fn verify_sequential_avx2_vaes(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let checkpoints = PotOutput::repr_from_slice(checkpoints.as_slice());

    let keys = expand_key(key);
    let xor_key = _mm_xor_si128(keys[10], keys[0]);
    let xor_key_256 = _mm256_broadcastsi128_si256(xor_key);

    // Invert keys for decryption, the first and last element is not used below, hence they are
    // copied as is from encryption keys (otherwise the first and last element would need to be
    // swapped)
    let mut inv_keys = keys;
    for i in 1..10 {
        inv_keys[i] = _mm_aesimc_si128(keys[10 - i]);
    }

    let keys_256 = array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm256_broadcastsi128_si256(keys[i]));
    let inv_keys_256 =
        array::from_fn::<_, NUM_ROUND_KEYS, _>(|i| _mm256_broadcastsi128_si256(inv_keys[i]));

    let mut input_0 = [[0u8; 16]; 2];
    input_0[0] = *seed;
    input_0[1] = checkpoints[0];
    let mut input_0 = __m256i::from(u8x32::from_slice(input_0.as_flattened()));

    let mut input_1 = __m256i::from(u8x32::from_slice(checkpoints[1..3].as_flattened()));
    let mut input_2 = __m256i::from(u8x32::from_slice(checkpoints[3..5].as_flattened()));
    let mut input_3 = __m256i::from(u8x32::from_slice(checkpoints[5..7].as_flattened()));

    let mut output_0 = __m256i::from(u8x32::from_slice(checkpoints[0..2].as_flattened()));
    let mut output_1 = __m256i::from(u8x32::from_slice(checkpoints[2..4].as_flattened()));
    let mut output_2 = __m256i::from(u8x32::from_slice(checkpoints[4..6].as_flattened()));
    let mut output_3 = __m256i::from(u8x32::from_slice(checkpoints[6..8].as_flattened()));

    input_0 = _mm256_xor_si256(input_0, keys_256[0]);
    input_1 = _mm256_xor_si256(input_1, keys_256[0]);
    input_2 = _mm256_xor_si256(input_2, keys_256[0]);
    input_3 = _mm256_xor_si256(input_3, keys_256[0]);

    output_0 = _mm256_xor_si256(output_0, keys_256[10]);
    output_1 = _mm256_xor_si256(output_1, keys_256[10]);
    output_2 = _mm256_xor_si256(output_2, keys_256[10]);
    output_3 = _mm256_xor_si256(output_3, keys_256[10]);

    for _ in 0..checkpoint_iterations / 2 {
        for i in 1..10 {
            input_0 = _mm256_aesenc_epi128(input_0, keys_256[i]);
            input_1 = _mm256_aesenc_epi128(input_1, keys_256[i]);
            input_2 = _mm256_aesenc_epi128(input_2, keys_256[i]);
            input_3 = _mm256_aesenc_epi128(input_3, keys_256[i]);

            output_0 = _mm256_aesdec_epi128(output_0, inv_keys_256[i]);
            output_1 = _mm256_aesdec_epi128(output_1, inv_keys_256[i]);
            output_2 = _mm256_aesdec_epi128(output_2, inv_keys_256[i]);
            output_3 = _mm256_aesdec_epi128(output_3, inv_keys_256[i]);
        }

        input_0 = _mm256_aesenclast_epi128(input_0, xor_key_256);
        input_1 = _mm256_aesenclast_epi128(input_1, xor_key_256);
        input_2 = _mm256_aesenclast_epi128(input_2, xor_key_256);
        input_3 = _mm256_aesenclast_epi128(input_3, xor_key_256);

        output_0 = _mm256_aesdeclast_epi128(output_0, xor_key_256);
        output_1 = _mm256_aesdeclast_epi128(output_1, xor_key_256);
        output_2 = _mm256_aesdeclast_epi128(output_2, xor_key_256);
        output_3 = _mm256_aesdeclast_epi128(output_3, xor_key_256);
    }

    // Code below is a more efficient version of this:
    // input_0 = _mm256_xor_si256(input_0, keys_256[0]);
    // input_1 = _mm256_xor_si256(input_1, keys_256[0]);
    // input_2 = _mm256_xor_si256(input_2, keys_256[0]);
    // input_3 = _mm256_xor_si256(input_3, keys_256[0]);
    // output_0 = _mm256_xor_si256(output_0, keys_256[10]);
    // output_1 = _mm256_xor_si256(output_1, keys_256[10]);
    // output_2 = _mm256_xor_si256(output_2, keys_256[10]);
    // output_3 = _mm256_xor_si256(output_3, keys_256[10]);
    //
    // let mask_0 = _mm256_cmpeq_epi64(input_0, output_0);
    // let mask_1 = _mm256_cmpeq_epi64(input_1, output_1);
    // let mask_2 = _mm256_cmpeq_epi64(input_2, output_1);
    // let mask_3 = _mm256_cmpeq_epi64(input_3, output_1);

    let diff_0 = _mm256_xor_si256(input_0, output_0);
    let diff_1 = _mm256_xor_si256(input_1, output_1);
    let diff_2 = _mm256_xor_si256(input_2, output_2);
    let diff_3 = _mm256_xor_si256(input_3, output_3);

    let mask_0 = _mm256_cmpeq_epi64(diff_0, xor_key_256);
    let mask_1 = _mm256_cmpeq_epi64(diff_1, xor_key_256);
    let mask_2 = _mm256_cmpeq_epi64(diff_2, xor_key_256);
    let mask_3 = _mm256_cmpeq_epi64(diff_3, xor_key_256);

    // All bits set
    let all_ones = _mm256_set1_epi64x(-1);

    let match_0 = _mm256_testc_si256(mask_0, all_ones) != 0;
    let match_1 = _mm256_testc_si256(mask_1, all_ones) != 0;
    let match_2 = _mm256_testc_si256(mask_2, all_ones) != 0;
    let match_3 = _mm256_testc_si256(mask_3, all_ones) != 0;

    match_0 && match_1 && match_2 && match_3
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "avx512f,vaes")]
#[inline]
pub(super) fn verify_sequential_avx512f_vaes(
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
    // let mask_0 = _mm512_cmpeq_epu64_mask(input_0, output_0);
    // let mask_1 = _mm512_cmpeq_epu64_mask(input_1, output_1);

    let diff_0 = _mm512_xor_si512(input_0, output_0);
    let diff_1 = _mm512_xor_si512(input_1, output_1);

    let mask_0 = _mm512_cmpeq_epu64_mask(diff_0, xor_key_512);
    let mask_1 = _mm512_cmpeq_epu64_mask(diff_1, xor_key_512);

    // All inputs match outputs
    (mask_0 & mask_1) == u8::MAX
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
