use core::arch::aarch64::*;
use core::simd::u8x16;
use core::slice;
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
    let xor_key = veorq_u8(keys[10], keys[0]);
    let mut seed = uint8x16_t::from(u8x16::from(*seed));
    seed = veorq_u8(seed, keys[10]);
    for checkpoint in checkpoints.iter_mut() {
        for _ in 0..checkpoint_iterations {
            seed = vaesmcq_u8(vaeseq_u8(seed, xor_key));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[1]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[2]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[3]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[4]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[5]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[6]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[7]));
            seed = vaesmcq_u8(vaeseq_u8(seed, keys[8]));
            seed = vaeseq_u8(seed, keys[9]);
        }

        let checkpoint_reg = veorq_u8(seed, keys[10]);
        **checkpoint = u8x16::from(checkpoint_reg).to_array();
    }

    checkpoints
}

/// Verification mimics `create` function, but also has decryption half for better performance
#[target_feature(enable = "aes")]
#[inline]
pub(super) fn verify_sequential_aes(
    seed: &[u8; 16],
    key: &[u8; 16],
    checkpoints: &PotCheckpoints,
    checkpoint_iterations: u32,
) -> bool {
    let checkpoints = PotOutput::repr_from_slice(checkpoints.as_slice());

    let keys = expand_key(key);
    let xor_key = veorq_u8(keys[10], keys[0]);

    // Invert keys for decryption, the first and last element is not used below, hence they are
    // copied as is from encryption keys (otherwise the first and last element would need to be
    // swapped)
    let mut inv_keys = keys;
    for i in 1..10 {
        inv_keys[i] = vaesimcq_u8(keys[10 - i]);
    }

    let mut inputs: [uint8x16_t; PotCheckpoints::NUM_CHECKPOINTS.get() as usize] = [
        uint8x16_t::from(u8x16::from(*seed)),
        uint8x16_t::from(u8x16::from(checkpoints[0])),
        uint8x16_t::from(u8x16::from(checkpoints[1])),
        uint8x16_t::from(u8x16::from(checkpoints[2])),
        uint8x16_t::from(u8x16::from(checkpoints[3])),
        uint8x16_t::from(u8x16::from(checkpoints[4])),
        uint8x16_t::from(u8x16::from(checkpoints[5])),
        uint8x16_t::from(u8x16::from(checkpoints[6])),
    ];

    let mut outputs: [uint8x16_t; PotCheckpoints::NUM_CHECKPOINTS.get() as usize] = [
        uint8x16_t::from(u8x16::from(checkpoints[0])),
        uint8x16_t::from(u8x16::from(checkpoints[1])),
        uint8x16_t::from(u8x16::from(checkpoints[2])),
        uint8x16_t::from(u8x16::from(checkpoints[3])),
        uint8x16_t::from(u8x16::from(checkpoints[4])),
        uint8x16_t::from(u8x16::from(checkpoints[5])),
        uint8x16_t::from(u8x16::from(checkpoints[6])),
        uint8x16_t::from(u8x16::from(checkpoints[7])),
    ];

    inputs = inputs.map(|input| veorq_u8(input, keys[10]));
    outputs = outputs.map(|output| veorq_u8(output, keys[0]));

    for _ in 0..checkpoint_iterations / 2 {
        inputs = inputs.map(|input| vaesmcq_u8(vaeseq_u8(input, xor_key)));
        outputs = outputs.map(|output| vaesimcq_u8(vaesdq_u8(output, xor_key)));

        for i in 1..9 {
            inputs = inputs.map(|input| vaesmcq_u8(vaeseq_u8(input, keys[i])));
            outputs = outputs.map(|output| vaesimcq_u8(vaesdq_u8(output, inv_keys[i])));
        }

        inputs = inputs.map(|input| vaeseq_u8(input, keys[9]));
        outputs = outputs.map(|output| vaesdq_u8(output, inv_keys[9]));
    }

    inputs.into_iter().zip(outputs).all(|(input, output)| {
        let diff = veorq_u8(input, output);
        let cmp = vceqq_u8(diff, xor_key);
        vminvq_u8(cmp) == u8::MAX
    })
}

// Below code copied with minor changes from the following place under MIT/Apache-2.0 license by
// Artyom Pavlov:
// https://github.com/RustCrypto/block-ciphers/blob/fbb68f40b122909d92e40ee8a50112b6e5d0af8f/aes/src/armv8/expand.rs

/// There are 4 AES words in a block.
const BLOCK_WORDS: usize = 4;

/// The AES (nee Rijndael) notion of a word is always 32-bits, or 4-bytes.
const WORD_SIZE: usize = 4;

/// AES round constants.
const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES key expansion.
#[target_feature(enable = "aes")]
fn expand_key(key: &[u8; 16]) -> [uint8x16_t; NUM_ROUND_KEYS] {
    let mut expanded_keys = [uint8x16_t::from(u8x16::default()); NUM_ROUND_KEYS];

    // Sanity check, as this is required in order for the subsequent conversion to be sound.
    const _: () = assert!(align_of::<uint8x16_t>() >= align_of::<u32>());
    let columns = unsafe {
        slice::from_raw_parts_mut(
            expanded_keys.as_mut_ptr().cast::<u32>(),
            NUM_ROUND_KEYS * BLOCK_WORDS,
        )
    };

    for (i, chunk) in key.array_chunks::<WORD_SIZE>().enumerate() {
        columns[i] = u32::from_ne_bytes(*chunk);
    }

    // From "The Rijndael Block Cipher" Section 4.1:
    // > The number of columns of the Cipher Key is denoted by `Nk` and is
    // > equal to the key length divided by 32 [bits].
    let nk = 16 / WORD_SIZE;

    for i in nk..NUM_ROUND_KEYS * BLOCK_WORDS {
        let mut word = columns[i - 1];

        if i % nk == 0 {
            word = sub_word(word).rotate_right(8) ^ ROUND_CONSTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            word = sub_word(word);
        }

        columns[i] = columns[i - nk] ^ word;
    }

    expanded_keys
}

/// Sub bytes for a single AES word: used for key expansion
#[target_feature(enable = "aes")]
fn sub_word(input: u32) -> u32 {
    let input = vreinterpretq_u8_u32(vdupq_n_u32(input));

    // AES single round encryption (with a "round" key of all zeros)
    let sub_input = vaeseq_u8(input, vdupq_n_u8(0));

    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(sub_input))
}
