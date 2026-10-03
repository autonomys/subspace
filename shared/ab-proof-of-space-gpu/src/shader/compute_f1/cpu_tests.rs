use crate::shader::compute_f1::{
    CHACHA8_BLOCK_WORDS, ELEMENTS_PER_INVOCATION, INVOCATION_KEYSTREAM_WORDS, compute_f1_impl,
};
use crate::shader::constants::PARAM_EXT;
use crate::shader::types::{X, Y};
use ab_chacha8::ChaCha8State;
use subspace_core_primitives::pos::PosProof;

// TODO: Reuse code from `ab-proof-of-space`, right now this is copy-pasted from there
/// `partial_y_offset` is in bits within `partial_y`
pub(super) fn correct_compute_f1<const K: u8>(x: X, seed: &[u8; 32]) -> Y {
    let skip_bits = u32::from(K) * u32::from(x);
    let skip_u32s = skip_bits / u32::BITS;
    let partial_y_offset = skip_bits % u32::BITS;

    let initial_state = ChaCha8State::init(seed, &[0; _]);
    let first_block_counter = skip_u32s / CHACHA8_BLOCK_WORDS as u32;
    let u32_in_first_block = skip_u32s as usize % CHACHA8_BLOCK_WORDS;

    let first_block = initial_state.compute_block(first_block_counter);
    let hi = first_block[u32_in_first_block].to_be();

    // TODO: Is SIMD version of `compute_block()` that produces two blocks at once possible?
    let lo = if u32_in_first_block + 1 == CHACHA8_BLOCK_WORDS {
        // Spilled over into the second block
        let second_block = initial_state.compute_block(first_block_counter + 1);
        second_block[0].to_be()
    } else {
        first_block[u32_in_first_block + 1].to_be()
    };

    let partial_y = (u64::from(hi) << u32::BITS) | u64::from(lo);

    let pre_y = partial_y >> (u64::BITS - u32::from(K + PARAM_EXT) - partial_y_offset);
    let pre_y = pre_y as u32;
    // Mask for clearing the rest of bits of `pre_y`.
    let pre_y_mask = (u32::MAX << PARAM_EXT) & (u32::MAX >> (u32::BITS - u32::from(K + PARAM_EXT)));

    // Extract `PARAM_EXT` most significant bits from `x` and store in the final offset of
    // eventual `y` with the rest of bits being zero (`x` is `0..2^K`)
    let pre_ext = u32::from(x) >> (K - PARAM_EXT);

    // Combine all of the bits together:
    // [padding zero bits][`K` bits from `partial_y`][`PARAM_EXT` bits from `x`]
    Y::from((pre_y & pre_y_mask) | pre_ext)
}

#[test]
fn compute_f1_cpu() {
    let seed = [1; 32];

    let initial_state = ChaCha8State::init(&seed, &[0; _]);

    // SAFETY: Data structure filled with zeroes is a valid invariant
    let mut chacha8_keystream =
        unsafe { Box::<[u32; INVOCATION_KEYSTREAM_WORDS]>::new_zeroed().assume_init() };

    for (counter, block) in chacha8_keystream.as_chunks_mut().0.iter_mut().enumerate() {
        *block = initial_state.compute_block(counter as u32);
    }

    for x in (X::ZERO..).take(ELEMENTS_PER_INVOCATION as usize) {
        assert_eq!(
            correct_compute_f1::<{ PosProof::K }>(x, &seed),
            compute_f1_impl(x, &chacha8_keystream),
            "X={x:?}"
        );
    }
}
