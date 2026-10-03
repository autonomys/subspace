#[cfg(all(test, not(target_arch = "spirv")))]
pub(super) mod cpu_tests;

use crate::shader::constants::{K, PARAM_EXT};
use crate::shader::types::{Metadata, Y};
use crate::shader::u32n::U32N;

// TODO: Reuse code from `ab-proof-of-space` after https://github.com/Rust-GPU/rust-gpu/pull/249 and
//  https://github.com/Rust-GPU/rust-gpu/discussions/301
/// Compute the size of `y` in bits
const fn y_size_bits(k: u8) -> u32 {
    k as u32 + PARAM_EXT as u32
}

// TODO: Reuse code from `ab-proof-of-space` after https://github.com/Rust-GPU/rust-gpu/pull/249 and
//  https://github.com/Rust-GPU/rust-gpu/discussions/301
/// Metadata size in bits
const fn metadata_size_bits(k: u8, table_number: u8) -> u32 {
    k as u32
        * match table_number {
            1 => 1,
            2 => 2,
            3 | 4 => 4,
            5 => 3,
            6 => 2,
            7 => 0,
            _ => unreachable!(),
        }
}

// TODO: Make unsafe and avoid bounds check
// TODO: Reuse code from `ab-proof-of-space` after https://github.com/Rust-GPU/rust-gpu/pull/249 and
//  https://github.com/Rust-GPU/rust-gpu/discussions/301
#[inline(always)]
pub(super) fn compute_fn_impl<const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    y: Y,
    left_metadata: Metadata,
    right_metadata: Metadata,
) -> (Y, Metadata) {
    let left_metadata = U32N::<4>::from(left_metadata);
    let right_metadata = U32N::<4>::from(right_metadata);

    // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
    //  shouldn't be necessary otherwise
    let parent_metadata_bits = const { metadata_size_bits(K, PARENT_TABLE_NUMBER) };

    // Only supports `K` from 15 to 25 (otherwise math will not be correct when concatenating y,
    // left metadata and right metadata)
    let mut input_words = [0; _];
    let byte_length = {
        // Take only bytes where bits were set
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let num_bytes_with_data =
            (const { y_size_bits(K) } + parent_metadata_bits * 2).div_ceil(u8::BITS);

        // Collect `K` most significant bits of `y` at the final offset of eventual `input_a`
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let y_bits = U32N::<4>::from(y) << (U32N::<4>::BITS - const { y_size_bits(K) });

        // Move bits of `left_metadata` at the final offset of eventual `input_a`
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let left_metadata_bits =
            left_metadata << (U32N::<4>::BITS - parent_metadata_bits - const { y_size_bits(K) });

        // Part of the `right_bits` at the final offset of eventual `input_a`
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let y_and_left_bits = const { y_size_bits(K) } + parent_metadata_bits;
        let right_bits_start_offset = U32N::<4>::BITS - parent_metadata_bits;

        // If `right_metadata` bits start to the left of the desired position in `input_a` move
        // bits right, else move left
        if right_bits_start_offset < y_and_left_bits {
            let right_bits_pushed_into_input_b = y_and_left_bits - right_bits_start_offset;
            // Collect bits of `right_metadata` that will fit into `input_a` at the final offset in
            // eventual `input_a`
            let right_bits_a = right_metadata >> right_bits_pushed_into_input_b;
            let input_a = y_bits | left_metadata_bits | right_bits_a;
            // Collect bits of `right_metadata` that will spill over into `input_b`
            let input_b = right_metadata << (U32N::<4>::BITS - right_bits_pushed_into_input_b);

            let input_a_words = input_a.as_be_bytes_to_le_u32_words();
            // TODO: Manually indexing elements and constructing an array is a workaround for
            //  rust-gpu to compile
            // input_words[..input_a_words.len()].copy_from_slice(&input_a_words);
            input_words[0] = input_a_words[0];
            input_words[1] = input_a_words[1];
            input_words[2] = input_a_words[2];
            input_words[3] = input_a_words[3];
            let input_b_words = input_b.as_be_bytes_to_le_u32_words();
            // TODO: Manually indexing elements and constructing an array is a workaround for
            //  rust-gpu to compile
            // input_words[input_a_words.len()..].copy_from_slice(&input_b_words);
            input_words[4] = input_b_words[0];
            input_words[5] = input_b_words[1];
            input_words[6] = input_b_words[2];
            input_words[7] = input_b_words[3];

            size_of::<U32N<4>>() as u32 + right_bits_pushed_into_input_b.div_ceil(u8::BITS)
        } else {
            let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
            let input_a = y_bits | left_metadata_bits | right_bits_a;
            let input_a_words = input_a.as_be_bytes_to_le_u32_words();
            // TODO: Manually indexing elements and constructing an array is a workaround for
            //  rust-gpu to compile
            // input_words[..input_a_words.len()].copy_from_slice(&input_a_words);
            input_words[0] = input_a_words[0];
            input_words[1] = input_a_words[1];
            input_words[2] = input_a_words[2];
            input_words[3] = input_a_words[3];

            num_bytes_with_data
        }
    };
    let hash = ab_blake3::single_block_hash_portable_words(&input_words, byte_length);

    // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
    //  shouldn't be necessary otherwise
    let y_output = Y::from(hash[0].to_be() >> (u32::BITS - const { y_size_bits(K) }));

    // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
    //  shouldn't be necessary otherwise
    let metadata_size_bits = const { metadata_size_bits(K, TABLE_NUMBER) };

    let metadata = if TABLE_NUMBER < 4 {
        Metadata::from(
            (left_metadata.cast::<3>() << parent_metadata_bits) | right_metadata.cast::<3>(),
        )
    } else if metadata_size_bits > 0 {
        // For K up to 24 it is guaranteed that metadata + bit offset will always fit into 4 `u32`
        // words (equivalent to `u128` size). For K=25 it'll be necessary to have fifth word, which
        // will become more cumbersome to handle. We collect bytes necessary, potentially with extra
        // bits at the start and end of the bytes that will be taken care of later.
        // TODO: Manually indexing elements and constructing an array is a workaround for rust-gpu
        //  to compile
        // let metadata = U128::from_le_u32_words_as_be_bytes(
        //     hash[(y_size_bits(K) / u32::BITS) as usize..][..size_of::<u128>() / size_of::<u32>()]
        //         .try_into()
        //         .expect("Always enough bits for any K; qed"),
        // );
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let first_element = (const { y_size_bits(K) } / u32::BITS) as usize;
        let metadata = U32N::<4>::from_le_u32_words_as_be_bytes(&[
            hash[first_element],
            hash[first_element + 1],
            hash[first_element + 2],
            hash[first_element + 3],
        ]);
        // Remove extra bits at the beginning
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        let metadata = metadata << (const { y_size_bits(K) } % u32::BITS);
        // Move bits into the correct location
        Metadata::from((metadata >> (U32N::<4>::BITS - metadata_size_bits)).cast())
    } else {
        Metadata::default()
    };

    (y_output, metadata)
}
