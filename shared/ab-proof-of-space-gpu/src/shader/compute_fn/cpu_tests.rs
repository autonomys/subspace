use crate::shader::compute_fn::{compute_fn_impl, metadata_size_bits, y_size_bits};
use crate::shader::constants::K;
use crate::shader::types::{Metadata, Y};
use crate::shader::u32n::U32N;
use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use std::array;

// TODO: Reuse code from `ab-proof-of-space`, right now this is copy-pasted from there
pub(in super::super) fn correct_compute_fn<
    const TABLE_NUMBER: u8,
    const PARENT_TABLE_NUMBER: u8,
>(
    y: Y,
    left_metadata: Metadata,
    right_metadata: Metadata,
) -> (Y, Metadata) {
    let left_metadata = U32N::<4>::from(left_metadata);
    let right_metadata = U32N::<4>::from(right_metadata);

    let parent_metadata_bits = metadata_size_bits(K, PARENT_TABLE_NUMBER);

    // Only supports `K` from 15 to 25 (otherwise math will not be correct when concatenating y,
    // left metadata and right metadata)
    let hash = {
        // Take only bytes where bits were set
        let num_bytes_with_data =
            (y_size_bits(K) + parent_metadata_bits * 2).div_ceil(u8::BITS) as usize;

        // Collect `K` most significant bits of `y` at the final offset of eventual `input_a`
        let y_bits = U32N::<4>::from(y) << (U32N::<4>::BITS - y_size_bits(K));

        // Move bits of `left_metadata` at the final offset of eventual `input_a`
        let left_metadata_bits =
            left_metadata << (U32N::<4>::BITS - parent_metadata_bits - y_size_bits(K));

        // Part of the `right_bits` at the final offset of eventual `input_a`
        let y_and_left_bits = y_size_bits(K) + parent_metadata_bits;
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

            let input = [input_a.to_be_bytes(), input_b.to_be_bytes()];
            let input_len =
                size_of::<U32N<4>>() + right_bits_pushed_into_input_b.div_ceil(u8::BITS) as usize;
            ab_blake3::single_block_hash(&input.as_flattened()[..input_len])
                .expect("Exactly a single block worth of bytes; qed")
        } else {
            let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
            let input_a = y_bits | left_metadata_bits | right_bits_a;

            ab_blake3::single_block_hash(&input_a.to_be_bytes()[..num_bytes_with_data])
                .expect("Less than a single block worth of bytes; qed")
        }
    };

    let y_output = Y::from(
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) >> (u32::BITS - y_size_bits(K)),
    );

    let metadata_size_bits = metadata_size_bits(K, TABLE_NUMBER);

    let metadata = if TABLE_NUMBER < 4 {
        Metadata::from(((left_metadata << parent_metadata_bits) | right_metadata).cast())
    } else if metadata_size_bits > 0 {
        // For K up to 25 it is guaranteed that metadata + bit offset will always fit into u128.
        // We collect the bytes necessary, potentially with extra bits at the start and end of the
        // bytes that will be taken care of later.
        let metadata = U32N::<4>::from_be_bytes(
            hash[(y_size_bits(K) / u8::BITS) as usize..][..size_of::<U32N<4>>()]
                .try_into()
                .expect("Always enough bits for any K; qed"),
        );
        // Remove extra bits at the beginning
        let metadata = metadata << (y_size_bits(K) % u8::BITS);
        // Move bits into the correct location
        Metadata::from((metadata >> (U32N::<4>::BITS - metadata_size_bits)).cast())
    } else {
        Metadata::default()
    };

    (y_output, metadata)
}

pub(super) fn random_y(rng: &mut ChaCha8Rng) -> Y {
    Y::from(rng.next_u32() >> (u32::BITS - y_size_bits(K)))
}

pub(in super::super) fn random_metadata<const TABLE_NUMBER: u8>(rng: &mut ChaCha8Rng) -> Metadata {
    if metadata_size_bits(K, TABLE_NUMBER) == 0 {
        return Metadata::from(U32N::ZERO);
    }
    Metadata::from(
        (U32N::<4>::from_le_u32_words_as_be_bytes(&array::from_fn(|_| rng.next_u32()))
            >> (U32N::<4>::BITS - metadata_size_bits(K, TABLE_NUMBER)))
        .cast(),
    )
}

fn test_compute_fn_cpu_impl<const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    rng: &mut ChaCha8Rng,
) {
    let y = random_y(rng);
    let left_metadata = random_metadata::<PARENT_TABLE_NUMBER>(rng);
    let right_metadata = random_metadata::<PARENT_TABLE_NUMBER>(rng);

    assert_eq!(
        correct_compute_fn::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(y, left_metadata, right_metadata),
        compute_fn_impl::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(y, left_metadata, right_metadata),
        "TABLE_NUMBER={TABLE_NUMBER}: Y={y:?}, left_metadata={left_metadata:?}, right_metadata={right_metadata:?}"
    );
}

#[test]
fn compute_fn_cpu() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());

    // Just some random comparisons against reference implementation
    for _ in 0..10u8 {
        test_compute_fn_cpu_impl::<2, 1>(&mut rng);
        test_compute_fn_cpu_impl::<3, 2>(&mut rng);
        test_compute_fn_cpu_impl::<4, 3>(&mut rng);
        test_compute_fn_cpu_impl::<5, 4>(&mut rng);
        test_compute_fn_cpu_impl::<6, 5>(&mut rng);
        test_compute_fn_cpu_impl::<7, 6>(&mut rng);
    }
}
