use crate::shader::constants::{K, NUM_MATCH_BUCKETS, NUM_S_BUCKETS, REDUCED_MATCHES_COUNT};
use crate::shader::find_matches_and_compute_f7::{NUM_ELEMENTS_PER_S_BUCKET, ProofTargets};
use crate::shader::find_proofs::PROOF_BYTES;
use crate::shader::types::{Position, X};
use subspace_core_primitives::pieces::Record;

pub(super) fn find_proofs_correct(
    table_2_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_3_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_4_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_5_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_6_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    bucket_sizes: &[u32; NUM_S_BUCKETS],
    buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
) -> (
    Box<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>,
    Box<[[u8; PROOF_BYTES]; NUM_S_BUCKETS]>,
) {
    // SAFETY: Data structure filled with zeroes is a valid invariant
    let mut found_proofs = unsafe {
        Box::<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>::new_zeroed().assume_init()
    };
    // SAFETY: Data structure filled with zeroes is a valid invariant
    let mut proofs =
        unsafe { Box::<[[u8; PROOF_BYTES]; NUM_S_BUCKETS]>::new_zeroed().assume_init() };

    for (((bucket_sizes, table_6_proof_targets), proofs), found_proofs) in bucket_sizes
        .as_chunks::<{ u8::BITS as usize }>()
        .0
        .iter()
        .zip(buckets.as_chunks::<{ u8::BITS as usize }>().0.iter())
        .zip(proofs.as_chunks_mut::<{ u8::BITS as usize }>().0.iter_mut())
        .zip(found_proofs.iter_mut())
    {
        for (proof_offset, ((&bucket_size, proof), table_6_proof_targets)) in bucket_sizes
            .iter()
            .zip(proofs)
            .zip(table_6_proof_targets)
            .enumerate()
        {
            if bucket_size != 0 {
                let table_6_proof_targets = table_6_proof_targets[..bucket_size as usize]
                    .iter()
                    .min_by_key(|proof_targets| proof_targets.absolute_position)
                    .unwrap();
                *proof = find_proof_raw_internal(
                    table_2_positions,
                    table_3_positions,
                    table_4_positions,
                    table_5_positions,
                    table_6_positions,
                    table_6_proof_targets.positions,
                );

                *found_proofs |= 1 << proof_offset;
            }
        }
    }

    (found_proofs, proofs)
}

fn find_proof_raw_internal(
    table_2_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_3_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_4_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_5_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_6_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_6_proof_targets: [Position; 2],
) -> [u8; PROOF_BYTES] {
    let mut proof = [0u8; PROOF_BYTES];

    // TODO: Optimize with SIMD
    table_6_proof_targets
        .into_iter()
        .flat_map(|position| table_6_positions.as_flattened()[position as usize])
        .flat_map(|position| table_5_positions.as_flattened()[position as usize])
        .flat_map(|position| table_4_positions.as_flattened()[position as usize])
        .flat_map(|position| table_3_positions.as_flattened()[position as usize])
        .flat_map(|position| table_2_positions.as_flattened()[position as usize])
        .map(|position| {
            // X matches position
            X::from(position)
        })
        .enumerate()
        .for_each(|(offset, x)| {
            let x_offset_in_bits = usize::from(K) * offset;
            // Collect bytes where bits of `x` will be written
            let proof_bytes = &mut proof[x_offset_in_bits / u8::BITS as usize..]
                [..(x_offset_in_bits % u8::BITS as usize + usize::from(K))
                    .div_ceil(u8::BITS as usize)];

            // Bits of `x` already shifted to the correct location as they will appear
            // in `proof`
            let x_shifted = u32::from(x)
                << (u32::BITS as usize - (usize::from(K) + x_offset_in_bits % u8::BITS as usize));

            // Copy `x` bits into proof
            x_shifted
                .to_be_bytes()
                .iter()
                .zip(proof_bytes)
                .for_each(|(from, to)| {
                    *to |= from;
                });
        });

    proof
}
