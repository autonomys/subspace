use crate::shader::compute_fn::cpu_tests::correct_compute_fn;
use crate::shader::constants::{
    MAX_BUCKET_SIZE, NUM_BUCKETS, NUM_MATCH_BUCKETS, PARAM_BC, REDUCED_BUCKET_SIZE,
    REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_in_buckets::cpu_tests::find_matches_in_buckets_correct;
use crate::shader::types::{Metadata, Position, PositionExt, PositionR, Y};
use std::mem::MaybeUninit;

pub(super) fn find_matches_and_compute_f2_correct<
    'a,
    const TABLE_NUMBER: u8,
    const PARENT_TABLE_NUMBER: u8,
>(
    parent_buckets: &[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    buckets: &'a mut [[MaybeUninit<PositionR>; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    positions: &mut [[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    metadatas: &mut [[MaybeUninit<Metadata>; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
) -> &'a [[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS] {
    let mut matches = [MaybeUninit::uninit(); _];

    let mut bucket_offsets = [0_u16; NUM_BUCKETS];
    for (left_bucket_index, (([left_bucket, right_bucket], positions), metadatas)) in parent_buckets
        .array_windows()
        .zip(positions)
        .zip(metadatas)
        .enumerate()
    {
        let left_bucket_base = left_bucket_index as u32 * u32::from(PARAM_BC);
        let metadatas_offset = (left_bucket_index * REDUCED_MATCHES_COUNT) as u32;

        let (matches, rmap) = find_matches_in_buckets_correct(
            left_bucket_index as u32,
            left_bucket,
            right_bucket,
            &mut matches,
        );

        for (index, ((m, match_positions), match_metadata)) in
            matches.iter().zip(positions).zip(metadatas).enumerate()
        {
            // SAFETY: Guaranteed by function contract
            let (bucket_offset, r_target, positions_offset) = m.split();

            let left_position_r = left_bucket[bucket_offset as usize];
            let left_position = left_position_r.position;
            let left_r = left_position_r.r.get();

            // SAFETY: `r_target` is guaranteed to be within `0..PARAM_BC` range by `Match`
            // constructor
            let right_positions = unsafe { rmap.get(r_target) };
            // SAFETY: `positions_offset` is always either `0` or `1`
            let right_position =
                *unsafe { right_positions.get_unchecked(positions_offset as usize) };

            let left_metadata = Metadata::from(left_position);
            let right_metadata = Metadata::from(right_position);
            let (y, metadata) = correct_compute_fn::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                Y::from(left_bucket_base + left_r),
                left_metadata,
                right_metadata,
            );
            let (bucket_index, r) = y.into_bucket_index_and_r();

            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            let bucket_offset = unsafe { bucket_offsets.get_unchecked_mut(bucket_index as usize) };
            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            let bucket = unsafe { buckets.get_unchecked_mut(bucket_index as usize) };

            if *bucket_offset < REDUCED_BUCKET_SIZE as u16 {
                bucket[*bucket_offset as usize].write(PositionR {
                    position: Position::from_u32(metadatas_offset + index as u32),
                    r,
                });
                match_positions.write([left_position, right_position]);
                match_metadata.write(metadata);
                *bucket_offset += 1;
            }
        }
    }

    for (bucket, initialized) in buckets.iter_mut().zip(bucket_offsets) {
        bucket[usize::from(initialized)..].write_filled(PositionR::SENTINEL);
    }

    // SAFETY: All entries are initialized
    unsafe { &*buckets.as_ptr().cast() }
}
