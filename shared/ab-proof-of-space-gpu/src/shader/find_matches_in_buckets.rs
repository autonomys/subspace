#[cfg(all(test, not(target_arch = "spirv")))]
pub(super) mod cpu_tests;
#[cfg(all(test, not(miri), not(target_arch = "spirv")))]
mod gpu_tests;
pub mod rmap;

use crate::shader::constants::{
    MAX_BUCKET_SIZE, PARAM_B, PARAM_C, PARAM_M, REDUCED_BUCKET_SIZE, REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_in_buckets::rmap::Rmap;
use crate::shader::sort_buckets::sort_shared_bucket;
use crate::shader::types::{Match, Position, PositionExt, PositionR, R};
use core::mem::MaybeUninit;
use spirv_std::arch::{atomic_i_add, workgroup_memory_barrier_with_group_sync};
use spirv_std::glam::UVec3;
use spirv_std::memory::{Scope, Semantics};
use spirv_std::spirv;

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;

fn calculate_left_target_on_demand(parity: u32, r: u32, m: u32) -> u32 {
    let param_b = u32::from(PARAM_B);
    let param_c = u32::from(PARAM_C);

    ((r / param_c + m) % param_b) * param_c + (((2 * m + parity) * (2 * m + parity) + r) % param_c)
}

#[derive(Debug, Copy, Clone)]
pub struct FindMatchesShared {
    rmap: Rmap,
    matches_counter: u32,
}

// TODO: Reuse code from `ab-proof-of-space` after https://github.com/Rust-GPU/rust-gpu/pull/249 and
//  https://github.com/Rust-GPU/rust-gpu/discussions/301
/// Returns the number of matches found.
///
/// # Safety
/// Must be called from [`WORKGROUP_SIZE`] threads with `local_invocation_id` corresponding to the
/// thread index. All buckets must contain valid positions.
// TODO: Try to reduce the `matches` size further by processing `left_bucket` in chunks (like halves
//  for example)
#[inline(always)]
pub(super) unsafe fn find_matches_in_buckets_impl(
    local_invocation_id: u32,
    left_bucket_index: u32,
    // TODO: These should use `REDUCED_BUCKET_SIZE`, but it currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    left_bucket: &[PositionR; MAX_BUCKET_SIZE],
    right_bucket: &[PositionR; MAX_BUCKET_SIZE],
    matches: &mut [MaybeUninit<Match>; MAX_BUCKET_SIZE],
    shared: &mut FindMatchesShared,
) -> u32 {
    const CHUNK_SIZE: usize = WORKGROUP_SIZE as usize / PARAM_M as usize;

    const {
        // `CHUNK_SIZE` with `PARAM_M` must cover workgroup exactly
        assert!(CHUNK_SIZE as u32 * PARAM_M as u32 == WORKGROUP_SIZE);
        // The bucket size should be possible to iterate in exact chunks
        assert!(REDUCED_BUCKET_SIZE.is_multiple_of(CHUNK_SIZE));
    }

    let FindMatchesShared {
        rmap,
        matches_counter,
    } = shared;

    for index in
        (local_invocation_id as usize..REDUCED_BUCKET_SIZE).step_by(WORKGROUP_SIZE as usize)
    {
        let PositionR { position, r } = right_bucket[index];

        // TODO: Wouldn't it make more sense to check the size here instead of sentinel?
        if position == Position::SENTINEL {
            break;
        }

        rmap.add_with_data_parallel(r);
    }

    workgroup_memory_barrier_with_group_sync();

    let parity = left_bucket_index % 2;
    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    for chunk_index in 0..REDUCED_BUCKET_SIZE / CHUNK_SIZE {
        // First `PARAM_M` invocations in a workgroup process the first chunk index, next
        // `PARAM_M` process the second chunk index and so on, with each chunk index corresponding
        // to `PARAM_M` `r_target` values
        let index_within_chunk = local_invocation_id as usize / PARAM_M as usize;
        let bucket_offset = chunk_index * CHUNK_SIZE + index_within_chunk;
        let PositionR { position, r } = left_bucket[bucket_offset];
        let left_r = r.get();

        // TODO: Wouldn't it make more sense to check the size here instead of sentinel?
        // Check if reached the end of the bucket
        let (m, local_matches_count) = if position == Position::SENTINEL {
            (Match::SENTINEL, 0)
        } else {
            let m = local_invocation_id % u32::from(PARAM_M);
            let r_target = calculate_left_target_on_demand(parity, left_r, m);

            // SAFETY: Right targets are guaranteed to be within `0..PARAM_BC` range
            let local_matches_count = rmap.num_r_items(unsafe { R::new(r_target) });

            let m = if local_matches_count == 0 {
                Match::SENTINEL
            } else {
                // SAFETY: `bucket_offset` is guaranteed to be within `0..MAX_BUCKET_SIZE` range,
                // `m` is guaranteed to be within `0..PARAM_M` range, `r_target` is guaranteed to be
                // within `0..PARAM_BC` range

                unsafe { Match::new(bucket_offset as u32, m, r_target) }
            };

            (m, local_matches_count)
        };

        if local_matches_count >= 1 {
            // SAFETY: TODO: Probably should not be unsafe to begin with:
            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
            let local_matches_offset = unsafe {
                atomic_i_add::<_, const { Scope::Workgroup as u32 }, const { Semantics::NONE.bits() }>(
                    matches_counter,
                    local_matches_count,
                )
            };
            matches[local_matches_offset as usize].write(m);

            if local_matches_count == 2 {
                matches[local_matches_offset as usize + 1].write(m.second_second_position());
            }
        }
    }

    workgroup_memory_barrier_with_group_sync();

    let matches_counter = *matches_counter;

    for index in ((matches_counter + local_invocation_id) as usize..MAX_BUCKET_SIZE)
        .step_by(WORKGROUP_SIZE as usize)
    {
        matches[index].write(Match::SENTINEL);
    }

    workgroup_memory_barrier_with_group_sync();

    sort_shared_bucket(local_invocation_id, matches, |a, b| {
        // SAFETY: Initialized above
        unsafe { a.assume_init() }.cmp_key() <= unsafe { b.assume_init() }.cmp_key()
    });

    matches_counter.min(REDUCED_MATCHES_COUNT as u32)
}

/// # Safety
/// Must be called from [`WORKGROUP_SIZE`] threads. All buckets must contain valid positions.
#[spirv(compute(threads(256), entry_point_name = "find_matches_in_buckets"))]
pub unsafe fn find_matches_in_buckets(
    #[spirv(local_invocation_id)] local_invocation_id: UVec3,
    #[spirv(workgroup_id)] workgroup_id: UVec3,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)] buckets: &[[PositionR;
          MAX_BUCKET_SIZE]],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)] matches: &mut [[MaybeUninit<Match>;
              MAX_BUCKET_SIZE]],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 2)] matches_counts: &mut [MaybeUninit<
        u32,
    >],
    #[spirv(workgroup)] shared: &mut FindMatchesShared,
) {
    let local_invocation_id = local_invocation_id.x;
    let workgroup_id = workgroup_id.x;

    let left_bucket_index = workgroup_id as usize;
    if left_bucket_index >= buckets.len() - 1 {
        return;
    }

    let left_bucket = &buckets[left_bucket_index];
    let right_bucket = &buckets[left_bucket_index + 1];
    let matches = &mut matches[left_bucket_index];
    let matches_count = &mut matches_counts[left_bucket_index];

    // TODO: Truncate buckets to reduced size here once it compiles:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    // SAFETY: Guaranteed by function contract
    matches_count.write(unsafe {
        find_matches_in_buckets_impl(
            local_invocation_id,
            left_bucket_index as u32,
            left_bucket,
            right_bucket,
            matches,
            shared,
        )
    });
}
