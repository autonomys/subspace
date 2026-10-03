#[cfg(all(test, not(miri), not(target_arch = "spirv")))]
mod gpu_tests;

use crate::shader::constants::{MAX_BUCKET_SIZE, NUM_BUCKETS};
use crate::shader::types::PositionR;
use spirv_std::arch::workgroup_memory_barrier_with_group_sync;
use spirv_std::glam::UVec3;
use spirv_std::spirv;

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;

const _: () = {
    // This implementation assumes the following is true
    assert!(MAX_BUCKET_SIZE == WORKGROUP_SIZE as usize * 2);
};

#[inline(always)]
fn perform_compare_swap<T, LessOrEqual>(
    local_invocation_id: u32,
    bit_position: u32,
    block_size: usize,
    shared_bucket: &mut [T; MAX_BUCKET_SIZE],
    // TODO: Should have been just `fn()`, but https://github.com/Rust-GPU/rust-gpu/issues/452
    less_or_equal: LessOrEqual,
) where
    T: Copy,
    LessOrEqual: Fn(&T, &T) -> bool,
{
    // Take a pair `(a_offset, b_offset)` where indices differ only at `bit_position` and swaps them
    let pair_id = local_invocation_id as usize;
    // Bits above `bit_position`
    let high = (pair_id >> bit_position) << (bit_position + 1);
    // Bits below `bit_position`
    let low = pair_id & (u32::MAX as usize).unbounded_shr(u32::BITS - bit_position);
    let a_offset = high | low;
    let b_offset = a_offset | (1 << bit_position);

    // Determine the sort direction: ascending if `a_offset`'s bit at `block_size` is `0`.
    // This alternates direction in bitonic merges to create sorted sequences.
    let ascending = (a_offset & block_size) == 0;

    let a = shared_bucket[a_offset];
    let b = shared_bucket[b_offset];

    // Only update when necessary
    if less_or_equal(&a, &b) != ascending {
        shared_bucket[a_offset] = b;
        shared_bucket[b_offset] = a;
    }
}

#[inline(always)]
pub(super) fn sort_shared_bucket<T, LessOrEqual>(
    local_invocation_id: u32,
    shared_bucket: &mut [T; MAX_BUCKET_SIZE],
    // TODO: Should have been just `fn()`, but https://github.com/Rust-GPU/rust-gpu/issues/452
    less_or_equal: LessOrEqual,
) where
    T: Copy,
    LessOrEqual: Fn(&T, &T) -> bool,
{
    // Iterate over merger stages, doubling block_size each time
    for merger_stage in 1..=MAX_BUCKET_SIZE.ilog2() {
        let block_size = 1 << merger_stage;
        // For each stage, process bit positions in reverse for bitonic comparisons
        for bit_position in (0..merger_stage).rev() {
            perform_compare_swap(
                local_invocation_id,
                bit_position,
                block_size,
                shared_bucket,
                &less_or_equal,
            );

            workgroup_memory_barrier_with_group_sync();
        }
    }
}

#[inline(always)]
fn load_into_shared_bucket(
    local_invocation_id: u32,
    bucket_size: u32,
    bucket: &[PositionR; MAX_BUCKET_SIZE],
    shared_bucket: &mut [PositionR; MAX_BUCKET_SIZE],
) {
    for bucket_offset in
        (local_invocation_id as usize..MAX_BUCKET_SIZE).step_by(WORKGROUP_SIZE as usize)
    {
        shared_bucket[bucket_offset] = if bucket_offset < bucket_size as usize {
            bucket[bucket_offset]
        } else {
            PositionR::SENTINEL
        };
    }
}

#[inline(always)]
fn store_from_shared_bucket(
    local_invocation_id: u32,
    bucket: &mut [PositionR; MAX_BUCKET_SIZE],
    shared_bucket: &[PositionR; MAX_BUCKET_SIZE],
) {
    for bucket_offset in
        (local_invocation_id as usize..MAX_BUCKET_SIZE).step_by(WORKGROUP_SIZE as usize)
    {
        bucket[bucket_offset] = shared_bucket[bucket_offset];
    }
}

// TODO: Make unsafe and avoid bounds check
/// Sort a bucket using bitonic sort
fn sort_bucket_impl(
    local_invocation_id: u32,
    bucket_size: u32,
    bucket: &mut [PositionR; MAX_BUCKET_SIZE],
    shared_bucket: &mut [PositionR; MAX_BUCKET_SIZE],
) {
    load_into_shared_bucket(local_invocation_id, bucket_size, bucket, shared_bucket);

    workgroup_memory_barrier_with_group_sync();

    sort_shared_bucket(
        local_invocation_id,
        shared_bucket,
        #[inline(always)]
        |a, b| a.position <= b.position,
    );

    store_from_shared_bucket(local_invocation_id, bucket, shared_bucket);
}

/// NOTE: bucket sizes are zeroed after use
#[spirv(compute(threads(256), entry_point_name = "sort_buckets"))]
pub fn sort_buckets(
    #[spirv(workgroup_id)] workgroup_id: UVec3,
    #[spirv(local_invocation_id)] local_invocation_id: UVec3,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)] bucket_sizes: &mut [u32; NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)] buckets: &mut [[PositionR; MAX_BUCKET_SIZE];
             NUM_BUCKETS],
    #[spirv(workgroup)] shared_bucket: &mut [PositionR; MAX_BUCKET_SIZE],
) {
    let local_invocation_id = local_invocation_id.x;
    let workgroup_id = workgroup_id.x;

    // Process one bucket per workgroup
    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    let bucket_size = bucket_sizes[workgroup_id as usize];
    let bucket = &mut buckets[workgroup_id as usize];

    sort_bucket_impl(local_invocation_id, bucket_size, bucket, shared_bucket);

    if local_invocation_id == 0 {
        bucket_sizes[workgroup_id as usize] = 0;
    }
}
