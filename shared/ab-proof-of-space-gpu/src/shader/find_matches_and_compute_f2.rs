#[cfg(all(test, not(miri), not(target_arch = "spirv")))]
mod cpu_tests;
#[cfg(all(test, not(miri), not(target_arch = "spirv")))]
mod gpu_tests;

use crate::shader::compute_fn::compute_fn_impl;
use crate::shader::constants::{
    MAX_BUCKET_SIZE, NUM_BUCKETS, NUM_MATCH_BUCKETS, PARAM_BC, REDUCED_BUCKET_SIZE,
    REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_in_buckets::{FindMatchesShared, find_matches_in_buckets_impl};
#[cfg(target_arch = "spirv")]
use crate::shader::polyfills::ArrayIndexingPolyfill;
use crate::shader::types::{Match, Metadata, Position, PositionExt, PositionR, Y};
use core::fmt;
use core::mem::MaybeUninit;
use spirv_std::arch::{atomic_i_increment, workgroup_memory_barrier_with_group_sync};
use spirv_std::glam::UVec3;
use spirv_std::memory::{Scope, Semantics};
use spirv_std::spirv;

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;
const TABLE_NUMBER: u8 = 2;
const PARENT_TABLE_NUMBER: u8 = 1;

const _: () = {
    assert!(crate::shader::find_matches_in_buckets::WORKGROUP_SIZE == WORKGROUP_SIZE);
};

// TODO: Should be union, but it currently doesn't compile:
//  https://github.com/Rust-GPU/rust-gpu/issues/241
#[derive(Copy, Clone)]
pub struct FindMatchesAndComputeF2Shared {
    find_matches_shared: FindMatchesShared,
    bucket_scratch: [PositionR; REDUCED_BUCKET_SIZE],
}

impl fmt::Debug for FindMatchesAndComputeF2Shared {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindMatchesAndComputeF2Shared")
            .finish_non_exhaustive()
    }
}

/// # Safety
/// `bucket_index` must be within range `0..REDUCED_MATCHES_COUNT`. `matches_count` elements in
/// `matches` must be initialized. `matches` must have valid pointers into left/right buckets and
/// `parent_metadatas`.
#[inline(always)]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
unsafe fn compute_f2_into_buckets_inner(
    index: u32,
    left_bucket_base: u32,
    metadatas_offset: u32,
    left_bucket: &[PositionR; MAX_BUCKET_SIZE],
    // TODO: `&[Match]` would have been nicer, but it currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    matches: &[MaybeUninit<Match>; MAX_BUCKET_SIZE],
    bucket_sizes: &mut [u32; NUM_BUCKETS],
    buckets: &mut [[MaybeUninit<PositionR>; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    positions: &mut [MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT],
    metadatas: &mut [MaybeUninit<Metadata>; REDUCED_MATCHES_COUNT],
    bucket_scratch: &[PositionR; REDUCED_BUCKET_SIZE],
) {
    // SAFETY: Guaranteed by function contract
    let (bucket_offset, r_target, positions_offset) =
        unsafe { matches.get_unchecked(index as usize).assume_init() }.split();

    // SAFETY: Guaranteed by function contract
    let left_position_r = *unsafe { left_bucket.get_unchecked(bucket_offset as usize) };
    let left_position = left_position_r.position;
    let left_r = left_position_r.r.get();

    // Repurpose variable for two purposes to save on registers
    let mut right_position_or_skip = positions_offset;
    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    #[expect(
        clippy::needless_range_loop,
        reason = "Intentional workaround for rust-gpu"
    )]
    for offset in 0..REDUCED_BUCKET_SIZE {
        let position_r = bucket_scratch[offset];
        if position_r.r.get() == r_target {
            if right_position_or_skip == 0 {
                right_position_or_skip = position_r.position;
                break;
            }

            right_position_or_skip -= 1;
        }
    }
    let right_position = right_position_or_skip;

    let left_metadata = Metadata::from(left_position);
    let right_metadata = Metadata::from(right_position);

    let (y, metadata) = compute_fn_impl::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        Y::from(left_bucket_base + left_r),
        left_metadata,
        right_metadata,
    );

    let (bucket_index, r) = y.into_bucket_index_and_r();
    // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
    let bucket_size = unsafe { bucket_sizes.get_unchecked_mut(bucket_index as usize) };
    // SAFETY: TODO: Probably should not be unsafe to begin with:
    //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
    let bucket_offset = unsafe {
        atomic_i_increment::<_, { Scope::QueueFamily as u32 }, { Semantics::NONE.bits() }>(
            bucket_size,
        )
    };

    // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition. Bucket
    // size upper bound is known statically to be [`MAX_BUCKET_SIZE`], so `bucket_offset`
    // is also always within bounds.
    unsafe {
        buckets
            .get_unchecked_mut(bucket_index as usize)
            .get_unchecked_mut(bucket_offset as usize)
    }
    .write(PositionR {
        position: Position::from_u32(metadatas_offset + index),
        r,
    });

    positions[index as usize].write([left_position, right_position]);

    metadatas[index as usize].write(metadata);
}

/// # Safety
/// `bucket_index` must be within range `0..REDUCED_MATCHES_COUNT`. `matches_count` elements in
/// `matches` must be initialized. `matches` must have valid pointers into left/right buckets and
/// `parent_metadatas`.
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
unsafe fn compute_f2_into_buckets(
    local_invocation_id: u32,
    left_bucket_index: u32,
    left_bucket: &[PositionR; MAX_BUCKET_SIZE],
    right_bucket: &[PositionR; MAX_BUCKET_SIZE],
    matches_count: usize,
    // TODO: `&[Match]` would have been nicer, but it currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    matches: &[MaybeUninit<Match>; MAX_BUCKET_SIZE],
    bucket_sizes: &mut [u32; NUM_BUCKETS],
    buckets: &mut [[MaybeUninit<PositionR>; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    positions: &mut [MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT],
    metadatas: &mut [MaybeUninit<Metadata>; REDUCED_MATCHES_COUNT],
    bucket_scratch: &mut [PositionR; REDUCED_BUCKET_SIZE],
) {
    // Load the right bucket into shared memory for faster access
    for bucket_offset in
        (local_invocation_id as usize..REDUCED_BUCKET_SIZE).step_by(WORKGROUP_SIZE as usize)
    {
        bucket_scratch[bucket_offset] = right_bucket[bucket_offset];
    }

    workgroup_memory_barrier_with_group_sync();

    let left_bucket_base = left_bucket_index * u32::from(PARAM_BC);
    let metadatas_offset = left_bucket_index * REDUCED_MATCHES_COUNT as u32;

    const {
        assert!(MAX_BUCKET_SIZE == WORKGROUP_SIZE as usize * 2);
    }
    // TODO: This should have been a loop, but register usage is too high, see:
    //  https://github.com/Rust-GPU/rust-gpu/issues/462
    // SAFETY: Guaranteed by function contract
    unsafe {
        if (local_invocation_id as usize) < matches_count {
            compute_f2_into_buckets_inner(
                local_invocation_id,
                left_bucket_base,
                metadatas_offset,
                left_bucket,
                matches,
                bucket_sizes,
                buckets,
                positions,
                metadatas,
                bucket_scratch,
            );
        }
        if ((local_invocation_id + WORKGROUP_SIZE) as usize) < matches_count {
            compute_f2_into_buckets_inner(
                local_invocation_id + WORKGROUP_SIZE,
                left_bucket_base,
                metadatas_offset,
                left_bucket,
                matches,
                bucket_sizes,
                buckets,
                positions,
                metadatas,
                bucket_scratch,
            );
        }
    }
}

/// This is similar to `find_matches_and_compute_fn`, but it doesn't use any parent table metadata.
///
/// Buckets need to be sorted by position afterward due to concurrent writes that do not have
/// deterministic order. Content of the bucket beyond the size specified in `bucket_sizes` is
/// undefined.
///
/// # Safety
/// Must be called from [`WORKGROUP_SIZE`] threads. All buckets must contain valid positions.
#[spirv(compute(threads(256), entry_point_name = "find_matches_and_compute_f2"))]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
pub unsafe fn find_matches_and_compute_f2(
    #[spirv(local_invocation_id)] local_invocation_id: UVec3,
    #[spirv(workgroup_id)] workgroup_id: UVec3,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)] parent_buckets: &[[PositionR; MAX_BUCKET_SIZE];
         NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)] bucket_sizes: &mut [u32; NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 2)] buckets: &mut [[MaybeUninit<PositionR>; MAX_BUCKET_SIZE];
             NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 3)] positions: &mut [[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT];
             NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 4)] metadatas: &mut [[MaybeUninit<Metadata>; REDUCED_MATCHES_COUNT];
             NUM_MATCH_BUCKETS],
    #[spirv(workgroup)] matches: &mut [MaybeUninit<Match>; MAX_BUCKET_SIZE],
    #[spirv(workgroup)] shared: &mut FindMatchesAndComputeF2Shared,
) {
    let local_invocation_id = local_invocation_id.x;
    let workgroup_id = workgroup_id.x;

    let left_bucket_index = workgroup_id as usize;
    let left_bucket = &parent_buckets[left_bucket_index];
    let right_bucket = &parent_buckets[left_bucket_index + 1];
    let positions = &mut positions[left_bucket_index];
    let metadatas = &mut metadatas[left_bucket_index];
    let left_bucket_index = left_bucket_index as u32;

    // TODO: Truncate buckets to reduced size here once it compiles:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    // SAFETY: Guaranteed by function contract
    let matches_count = unsafe {
        find_matches_in_buckets_impl(
            local_invocation_id,
            left_bucket_index,
            left_bucket,
            right_bucket,
            matches,
            &mut shared.find_matches_shared,
        )
    };

    // SAFETY: Guaranteed by function contract and call to `find_matches_in_buckets_impl`
    unsafe {
        compute_f2_into_buckets(
            local_invocation_id,
            left_bucket_index,
            left_bucket,
            right_bucket,
            matches_count as usize,
            matches,
            bucket_sizes,
            buckets,
            positions,
            metadatas,
            &mut shared.bucket_scratch,
        );
    }
}
