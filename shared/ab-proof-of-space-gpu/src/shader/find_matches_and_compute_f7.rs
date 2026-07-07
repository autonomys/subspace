
use crate::shader::compute_fn::compute_fn_impl;
use crate::shader::constants::{
    MAX_BUCKET_SIZE, NUM_BUCKETS, NUM_MATCH_BUCKETS, NUM_S_BUCKETS, PARAM_BC, REDUCED_BUCKET_SIZE,
    REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_in_buckets::{FindMatchesShared, find_matches_in_buckets_impl};
#[cfg(target_arch = "spirv")]
use crate::shader::polyfills::ArrayIndexingPolyfill;
use crate::shader::types::{Match, Metadata, Position, PositionR, Y};
use core::fmt;
use core::mem::MaybeUninit;
use spirv_std::arch::{atomic_i_increment, workgroup_memory_barrier_with_group_sync};
use spirv_std::glam::UVec3;
use spirv_std::memory::{Scope, Semantics};
use spirv_std::spirv;

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;
const TABLE_NUMBER: u8 = 7;
const PARENT_TABLE_NUMBER: u8 = 6;

const _: () = {
    assert!(crate::shader::find_matches_in_buckets::WORKGROUP_SIZE == WORKGROUP_SIZE);
};

const PROOFS_BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS: u8 = 128;
/// Upper-bound estimation of the number of matched elements per s-bucket
pub const NUM_ELEMENTS_PER_S_BUCKET: usize =
    proofs_bucket_upper_bound(PROOFS_BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS) as usize;

// TODO: This data structure is quite large, could be compressed to a single `u64`, saving 1/3 of
//  space
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct ProofTargets {
    // Absolute position derived from bucket and match index
    pub absolute_position: u32,
    /// Left and right positions
    pub positions: [Position; 2],
}

/// Upper-bound estimation of the number of matched elements per s-bucket.
///
/// Buckets are defined by the lower `NUM_S_BUCKETS.ilog2()` bits of the values. This is based on a
/// Chernoff bound for the Poisson distribution with mean `lambda = 1`, ensuring the probability
/// that any bucket exceeds the bound is less than `2^{-security_bits}`. The bound is
/// `lambda + ceil(sqrt(3 * lambda * (NUM_S_BUCKETS.ilog2() + security_bits) * ln(2)))`.
/// Accounts for the filter to values in `0..NUM_S_BUCKETS-1` by using the expected number of
/// remaining elements ~`NUM_S_BUCKETS`, distributed uniformly across all `NUM_S_BUCKETS` buckets.
const fn proofs_bucket_upper_bound(security_bits: u8) -> u64 {
    // Lambda is the expected number of entries in a bucket:
    // ~`NUM_S_BUCKETS / NUM_S_BUCKETS = 1`
    const LAMBDA: u64 = 1;
    // Approximation of ln(2) as a fraction: `ln(2) ≈ LN2_NUM / LN2_DEN`.
    // This allows integer-only computation of the square root term involving ln(2).
    const LN2_NUM: u128 = 693_147;
    const LN2_DEN: u128 = 1_000_000;

    // `log2(NUM_S_BUCKETS) + security_bits` for the union bound over `NUM_S_BUCKETS` buckets
    let ks = NUM_S_BUCKETS.ilog2() as u128 + security_bits as u128;
    // Compute numerator for the expression under the square root:
    // `3 * lambda * ks * LN2_NUM`
    let num = 3u128 * LAMBDA as u128 * ks * LN2_NUM;
    // Denominator for ln(2): `LN2_DEN`
    let den = LN2_DEN;

    let ceil_div = num.div_ceil(den);

    // Binary search to find the smallest `x` such that `x * x >= ceil_div`,
    // which computes `ceil(sqrt(num / den))` without floating-point.
    // We use a custom binary search over `u64` range because binary search in the standard library
    // operates on sorted slices, not directly on integer ranges for solving inequalities like this.
    let mut low = 0u64;
    let mut high = u64::MAX;
    while low < high {
        let mid = low + (high - low) / 2;
        let left = (mid as u128) * (mid as u128);
        if left >= ceil_div {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let add_term = low;

    LAMBDA + add_term
}

// TODO: Should be union, but it currently doesn't compile:
//  https://github.com/Rust-GPU/rust-gpu/issues/241
#[derive(Copy, Clone)]
pub struct FindMatchesAndComputeF7Shared {
    find_matches_shared: FindMatchesShared,
    bucket_scratch: [PositionR; REDUCED_BUCKET_SIZE],
}

impl fmt::Debug for FindMatchesAndComputeF7Shared {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindMatchesAndComputeF7Shared")
            .finish_non_exhaustive()
    }
}

/// # Safety
/// `bucket_index` must be within range `0..REDUCED_MATCHES_COUNT`. `matches_count` elements in
/// `matches` must be initialized, `matches` must have valid pointers into left/right buckets and
/// `parent_metadatas`.
#[inline(always)]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
unsafe fn compute_f7_into_buckets_inner(
    index: u32,
    left_bucket_base: u32,
    absolute_position_base: u32,
    left_bucket: &[PositionR; MAX_BUCKET_SIZE],
    // TODO: `&[Match]` would have been nicer, but it currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    matches: &[MaybeUninit<Match>; MAX_BUCKET_SIZE],
    // TODO: This should have been `&[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]`, but
    //  it currently doesn't compile if flattened:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    parent_metadatas: &[Metadata; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_6_proof_targets_sizes: &mut [u32; NUM_S_BUCKETS],
    table_6_proof_targets: &mut [[MaybeUninit<ProofTargets>; NUM_ELEMENTS_PER_S_BUCKET];
             NUM_S_BUCKETS],
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

    // TODO: Correct version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    // let left_metadata = parent_metadatas[usize::from(left_position)];
    // let right_metadata = parent_metadatas[usize::from(right_position)];
    // SAFETY: Guaranteed by function contract
    let left_metadata = *unsafe { parent_metadatas.get_unchecked(left_position as usize) };
    // SAFETY: Guaranteed by function contract
    let right_metadata = *unsafe { parent_metadatas.get_unchecked(right_position as usize) };

    let (y, _) = compute_fn_impl::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        Y::from(left_bucket_base + left_r),
        left_metadata,
        right_metadata,
    );

    let s_bucket = y.first_k_bits() as usize;
    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    // let Some(bucket_count) = bucket_sizes.get_mut(s_bucket) else {
    //     continue;
    // };
    if s_bucket >= NUM_S_BUCKETS {
        return;
    }
    let bucket_size = &mut table_6_proof_targets_sizes[s_bucket];
    // SAFETY: TODO: Probably should not be unsafe to begin with:
    //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
    let bucket_offset = unsafe {
        atomic_i_increment::<_, { Scope::QueueFamily as u32 }, { Semantics::NONE.bits() }>(
            bucket_size,
        )
    };

    // TODO: Maybe store `absolute_position` separately from more densely populated positions,
    //  then per-s-bucket `atomic_u_min()` can be done to store the minimum pointer. This all
    //  will use less memory overall
    // SAFETY: `s_bucket` is checked above to be correct. Bucket size upper bound is known
    // statically to be [`NUM_ELEMENTS_PER_S_BUCKET`], so `bucket_offset` is also always within
    // bounds.
    unsafe {
        table_6_proof_targets
            .get_unchecked_mut(s_bucket)
            .get_unchecked_mut(bucket_offset as usize)
    }
    .write(ProofTargets {
        absolute_position: absolute_position_base + index,
        positions: [left_position, right_position],
    });
}

/// # Safety
/// `bucket_index` must be within range `0..REDUCED_MATCHES_COUNT`. `matches_count` elements in
/// `matches` must be initialized, `matches` must have valid pointers into left/right buckets and
/// `parent_metadatas`.
#[inline(always)]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
unsafe fn compute_f7_into_buckets(
    local_invocation_id: u32,
    left_bucket_index: u32,
    left_bucket: &[PositionR; MAX_BUCKET_SIZE],
    right_bucket: &[PositionR; MAX_BUCKET_SIZE],
    matches_count: usize,
    // TODO: `&[Match]` would have been nicer, but it currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    matches: &[MaybeUninit<Match>; MAX_BUCKET_SIZE],
    // TODO: This should have been `&[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]`, but
    //  it currently doesn't compile if flattened:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    parent_metadatas: &[Metadata; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_6_proof_targets_sizes: &mut [u32; NUM_S_BUCKETS],
    table_6_proof_targets: &mut [[MaybeUninit<ProofTargets>; NUM_ELEMENTS_PER_S_BUCKET];
             NUM_S_BUCKETS],
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
    let absolute_position_base = left_bucket_index * REDUCED_MATCHES_COUNT as u32;

    const {
        assert!(MAX_BUCKET_SIZE == WORKGROUP_SIZE as usize * 2);
    }
    // TODO: This should have been a loop, but register usage is too high, see:
    //  https://github.com/Rust-GPU/rust-gpu/issues/462
    // SAFETY: Guaranteed by function contract
    unsafe {
        if (local_invocation_id as usize) < matches_count {
            compute_f7_into_buckets_inner(
                local_invocation_id,
                left_bucket_base,
                absolute_position_base,
                left_bucket,
                matches,
                parent_metadatas,
                table_6_proof_targets_sizes,
                table_6_proof_targets,
                bucket_scratch,
            );
        }
        if ((local_invocation_id + WORKGROUP_SIZE) as usize) < matches_count {
            compute_f7_into_buckets_inner(
                local_invocation_id + WORKGROUP_SIZE,
                left_bucket_base,
                absolute_position_base,
                left_bucket,
                matches,
                parent_metadatas,
                table_6_proof_targets_sizes,
                table_6_proof_targets,
                bucket_scratch,
            );
        }
    }
}

/// This is similar to `find_matches_and_compute_fn`, but it stores results in buckets grouped by
/// s-buckets, which is how proofs can later be found efficiently.
///
/// Buckets need to be sorted by position afterward due to concurrent writes that do not have
/// deterministic order. Content of the bucket beyond the size specified in `bucket_sizes` is
/// undefined.
///
/// # Safety
/// Must be called from [`WORKGROUP_SIZE`] threads.  All buckets must contain valid positions.
#[spirv(compute(threads(256), entry_point_name = "find_matches_and_compute_f7"))]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
pub unsafe fn find_matches_and_compute_f7(
    #[spirv(local_invocation_id)] local_invocation_id: UVec3,
    #[spirv(workgroup_id)] workgroup_id: UVec3,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)] parent_buckets: &[[PositionR; MAX_BUCKET_SIZE];
         NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)]
    parent_metadatas: &[Metadata; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 2)]
    table_6_proof_targets_sizes: &mut [u32; NUM_S_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 3)]
    table_6_proof_targets: &mut [[MaybeUninit<ProofTargets>; NUM_ELEMENTS_PER_S_BUCKET];
             NUM_S_BUCKETS],
    #[spirv(workgroup)] matches: &mut [MaybeUninit<Match>; MAX_BUCKET_SIZE],
    #[spirv(workgroup)] shared: &mut FindMatchesAndComputeF7Shared,
) {
    let local_invocation_id = local_invocation_id.x;
    let workgroup_id = workgroup_id.x;

    let left_bucket_index = workgroup_id as usize;
    let left_bucket = &parent_buckets[left_bucket_index];
    let right_bucket = &parent_buckets[left_bucket_index + 1];
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
        compute_f7_into_buckets(
            local_invocation_id,
            left_bucket_index,
            left_bucket,
            right_bucket,
            matches_count as usize,
            matches,
            parent_metadatas,
            table_6_proof_targets_sizes,
            table_6_proof_targets,
            &mut shared.bucket_scratch,
        );
    }
}
