#[cfg(any(feature = "alloc", test))]
mod rmap;
#[cfg(test)]
mod tests;
pub(super) mod types;

use crate::chiapos::Seed;
use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT, PARAM_M};
#[cfg(feature = "alloc")]
use crate::chiapos::table::rmap::Rmap;
use crate::chiapos::table::types::{Metadata, X, Y};
#[cfg(feature = "alloc")]
use crate::chiapos::table::types::{Position, R};
use crate::chiapos::utils::EvaluatableUsize;
use ab_chacha8::{ChaCha8Block, ChaCha8State};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use chacha20::cipher::{Iv, KeyIvInit, StreamCipher};
#[cfg(feature = "alloc")]
use chacha20::{ChaCha8, Key};
use core::array;
#[cfg(feature = "parallel")]
use core::cell::SyncUnsafeCell;
#[cfg(feature = "alloc")]
use core::mem;
#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;
#[cfg(any(feature = "alloc", test))]
use core::simd::prelude::*;
#[cfg(feature = "parallel")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "alloc")]
use derive_more::Deref;
#[cfg(any(feature = "alloc", test))]
use seq_macro::seq;
// TODO: Switch to `rclite` once https://github.com/fereidani/rclite/issues/11 is resolved
#[cfg(feature = "alloc")]
use alloc::sync::Arc;
use subspace_core_primitives::hashes::blake3_hash;

pub(super) const COMPUTE_F1_SIMD_FACTOR: usize = 8;
#[cfg(any(feature = "alloc", test))]
const COMPUTE_FN_SIMD_FACTOR: usize = 16;
const MAX_BUCKET_SIZE: usize = 512;
#[cfg(feature = "alloc")]
const BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS: u8 = 128;
/// Reducing bucket size for better performance.
///
/// The number should be sufficient to produce enough proofs for sector encoding with high
/// probability.
// TODO: Statistical analysis if possible, confirming there will be enough proofs
const REDUCED_BUCKET_SIZE: usize = 272;
/// Reducing matches count for better performance.
///
/// The number should be sufficient to produce enough proofs for sector encoding with high
/// probability.
// TODO: Statistical analysis if possible, confirming there will be enough proofs
const REDUCED_MATCHES_COUNT: usize = 288;
#[cfg(feature = "parallel")]
const CACHE_LINE_SIZE: usize = 64;

const _: () = {
    debug_assert!(REDUCED_BUCKET_SIZE <= MAX_BUCKET_SIZE);
    debug_assert!(REDUCED_MATCHES_COUNT <= MAX_BUCKET_SIZE);
};

/// Compute the size of `y` in bits
pub(super) const fn y_size_bits(k: u8) -> usize {
    k as usize + PARAM_EXT as usize
}

/// Metadata size in bytes
pub const fn metadata_size_bytes(k: u8, table_number: u8) -> usize {
    metadata_size_bits(k, table_number).div_ceil(u8::BITS as usize)
}

/// Metadata size in bits
pub(super) const fn metadata_size_bits(k: u8, table_number: u8) -> usize {
    k as usize
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

/// Number of buckets for a given `k`
pub const fn num_buckets(k: u8) -> usize {
    2_usize
        .pow(y_size_bits(k) as u32)
        .div_ceil(usize::from(PARAM_BC))
}

#[cfg(feature = "parallel")]
#[inline(always)]
fn strip_sync_unsafe_cell<const N: usize, T>(value: Box<[SyncUnsafeCell<T>; N]>) -> Box<[T; N]> {
    // SAFETY: `SyncUnsafeCell` has the same layout as `T`
    unsafe { Box::from_raw(Box::into_raw(value).cast()) }
}

/// ChaCha8 [`Vec`] sufficient for the whole first table for [`K`].
/// Prefer [`partial_y`] if you need partial y just for a single `x`.
#[cfg(feature = "alloc")]
fn partial_ys<const K: u8>(seed: Seed) -> Vec<u8> {
    let output_len_bits = usize::from(K) * (1 << K);
    let mut output = vec![0; output_len_bits.div_ceil(u8::BITS as usize)];

    let key = Key::from(seed);
    let iv = Iv::<ChaCha8>::default();

    let mut cipher = ChaCha8::new(&key, &iv);

    cipher.write_keystream(&mut output);

    output
}

/// Calculate a probabilistic upper bound on the Chia bucket size for a given `k` and
/// `security_bits` (security level).
///
/// This is based on a Chernoff bound for the Poisson distribution with mean
/// `lambda = PARAM_BC / 2^PARAM_EXT`, ensuring the probability that any bucket exceeds the bound is
/// less than `2^{-security_bits}`.
/// The bound is lambda + ceil(sqrt(3 * lambda * (k + security_bits) * ln(2))).
#[cfg(feature = "alloc")]
const fn bucket_size_upper_bound(k: u8, security_bits: u8) -> usize {
    // Lambda is the expected number of entries in a bucket, approximated as
    // `PARAM_BC / 2^PARAM_EXT`. It is independent of `k`.
    const LAMBDA: u64 = PARAM_BC as u64 / 2u64.pow(PARAM_EXT as u32);
    // Approximation of ln(2) as a fraction: ln(2) ≈ LN2_NUM / LN2_DEN.
    // This allows integer-only computation of the square root term involving ln(2).
    const LN2_NUM: u128 = 693147;
    const LN2_DEN: u128 = 1000000;

    // `k + security_bits` for the union bound over ~2^k intervals
    let ks = k as u128 + security_bits as u128;
    // Compute numerator for the expression under the square root:
    // `3 * lambda * (k + security_bits) * LN2_NUM`
    let num = 3u128 * LAMBDA as u128 * ks * LN2_NUM;
    // Denominator for ln(2): `LN2_DEN`
    let den = LN2_DEN;

    let ceil_div: u128 = num.div_ceil(den);

    // Binary search to find the smallest `x` such that `x * x * den >= num`,
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

    (LAMBDA + add_term) as usize
}

#[cfg(feature = "alloc")]
fn group_by_buckets<const K: u8>(
    ys: &[Y],
) -> Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)]>
where
    [(); num_buckets(K)]:,
{
    let mut bucket_offsets = [0_u16; num_buckets(K)];
    // SAFETY: Contents is `MaybeUninit`
    let mut buckets = unsafe {
        Box::<[[MaybeUninit<(Position, Y)>; REDUCED_BUCKET_SIZE]; num_buckets(K)]>::new_uninit()
            .assume_init()
    };

    for (&y, position) in ys.iter().zip(Position::ZERO..) {
        let bucket_index = (u32::from(y) / u32::from(PARAM_BC)) as usize;

        // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
        let bucket_offset = unsafe { bucket_offsets.get_unchecked_mut(bucket_index) };
        // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
        let bucket = unsafe { buckets.get_unchecked_mut(bucket_index) };

        if *bucket_offset < REDUCED_BUCKET_SIZE as u16 {
            bucket[*bucket_offset as usize].write((position, y));
            *bucket_offset += 1;
        }
    }

    for (bucket, initialized) in buckets.iter_mut().zip(bucket_offsets) {
        bucket[usize::from(initialized)..].write_filled((Position::SENTINEL, Y::SENTINEL));
    }

    // SAFETY: All entries are initialized
    unsafe { Box::from_raw(Box::into_raw(buckets).cast()) }
}

/// Similar to [`group_by_buckets()`], but processes buckets instead of a flat list of `y`s.
///
/// # Safety
/// Iterator item is a list of potentially uninitialized `y`s and a number of initialized `y`s. The
/// number of initialized `y`s must be correct.
#[cfg(feature = "parallel")]
unsafe fn group_by_buckets_from_buckets<'a, const K: u8, I>(
    iter: I,
) -> Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)]>
where
    I: Iterator<Item = (&'a [MaybeUninit<Y>; REDUCED_MATCHES_COUNT], usize)> + 'a,
    [(); num_buckets(K)]:,
{
    let mut bucket_offsets = [0_u16; num_buckets(K)];
    // SAFETY: Contents is `MaybeUninit`
    let mut buckets = unsafe {
        Box::<[[MaybeUninit<(Position, Y)>; REDUCED_BUCKET_SIZE]; num_buckets(K)]>::new_uninit()
            .assume_init()
    };

    for ((ys, count), batch_start) in iter.zip((Position::ZERO..).step_by(REDUCED_MATCHES_COUNT)) {
        // SAFETY: Function contract guarantees that `y`s are initialized
        let ys = unsafe { ys[..count].assume_init_ref() };
        for (&y, position) in ys.iter().zip(batch_start..) {
            let bucket_index = (u32::from(y) / u32::from(PARAM_BC)) as usize;

            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            let bucket_offset = unsafe { bucket_offsets.get_unchecked_mut(bucket_index) };
            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            let bucket = unsafe { buckets.get_unchecked_mut(bucket_index) };

            if *bucket_offset < REDUCED_BUCKET_SIZE as u16 {
                bucket[*bucket_offset as usize].write((position, y));
                *bucket_offset += 1;
            }
        }
    }

    for (bucket, initialized) in buckets.iter_mut().zip(bucket_offsets) {
        bucket[usize::from(initialized)..].write_filled((Position::SENTINEL, Y::SENTINEL));
    }

    // SAFETY: All entries are initialized
    unsafe { Box::from_raw(Box::into_raw(buckets).cast()) }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, Deref)]
#[repr(align(64))]
struct CacheLineAligned<T>(T);

/// Mapping from `parity` to `r` to `m`
#[cfg(feature = "alloc")]
type LeftTargets = [[CacheLineAligned<[R; PARAM_M as usize]>; PARAM_BC as usize]; 2];

#[cfg(feature = "alloc")]
fn calculate_left_targets() -> Arc<LeftTargets> {
    let mut left_targets = Arc::<LeftTargets>::new_uninit();
    // SAFETY: Same layout and uninitialized in both cases
    let left_targets_slice = unsafe {
        mem::transmute::<
            &mut MaybeUninit<[[CacheLineAligned<[R; PARAM_M as usize]>; PARAM_BC as usize]; 2]>,
            &mut [[MaybeUninit<CacheLineAligned<[R; PARAM_M as usize]>>; PARAM_BC as usize]; 2],
        >(Arc::get_mut_unchecked(&mut left_targets))
    };

    for parity in 0..=1 {
        for r in 0..PARAM_BC {
            let c = r / PARAM_C;

            let mut arr = array::from_fn(|m| {
                let m = m as u16;
                R::from(
                    ((c + m) % PARAM_B) * PARAM_C
                        + (((2 * m + parity) * (2 * m + parity) + r) % PARAM_C),
                )
            });
            arr.sort_unstable();
            left_targets_slice[parity as usize][r as usize].write(CacheLineAligned(arr));
        }
    }

    // SAFETY: Initialized all entries
    unsafe { left_targets.assume_init() }
}

fn calculate_left_target_on_demand(parity: u32, r: u32, m: u32) -> u32 {
    let param_b = u32::from(PARAM_B);
    let param_c = u32::from(PARAM_C);

    ((r / param_c + m) % param_b) * param_c + (((2 * m + parity) * (2 * m + parity) + r) % param_c)
}

/// Caches that can be used to optimize the creation of multiple [`Tables`](super::Tables).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct TablesCache {
    left_targets: Arc<LeftTargets>,
}

#[cfg(feature = "alloc")]
impl Default for TablesCache {
    /// Create a new instance
    fn default() -> Self {
        Self {
            left_targets: calculate_left_targets(),
        }
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone)]
struct Match {
    left_position: Position,
    left_y: Y,
    right_position: Position,
}

/// `partial_y_offset` is in bits within `partial_y`
pub(super) fn compute_f1<const K: u8>(x: X, seed: &Seed) -> Y {
    let skip_bits = u32::from(K) * u32::from(x);
    let skip_u32s = skip_bits / u32::BITS;
    let partial_y_offset = skip_bits % u32::BITS;

    const U32S_PER_BLOCK: usize = size_of::<ChaCha8Block>() / size_of::<u32>();

    let initial_state = ChaCha8State::init(seed, &[0; _]);
    let first_block_counter = skip_u32s / U32S_PER_BLOCK as u32;
    let u32_in_first_block = skip_u32s as usize % U32S_PER_BLOCK;

    let first_block = initial_state.compute_block(first_block_counter);
    let hi = first_block[u32_in_first_block].to_be();

    // TODO: Is SIMD version of `compute_block()` that produces two blocks at once possible?
    let lo = if u32_in_first_block + 1 == U32S_PER_BLOCK {
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
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    Y::from((pre_y & pre_y_mask) | pre_ext)
}

#[cfg(any(feature = "alloc", test))]
pub(super) fn compute_f1_simd<const K: u8>(
    xs: Simd<u32, COMPUTE_F1_SIMD_FACTOR>,
    partial_ys: &[u8; K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize],
) -> [Y; COMPUTE_F1_SIMD_FACTOR] {
    // Each element contains `K` desired bits of `partial_ys` in the final offset of eventual `ys`
    // with the rest of bits being in undefined state
    let pre_ys_bytes = array::from_fn(|i| {
        let partial_y_offset = i * usize::from(K);
        let partial_y_length =
            (partial_y_offset % u8::BITS as usize + usize::from(K)).div_ceil(u8::BITS as usize);
        let mut pre_y_bytes = 0u64.to_be_bytes();
        pre_y_bytes[..partial_y_length].copy_from_slice(
            &partial_ys[partial_y_offset / u8::BITS as usize..][..partial_y_length],
        );

        u64::from_be_bytes(pre_y_bytes)
    });
    let pre_ys_right_offset = array::from_fn(|i| {
        let partial_y_offset = i as u32 * u32::from(K);
        u64::from(u64::BITS - u32::from(K + PARAM_EXT) - partial_y_offset % u8::BITS)
    });
    let pre_ys = Simd::from_array(pre_ys_bytes) >> Simd::from_array(pre_ys_right_offset);

    // Mask for clearing the rest of bits of `pre_ys`.
    let pre_ys_mask = Simd::splat(
        (u32::MAX << usize::from(PARAM_EXT))
            & (u32::MAX >> (u32::BITS as usize - usize::from(K + PARAM_EXT))),
    );

    // Extract `PARAM_EXT` most significant bits from `xs` and store in the final offset of
    // eventual `ys` with the rest of bits being in undefined state.
    let pre_exts = xs >> Simd::splat(u32::from(K - PARAM_EXT));

    // Combine all of the bits together:
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    let ys = (pre_ys.cast() & pre_ys_mask) | pre_exts;

    Y::array_from_repr(ys.to_array())
}

/// For verification use [`has_match`] instead.
///
/// # Safety
/// Left and right bucket positions must correspond to the parent table.
// TODO: Try to reduce the `matches` size further by processing `left_bucket` in chunks (like halves
//  for example)
#[cfg(feature = "alloc")]
unsafe fn find_matches_in_buckets<'a>(
    left_bucket_index: u32,
    left_bucket: &[(Position, Y); REDUCED_BUCKET_SIZE],
    right_bucket: &[(Position, Y); REDUCED_BUCKET_SIZE],
    // `PARAM_M as usize * 2` corresponds to the upper bound number of matches a single `y` in the
    // left bucket might have here
    matches: &'a mut [MaybeUninit<Match>; REDUCED_MATCHES_COUNT + PARAM_M as usize * 2],
    left_targets: &LeftTargets,
) -> &'a [Match] {
    let left_base = left_bucket_index * u32::from(PARAM_BC);
    let right_base = left_base + u32::from(PARAM_BC);

    let mut rmap = Rmap::new();
    for &(right_position, y) in right_bucket {
        if right_position == Position::SENTINEL {
            break;
        }
        let r = R::from((u32::from(y) - right_base) as u16);
        // SAFETY: `r` is within `0..PARAM_BC` range by definition, the right bucket is limited to
        // `REDUCED_BUCKETS_SIZE`
        unsafe {
            rmap.add(r, right_position);
        }
    }

    let parity = left_base % 2;
    let left_targets_parity = &left_targets[parity as usize];
    let mut next_match_index = 0;

    // TODO: Simd read for left bucket? It might be more efficient in terms of memory access to
    //  process chunks of the left bucket against one right value for each at a time
    for &(left_position, y) in left_bucket {
        // `next_match_index >= REDUCED_MATCHES_COUNT` is crucial to make sure
        if left_position == Position::SENTINEL || next_match_index >= REDUCED_MATCHES_COUNT {
            // Sentinel values are padded to the end of the bucket
            break;
        }

        let r = R::from((u32::from(y) - left_base) as u16);
        // SAFETY: `r` is within a bucket and exists by definition
        let left_targets_r = unsafe { left_targets_parity.get_unchecked(usize::from(r)) };

        for &r_target in left_targets_r.iter() {
            // SAFETY: Targets are always limited to `PARAM_BC`
            let [right_position_a, right_position_b] = unsafe { rmap.get(r_target) };

            // The right bucket position is never zero
            if right_position_a != Position::ZERO {
                // SAFETY: Iteration will stop before `REDUCED_MATCHES_COUNT + PARAM_M * 2`
                // elements is inserted
                unsafe { matches.get_unchecked_mut(next_match_index) }.write(Match {
                    left_position,
                    left_y: y,
                    right_position: right_position_a,
                });
                next_match_index += 1;

                if right_position_b != Position::ZERO {
                    // SAFETY: Iteration will stop before
                    // `REDUCED_MATCHES_COUNT + PARAM_M * 2` elements is inserted
                    unsafe { matches.get_unchecked_mut(next_match_index) }.write(Match {
                        left_position,
                        left_y: y,
                        right_position: right_position_b,
                    });
                    next_match_index += 1;
                }
            }
        }
    }

    // SAFETY: Initialized this many matches
    unsafe { matches[..next_match_index].assume_init_ref() }
}

/// Simplified version of [`find_matches_in_buckets`] for verification purposes.
pub(super) fn has_match(left_y: Y, right_y: Y) -> bool {
    let right_r = u32::from(right_y) % u32::from(PARAM_BC);
    let parity = (u32::from(left_y) / u32::from(PARAM_BC)) % 2;
    let left_r = u32::from(left_y) % u32::from(PARAM_BC);

    let r_targets = array::from_fn::<_, { PARAM_M as usize }, _>(|i| {
        calculate_left_target_on_demand(parity, left_r, i as u32)
    });

    r_targets.contains(&right_r)
}

#[inline(always)]
pub(super) fn compute_fn<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    y: Y,
    left_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
    right_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
) -> (Y, Metadata<K, TABLE_NUMBER>)
where
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    let left_metadata = u128::from(left_metadata);
    let right_metadata = u128::from(right_metadata);

    let parent_metadata_bits = metadata_size_bits(K, PARENT_TABLE_NUMBER);

    // Part of the `right_bits` at the final offset of eventual `input_a`
    let y_and_left_bits = y_size_bits(K) + parent_metadata_bits;
    let right_bits_start_offset = u128::BITS as usize - parent_metadata_bits;

    // Take only bytes where bits were set
    let num_bytes_with_data =
        (y_size_bits(K) + parent_metadata_bits * 2).div_ceil(u8::BITS as usize);

    // Only supports `K` from 15 to 25 (otherwise math will not be correct when concatenating y,
    // left metadata and right metadata)
    let hash = {
        // Collect `K` most significant bits of `y` at the final offset of eventual `input_a`
        let y_bits = u128::from(y) << (u128::BITS as usize - y_size_bits(K));

        // Move bits of `left_metadata` at the final offset of eventual `input_a`
        let left_metadata_bits =
            left_metadata << (u128::BITS as usize - parent_metadata_bits - y_size_bits(K));

        // If `right_metadata` bits start to the left of the desired position in `input_a` move
        // bits right, else move left
        if right_bits_start_offset < y_and_left_bits {
            let right_bits_pushed_into_input_b = y_and_left_bits - right_bits_start_offset;
            // Collect bits of `right_metadata` that will fit into `input_a` at the final offset in
            // eventual `input_a`
            let right_bits_a = right_metadata >> right_bits_pushed_into_input_b;
            let input_a = y_bits | left_metadata_bits | right_bits_a;
            // Collect bits of `right_metadata` that will spill over into `input_b`
            let input_b = right_metadata << (u128::BITS as usize - right_bits_pushed_into_input_b);

            let input = [input_a.to_be_bytes(), input_b.to_be_bytes()];
            let input_len =
                size_of::<u128>() + right_bits_pushed_into_input_b.div_ceil(u8::BITS as usize);
            blake3_hash(&input.as_flattened()[..input_len])
        } else {
            let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
            let input_a = y_bits | left_metadata_bits | right_bits_a;

            blake3_hash(&input_a.to_be_bytes()[..num_bytes_with_data])
        }
    };

    let y_output = Y::from(
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
            >> (u32::BITS as usize - y_size_bits(K)),
    );

    let metadata_size_bits = metadata_size_bits(K, TABLE_NUMBER);

    let metadata = if TABLE_NUMBER < 4 {
        (left_metadata << parent_metadata_bits) | right_metadata
    } else if metadata_size_bits > 0 {
        // For K up to 25 it is guaranteed that metadata + bit offset will always fit into u128.
        // We collect the bytes necessary, potentially with extra bits at the start and end of the
        // bytes that will be taken care of later.
        let metadata = u128::from_be_bytes(
            hash[y_size_bits(K) / u8::BITS as usize..][..size_of::<u128>()]
                .try_into()
                .expect("Always enough bits for any K; qed"),
        );
        // Remove extra bits at the beginning
        let metadata = metadata << (y_size_bits(K) % u8::BITS as usize);
        // Move bits into the correct location
        metadata >> (u128::BITS as usize - metadata_size_bits)
    } else {
        0
    };

    (y_output, Metadata::from(metadata))
}

// TODO: This is actually using only pipelining rather than real SIMD (at least explicitly) due to:
//  * https://github.com/rust-lang/portable-simd/issues/108
//  * https://github.com/BLAKE3-team/BLAKE3/issues/478#issuecomment-3200106103
#[cfg(any(feature = "alloc", test))]
fn compute_fn_simd<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    left_ys: [Y; COMPUTE_FN_SIMD_FACTOR],
    left_metadatas: [Metadata<K, PARENT_TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
    right_metadatas: [Metadata<K, PARENT_TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
) -> (
    [Y; COMPUTE_FN_SIMD_FACTOR],
    [Metadata<K, TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
)
where
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    let parent_metadata_bits = metadata_size_bits(K, PARENT_TABLE_NUMBER);
    let metadata_size_bits = metadata_size_bits(K, TABLE_NUMBER);

    // TODO: `u128` is not supported as SIMD element yet, see
    //  https://github.com/rust-lang/portable-simd/issues/108
    let left_metadatas: [u128; COMPUTE_FN_SIMD_FACTOR] = seq!(N in 0..16 {
        [
        #(
            u128::from(left_metadatas[N]),
        )*
        ]
    });
    let right_metadatas: [u128; COMPUTE_FN_SIMD_FACTOR] = seq!(N in 0..16 {
        [
        #(
            u128::from(right_metadatas[N]),
        )*
        ]
    });

    // Part of the `right_bits` at the final offset of eventual `input_a`
    let y_and_left_bits = y_size_bits(K) + parent_metadata_bits;
    let right_bits_start_offset = u128::BITS as usize - parent_metadata_bits;

    // Take only bytes where bits were set
    let num_bytes_with_data =
        (y_size_bits(K) + parent_metadata_bits * 2).div_ceil(u8::BITS as usize);

    // Only supports `K` from 15 to 25 (otherwise math will not be correct when concatenating y,
    // left metadata and right metadata)
    // TODO: SIMD hashing once this is possible:
    //  https://github.com/BLAKE3-team/BLAKE3/issues/478#issuecomment-3200106103
    let hashes: [_; COMPUTE_FN_SIMD_FACTOR] = seq!(N in 0..16 {
        [
        #(
        {
            let y = left_ys[N];
            let left_metadata = left_metadatas[N];
            let right_metadata = right_metadatas[N];

            // Collect `K` most significant bits of `y` at the final offset of eventual
            // `input_a`
            let y_bits = u128::from(y) << (u128::BITS as usize - y_size_bits(K));

            // Move bits of `left_metadata` at the final offset of eventual `input_a`
            let left_metadata_bits =
                left_metadata << (u128::BITS as usize - parent_metadata_bits - y_size_bits(K));

            // If `right_metadata` bits start to the left of the desired position in `input_a` move
            // bits right, else move left
            if right_bits_start_offset < y_and_left_bits {
                let right_bits_pushed_into_input_b = y_and_left_bits - right_bits_start_offset;
                // Collect bits of `right_metadata` that will fit into `input_a` at the final offset
                // in eventual `input_a`
                let right_bits_a = right_metadata >> right_bits_pushed_into_input_b;
                let input_a = y_bits | left_metadata_bits | right_bits_a;
                // Collect bits of `right_metadata` that will spill over into `input_b`
                let input_b = right_metadata << (u128::BITS as usize - right_bits_pushed_into_input_b);

                let input = [input_a.to_be_bytes(), input_b.to_be_bytes()];
                let input_len =
                    size_of::<u128>() + right_bits_pushed_into_input_b.div_ceil(u8::BITS as usize);
                blake3_hash(&input.as_flattened()[..input_len])
            } else {
                let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
                let input_a = y_bits | left_metadata_bits | right_bits_a;

                blake3_hash(&input_a.to_be_bytes()[..num_bytes_with_data])
            }
        },
        )*
        ]
    });

    let y_outputs = Simd::from_array(
        hashes.map(|hash| u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])),
    ) >> (u32::BITS - y_size_bits(K) as u32);
    let y_outputs = Y::array_from_repr(y_outputs.to_array());

    let metadatas = if TABLE_NUMBER < 4 {
        seq!(N in 0..16 {
            [
            #(
                Metadata::from((left_metadatas[N] << parent_metadata_bits) | right_metadatas[N]),
            )*
            ]
        })
    } else if metadata_size_bits > 0 {
        // For K up to 25 it is guaranteed that metadata + bit offset will always fit into u128.
        // We collect the bytes necessary, potentially with extra bits at the start and end of the
        // bytes that will be taken care of later.
        seq!(N in 0..16 {
            [
            #(
            {
                let metadata = u128::from_be_bytes(
                    hashes[N][y_size_bits(K) / u8::BITS as usize..][..size_of::<u128>()]
                        .try_into()
                        .expect("Always enough bits for any K; qed"),
                );
                // Remove extra bits at the beginning
                let metadata = metadata << (y_size_bits(K) % u8::BITS as usize);
                // Move bits into the correct location
                Metadata::from(metadata >> (u128::BITS as usize - metadata_size_bits))
            },
            )*
            ]
        })
    } else {
        [Metadata::default(); _]
    };

    (y_outputs, metadatas)
}

/// # Safety
/// `m` must contain positions that correspond to the parent table
#[cfg(feature = "alloc")]
unsafe fn match_to_result<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    m: &Match,
) -> (Y, [Position; 2], Metadata<K, TABLE_NUMBER>)
where
    Table<K, PARENT_TABLE_NUMBER>: private::NotLastTable,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    // SAFETY: Guaranteed by function contract
    let left_metadata = unsafe { parent_table.metadata(m.left_position) };
    // SAFETY: Guaranteed by function contract
    let right_metadata = unsafe { parent_table.metadata(m.right_position) };

    let (y, metadata) =
        compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(m.left_y, left_metadata, right_metadata);

    (y, [m.left_position, m.right_position], metadata)
}

/// # Safety
/// `matches` must contain positions that correspond to the parent table
#[cfg(feature = "alloc")]
#[inline(always)]
unsafe fn match_to_result_simd<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    matches: &[Match; COMPUTE_FN_SIMD_FACTOR],
) -> (
    [Y; COMPUTE_FN_SIMD_FACTOR],
    [[Position; 2]; COMPUTE_FN_SIMD_FACTOR],
    [Metadata<K, TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
)
where
    Table<K, PARENT_TABLE_NUMBER>: private::NotLastTable,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    let left_ys: [_; COMPUTE_FN_SIMD_FACTOR] = seq!(N in 0..16 {
        [
        #(
            matches[N].left_y,
        )*
        ]
    });
    // SAFETY: Guaranteed by function contract
    let left_metadatas: [_; COMPUTE_FN_SIMD_FACTOR] = unsafe {
        seq!(N in 0..16 {
            [
            #(
                parent_table.metadata(matches[N].left_position),
            )*
            ]
        })
    };
    // SAFETY: Guaranteed by function contract
    let right_metadatas: [_; COMPUTE_FN_SIMD_FACTOR] = unsafe {
        seq!(N in 0..16 {
            [
            #(
                parent_table.metadata(matches[N].right_position),
            )*
            ]
        })
    };

    let (y_outputs, metadatas) = compute_fn_simd::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        left_ys,
        left_metadatas,
        right_metadatas,
    );

    let positions = seq!(N in 0..16 {
        [
        #(
            [
                matches[N].left_position,
                matches[N].right_position,
            ],
        )*
        ]
    });

    (y_outputs, positions, metadatas)
}

/// # Safety
/// `matches` must contain positions that correspond to the parent table. `ys`, `position` and
/// `metadatas` length must be at least the length of `matches`
#[cfg(feature = "alloc")]
#[inline(always)]
unsafe fn matches_to_results<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    matches: &[Match],
    ys: &mut [MaybeUninit<Y>],
    positions: &mut [MaybeUninit<[Position; 2]>],
    metadatas: &mut [MaybeUninit<Metadata<K, TABLE_NUMBER>>],
) where
    Table<K, PARENT_TABLE_NUMBER>: private::NotLastTable,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    let (grouped_matches, other_matches) = matches.as_chunks::<COMPUTE_FN_SIMD_FACTOR>();
    let (grouped_ys, other_ys) = ys.split_at_mut(grouped_matches.as_flattened().len());
    let grouped_ys = grouped_ys.as_chunks_mut::<COMPUTE_FN_SIMD_FACTOR>().0;
    let (grouped_positions, other_positions) =
        positions.split_at_mut(grouped_matches.as_flattened().len());
    let grouped_positions = grouped_positions
        .as_chunks_mut::<COMPUTE_FN_SIMD_FACTOR>()
        .0;
    let (grouped_metadatas, other_metadatas) =
        metadatas.split_at_mut(grouped_matches.as_flattened().len());
    let grouped_metadatas = grouped_metadatas
        .as_chunks_mut::<COMPUTE_FN_SIMD_FACTOR>()
        .0;

    for (((grouped_matches, grouped_ys), grouped_positions), grouped_metadatas) in grouped_matches
        .iter()
        .zip(grouped_ys)
        .zip(grouped_positions)
        .zip(grouped_metadatas)
    {
        // SAFETY: Guaranteed by function contract
        let (ys_group, positions_group, metadatas_group) =
            unsafe { match_to_result_simd(parent_table, grouped_matches) };
        grouped_ys.write_copy_of_slice(&ys_group);
        grouped_positions.write_copy_of_slice(&positions_group);

        // The last table doesn't have metadata
        if metadata_size_bits(K, TABLE_NUMBER) > 0 {
            grouped_metadatas.write_copy_of_slice(&metadatas_group);
        }
    }
    for (((other_match, other_y), other_positions), other_metadata) in other_matches
        .iter()
        .zip(other_ys)
        .zip(other_positions)
        .zip(other_metadatas)
    {
        // SAFETY: Guaranteed by function contract
        let (y, p, metadata) = unsafe { match_to_result(parent_table, other_match) };
        other_y.write(y);
        other_positions.write(p);
        // The last table doesn't have metadata
        if metadata_size_bits(K, TABLE_NUMBER) > 0 {
            other_metadata.write(metadata);
        }
    }
}

/// Similar to [`Table`], but smaller size for later processing stages
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub(super) enum PrunedTable<const K: u8, const TABLE_NUMBER: u8>
where
    [(); 1 << K]:,
    [(); num_buckets(K) - 1]:,
{
    First,
    /// Other tables
    Other {
        /// Left and right entry positions in a previous table encoded into bits
        positions: Box<[MaybeUninit<[Position; 2]>; 1 << K]>,
    },
    /// Other tables
    #[cfg(feature = "parallel")]
    OtherBuckets {
        /// Left and right entry positions in a previous table encoded into bits.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        positions: Box<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; num_buckets(K) - 1]>,
    },
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> PrunedTable<K, TABLE_NUMBER>
where
    [(); 1 << K]:,
    [(); num_buckets(K) - 1]:,
{
    /// Get `[left_position, right_position]` of a previous table for a specified position in a
    /// current table.
    ///
    /// # Safety
    /// `position` must come from [`Table::buckets()`] or [`Self::position()`] and not be a sentinel
    /// value.
    #[inline(always)]
    pub(super) unsafe fn position(&self, position: Position) -> [Position; 2] {
        match self {
            Self::First => {
                unreachable!("Not the first table");
            }
            Self::Other { positions, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe { positions.get_unchecked(usize::from(position)).assume_init() }
            }
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { positions, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe {
                    positions
                        .as_flattened()
                        .get_unchecked(usize::from(position))
                        .assume_init()
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub(super) enum Table<const K: u8, const TABLE_NUMBER: u8>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    /// First table
    First {
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)]>,
    },
    /// Other tables
    Other {
        /// Left and right entry positions in a previous table encoded into bits
        positions: Box<[MaybeUninit<[Position; 2]>; 1 << K]>,
        /// Metadata corresponding to each entry
        metadatas: Box<[MaybeUninit<Metadata<K, TABLE_NUMBER>>; 1 << K]>,
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)]>,
    },
    /// Other tables
    #[cfg(feature = "parallel")]
    OtherBuckets {
        /// Left and right entry positions in a previous table encoded into bits.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        positions: Box<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; num_buckets(K) - 1]>,
        /// Metadata corresponding to each entry.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        metadatas: Box<
            [[MaybeUninit<Metadata<K, TABLE_NUMBER>>; REDUCED_MATCHES_COUNT]; num_buckets(K) - 1],
        >,
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)]>,
    },
}

#[cfg(feature = "alloc")]
impl<const K: u8> Table<K, 1>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    /// Create the table
    pub(super) fn create(seed: Seed) -> Self
    where
        EvaluatableUsize<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>: Sized,
    {
        // `MAX_BUCKET_SIZE` is not actively used, but is an upper-bound reference for the other
        // parameters
        debug_assert!(
            MAX_BUCKET_SIZE >= bucket_size_upper_bound(K, BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS),
            "Max bucket size is not sufficiently large"
        );

        let partial_ys = partial_ys::<K>(seed);

        // SAFETY: Contents is `MaybeUninit`
        let mut ys = unsafe { Box::<[MaybeUninit<Y>; 1 << K]>::new_uninit().assume_init() };

        for ((ys, xs_batch_start), partial_ys) in ys
            .as_chunks_mut::<COMPUTE_F1_SIMD_FACTOR>()
            .0
            .iter_mut()
            .zip((X::ZERO..).step_by(COMPUTE_F1_SIMD_FACTOR))
            .zip(
                partial_ys
                    .as_chunks::<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>()
                    .0,
            )
        {
            let xs = Simd::splat(u32::from(xs_batch_start))
                + Simd::from_array(array::from_fn(|i| i as u32));
            let ys_batch = compute_f1_simd::<K>(xs, partial_ys);

            ys.write_copy_of_slice(&ys_batch);
        }

        // SAFETY: Converting a boxed array to a vector of the same size, which has the same memory
        // layout, all elements were initialized
        let ys = unsafe {
            let ys_len = ys.len();
            let ys = Box::into_raw(ys);
            Vec::from_raw_parts(ys.cast(), ys_len, ys_len)
        };

        // TODO: Try to group buckets in the process of collecting `y`s
        let buckets = group_by_buckets::<K>(&ys);

        Self::First { buckets }
    }

    /// Create the table, leverages available parallelism
    #[cfg(feature = "parallel")]
    pub(super) fn create_parallel(seed: Seed) -> Self
    where
        EvaluatableUsize<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>: Sized,
    {
        // `MAX_BUCKET_SIZE` is not actively used, but is an upper-bound reference for the other
        // parameters
        debug_assert!(
            MAX_BUCKET_SIZE >= bucket_size_upper_bound(K, BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS),
            "Max bucket size is not sufficiently large"
        );

        let partial_ys = partial_ys::<K>(seed);

        // SAFETY: Contents is `MaybeUninit`
        let mut ys = unsafe { Box::<[MaybeUninit<Y>; 1 << K]>::new_uninit().assume_init() };

        // TODO: Try parallelism here?
        for ((ys, xs_batch_start), partial_ys) in ys
            .as_chunks_mut::<COMPUTE_F1_SIMD_FACTOR>()
            .0
            .iter_mut()
            .zip((X::ZERO..).step_by(COMPUTE_F1_SIMD_FACTOR))
            .zip(
                partial_ys
                    .as_chunks::<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>()
                    .0,
            )
        {
            let xs = Simd::splat(u32::from(xs_batch_start))
                + Simd::from_array(array::from_fn(|i| i as u32));
            let ys_batch = compute_f1_simd::<K>(xs, partial_ys);

            ys.write_copy_of_slice(&ys_batch);
        }

        // SAFETY: Converting a boxed array to a vector of the same size, which has the same memory
        // layout, all elements were initialized
        let ys = unsafe {
            let ys_len = ys.len();
            let ys = Box::into_raw(ys);
            Vec::from_raw_parts(ys.cast(), ys_len, ys_len)
        };

        // TODO: Try to group buckets in the process of collecting `y`s
        let buckets = group_by_buckets::<K>(&ys);

        Self::First { buckets }
    }
}

#[cfg(feature = "alloc")]
mod private {
    pub(in super::super) trait SupportedOtherTables {}
    pub(in super::super) trait NotLastTable {}
}

#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 2>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 3>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 4>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 5>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 6>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::SupportedOtherTables for Table<K, 7>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}

#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 1>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 2>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 3>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 4>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 5>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}
#[cfg(feature = "alloc")]
impl<const K: u8> private::NotLastTable for Table<K, 6>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: private::SupportedOtherTables,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    /// Creates a new [`TABLE_NUMBER`] table. There also exists [`Self::create_parallel()`] that
    /// trades CPU efficiency and memory usage for lower latency and with multiple parallel calls,
    /// better overall performance.
    pub(super) fn create<const PARENT_TABLE_NUMBER: u8>(
        parent_table: Table<K, PARENT_TABLE_NUMBER>,
        cache: &TablesCache,
    ) -> (Self, PrunedTable<K, PARENT_TABLE_NUMBER>)
    where
        Table<K, PARENT_TABLE_NUMBER>: private::NotLastTable,
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        let left_targets = &*cache.left_targets;
        let mut initialized_elements = 0_usize;
        // SAFETY: Contents is `MaybeUninit`
        let mut ys = unsafe { Box::<[MaybeUninit<Y>; 1 << K]>::new_uninit().assume_init() };
        // SAFETY: Contents is `MaybeUninit`
        let mut positions =
            unsafe { Box::<[MaybeUninit<[Position; 2]>; 1 << K]>::new_uninit().assume_init() };
        // The last table doesn't have metadata
        // SAFETY: Contents is `MaybeUninit`
        let mut metadatas = unsafe {
            Box::<[MaybeUninit<Metadata<K, TABLE_NUMBER>>; 1 << K]>::new_uninit().assume_init()
        };

        for ([left_bucket, right_bucket], left_bucket_index) in
            parent_table.buckets().array_windows().zip(0..)
        {
            let mut matches = [MaybeUninit::uninit(); _];
            // SAFETY: Positions are taken from `Table::buckets()` and correspond to initialized
            // values
            let matches = unsafe {
                find_matches_in_buckets(
                    left_bucket_index,
                    left_bucket,
                    right_bucket,
                    &mut matches,
                    left_targets,
                )
            };
            // Throw away some successful matches that are not that necessary
            let matches = &matches[..matches.len().min(REDUCED_MATCHES_COUNT)];
            // SAFETY: Already initialized this many elements
            let (ys, positions, metadatas) = unsafe {
                (
                    ys.split_at_mut_unchecked(initialized_elements).1,
                    positions.split_at_mut_unchecked(initialized_elements).1,
                    metadatas.split_at_mut_unchecked(initialized_elements).1,
                )
            };

            // SAFETY: Preallocated length is an upper bound and is always sufficient
            let (ys, positions, metadatas) = unsafe {
                (
                    ys.split_at_mut_unchecked(matches.len()).0,
                    positions.split_at_mut_unchecked(matches.len()).0,
                    metadatas.split_at_mut_unchecked(matches.len()).0,
                )
            };

            // SAFETY: Matches come from the parent table and the size of `ys`, `positions`
            // and `metadatas` is the same as the number of matches
            unsafe {
                matches_to_results(&parent_table, matches, ys, positions, metadatas);
            }

            initialized_elements += matches.len();
        }

        let parent_table = parent_table.prune();

        // SAFETY: Converting a boxed array to a vector of the same size, which has the same memory
        // layout, the number of elements matches the number of elements that were initialized
        let ys = unsafe {
            let ys_len = ys.len();
            let ys = Box::into_raw(ys);
            Vec::from_raw_parts(ys.cast(), initialized_elements, ys_len)
        };

        // TODO: Try to group buckets in the process of collecting `y`s
        let buckets = group_by_buckets::<K>(&ys);

        let table = Self::Other {
            positions,
            metadatas,
            buckets,
        };

        (table, parent_table)
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// performance (though not efficiency of CPU and memory usage), if you create multiple tables
    /// in parallel, prefer [`Self::create_parallel()`] for better overall performance.
    #[cfg(feature = "parallel")]
    pub(super) fn create_parallel<const PARENT_TABLE_NUMBER: u8>(
        parent_table: Table<K, PARENT_TABLE_NUMBER>,
        cache: &TablesCache,
    ) -> (Self, PrunedTable<K, PARENT_TABLE_NUMBER>)
    where
        Table<K, PARENT_TABLE_NUMBER>: private::NotLastTable,
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        // SAFETY: Contents is `MaybeUninit`
        let ys = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; num_buckets(K) - 1]>::new_uninit().assume_init()
        };
        // SAFETY: Contents is `MaybeUninit`
        let positions = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; num_buckets(K) - 1]>::new_uninit().assume_init()
        };
        // SAFETY: Contents is `MaybeUninit`
        let metadatas = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; num_buckets(K) - 1]>::new_uninit().assume_init()
        };
        let global_results_counts =
            array::from_fn::<_, { num_buckets(K) - 1 }, _>(|_| SyncUnsafeCell::new(0u16));

        let left_targets = &*cache.left_targets;

        let buckets = parent_table.buckets();
        // Iterate over buckets in batches, such that a cache line worth of bytes is taken from
        // `global_results_counts` each time to avoid unnecessary false sharing
        let bucket_batch_size = CACHE_LINE_SIZE / size_of::<u16>();
        let bucket_batch_index = AtomicUsize::new(0);

        rayon::broadcast(|_ctx| {
            loop {
                let bucket_batch_index = bucket_batch_index.fetch_add(1, Ordering::Relaxed);

                let buckets_batch = buckets
                    .array_windows::<2>()
                    .enumerate()
                    .skip(bucket_batch_index * bucket_batch_size)
                    .take(bucket_batch_size);

                if buckets_batch.is_empty() {
                    break;
                }

                for (left_bucket_index, [left_bucket, right_bucket]) in buckets_batch {
                    let mut matches = [MaybeUninit::uninit(); _];
                    // SAFETY: Positions are taken from `Table::buckets()` and correspond to
                    // initialized values
                    let matches = unsafe {
                        find_matches_in_buckets(
                            left_bucket_index as u32,
                            left_bucket,
                            right_bucket,
                            &mut matches,
                            left_targets,
                        )
                    };
                    // Throw away some successful matches that are not that necessary
                    let matches = &matches[..matches.len().min(REDUCED_MATCHES_COUNT)];

                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let ys = unsafe { &mut *ys.get_unchecked(left_bucket_index).get() };
                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let positions =
                        unsafe { &mut *positions.get_unchecked(left_bucket_index).get() };
                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let metadatas =
                        unsafe { &mut *metadatas.get_unchecked(left_bucket_index).get() };
                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let count = unsafe {
                        &mut *global_results_counts.get_unchecked(left_bucket_index).get()
                    };

                    // SAFETY: Matches come from the parent table and the size of `ys`, `positions`
                    // and `metadatas` is larger or equal to the number of matches
                    unsafe {
                        matches_to_results::<_, TABLE_NUMBER, _>(
                            &parent_table,
                            matches,
                            ys,
                            positions,
                            metadatas,
                        )
                    };
                    *count = matches.len() as u16;
                }
            }
        });

        let parent_table = parent_table.prune();

        let ys = strip_sync_unsafe_cell(ys);
        let positions = strip_sync_unsafe_cell(positions);
        let metadatas = strip_sync_unsafe_cell(metadatas);

        // TODO: Try to group buckets in the process of collecting `y`s
        // SAFETY: `global_results_counts` corresponds to the number of initialized `ys`
        let buckets = unsafe {
            group_by_buckets_from_buckets::<K, _>(
                ys.iter().zip(
                    global_results_counts
                        .into_iter()
                        .map(|count| usize::from(count.into_inner())),
                ),
            )
        };

        let table = Self::OtherBuckets {
            positions,
            metadatas,
            buckets,
        };

        (table, parent_table)
    }

    /// Get `[left_position, right_position]` of a previous table for a specified position in a
    /// current table.
    ///
    /// # Safety
    /// `position` must come from [`Self::buckets()`] or [`Self::position()`] or
    /// [`PrunedTable::position()`] and not be a sentinel value.
    #[inline(always)]
    pub(super) unsafe fn position(&self, position: Position) -> [Position; 2] {
        match self {
            Self::First { .. } => {
                unreachable!("Not the first table");
            }
            Self::Other { positions, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe { positions.get_unchecked(usize::from(position)).assume_init() }
            }
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { positions, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe {
                    positions
                        .as_flattened()
                        .get_unchecked(usize::from(position))
                        .assume_init()
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: private::NotLastTable,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    /// Returns `None` for an invalid position or for table number 7.
    ///
    /// # Safety
    /// `position` must come from [`Self::buckets()`] and not be a sentinel value.
    #[inline(always)]
    unsafe fn metadata(&self, position: Position) -> Metadata<K, TABLE_NUMBER> {
        match self {
            Self::First { .. } => {
                // X matches position
                Metadata::from(X::from(u32::from(position)))
            }
            Self::Other { metadatas, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe { metadatas.get_unchecked(usize::from(position)).assume_init() }
            }
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { metadatas, .. } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe {
                    metadatas
                        .as_flattened()
                        .get_unchecked(usize::from(position))
                        .assume_init()
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    #[inline(always)]
    fn prune(self) -> PrunedTable<K, TABLE_NUMBER> {
        match self {
            Self::First { .. } => PrunedTable::First,
            Self::Other { positions, .. } => PrunedTable::Other { positions },
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { positions, .. } => PrunedTable::OtherBuckets { positions },
        }
    }

    /// Positions of `y`s grouped by the bucket they belong to
    #[inline(always)]
    pub(super) fn buckets(&self) -> &[[(Position, Y); REDUCED_BUCKET_SIZE]; num_buckets(K)] {
        match self {
            Self::First { buckets, .. } => buckets,
            Self::Other { buckets, .. } => buckets,
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { buckets, .. } => buckets,
        }
    }
}
