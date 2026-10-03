mod left_targets;
#[cfg(any(feature = "alloc", test))]
mod rmap;
#[cfg(test)]
mod tests;
pub(super) mod types;

use crate::chiapos::Seed;
#[cfg(feature = "alloc")]
use crate::chiapos::constants::PARAM_M;
use crate::chiapos::constants::{PARAM_BC, PARAM_EXT};
use crate::chiapos::table::left_targets::LeftTargets;
#[cfg(feature = "alloc")]
use crate::chiapos::table::rmap::Rmap;
#[cfg(feature = "alloc")]
use crate::chiapos::table::types::Position;
use crate::chiapos::table::types::{Metadata, R, X, Y};
use ab_chacha8::{ChaCha8Block, ChaCha8State};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use chacha20::cipher::{Iv, KeyIvInit, StreamCipher};
#[cfg(feature = "alloc")]
use chacha20::{ChaCha8, Key};
#[cfg(any(feature = "alloc", test))]
use core::array;
#[cfg(feature = "parallel")]
use core::cell::SyncUnsafeCell;
#[cfg(feature = "alloc")]
use core::hint;
#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;
#[cfg(any(feature = "alloc", test))]
use core::simd::prelude::*;
#[cfg(feature = "parallel")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(any(feature = "alloc", test))]
use seq_macro::seq;
#[cfg(feature = "alloc")]
use subspace_core_primitives::pieces::Record;

#[cfg(any(feature = "alloc", test))]
const COMPUTE_F1_SIMD_FACTOR: usize = 8;
#[cfg(any(feature = "alloc", test))]
const COMPUTE_FN_SIMD_FACTOR: usize = 16;
const MAX_BUCKET_SIZE: usize = 512;
#[cfg(any(feature = "alloc", test))]
const BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS: u8 = 128;
/// Reducing bucket size for better performance.
///
/// The number should be sufficient to produce enough proofs for sector encoding with high
/// probability.
const REDUCED_BUCKET_SIZE: usize = 272;
/// Reducing matches count for better performance.
///
/// The number should be sufficient to produce enough proofs for sector encoding with high
/// probability.
const REDUCED_MATCHES_COUNT: usize = 288;
#[cfg(feature = "parallel")]
const CACHE_LINE_SIZE: usize = 64;

const {
    debug_assert!(REDUCED_BUCKET_SIZE <= MAX_BUCKET_SIZE);
    debug_assert!(REDUCED_MATCHES_COUNT <= MAX_BUCKET_SIZE);
}

/// Number of buckets for a given `k`
#[cfg(feature = "alloc")]
const NUM_BUCKETS<const K: u8>: usize =
    2_usize
        .pow(y_size_bits(K) as u32)
        .div_ceil(usize::from(PARAM_BC));
#[cfg(feature = "parallel")]
const NUM_BUCKET_PAIRS<const K: u8>: usize = NUM_BUCKETS::<K> - 1;

/// Size of the first table and max size for other tables
#[cfg(feature = "alloc")]
const MAX_TABLE_SIZE<const K: u8>: usize = 1 << K;

#[cfg(any(feature = "alloc", test))]
const TABLE_1_YS_BATCH_SIMD<const K: u8>: usize =
    usize::from(K) * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize;

/// Number of ChaCha8 keystream bytes the first table is derived from
#[cfg(feature = "alloc")]
const TABLE_1_PARTIAL_YS_SIZE<const K: u8>: usize =
    (usize::from(K) * MAX_TABLE_SIZE::<K>).div_ceil(u8::BITS as usize);

/// Number of bucket pairs one chunk of [`group_by_buckets_from_buckets()`] covers.
///
/// Fixed rather than derived from the number of threads, so that the result never depends on how
/// many threads happen to be available.
#[cfg(feature = "parallel")]
const GROUP_BY_BUCKETS_CHUNK_SIZE<const K: u8>: usize = NUM_BUCKET_PAIRS::<K>.div_ceil(64);
/// Number of chunks [`group_by_buckets_from_buckets()`] splits its input into
#[cfg(feature = "parallel")]
const GROUP_BY_BUCKETS_CHUNKS<const K: u8>: usize =
    NUM_BUCKET_PAIRS::<K>.div_ceil(GROUP_BY_BUCKETS_CHUNK_SIZE::<K>);

/// Compute the size of `y` in bits
const fn y_size_bits(k: u8) -> usize {
    usize::from(k) + usize::from(PARAM_EXT)
}

/// Metadata size in bits
const fn metadata_size_bits(k: u8, table_number: u8) -> usize {
    usize::from(k)
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

#[cfg(feature = "parallel")]
#[inline(always)]
fn strip_sync_unsafe_cell<const N: usize, T>(value: Box<[SyncUnsafeCell<T>; N]>) -> Box<[T; N]> {
    // SAFETY: `SyncUnsafeCell` has the same layout as `T`
    unsafe { Box::from_raw(Box::into_raw(value).cast()) }
}

/// The same as [`strip_sync_unsafe_cell()`], except each element of the inner arrays is wrapped
/// individually, which is what is needed when different threads write different elements of the
/// same inner array
#[cfg(feature = "parallel")]
#[inline(always)]
fn strip_sync_unsafe_cell_elements<const N: usize, const M: usize, T>(
    value: Box<[[SyncUnsafeCell<T>; M]; N]>,
) -> Box<[[T; M]; N]> {
    // SAFETY: `SyncUnsafeCell` has the same layout as `T`
    unsafe { Box::from_raw(Box::into_raw(value).cast()) }
}

/// ChaCha8 keystream sufficient for the whole first table for [`K`].
/// Prefer [`partial_y`] if you need partial y just for a single `x`.
#[cfg(feature = "alloc")]
fn partial_ys<const K: u8>(seed: Seed) -> Box<[u8; TABLE_1_PARTIAL_YS_SIZE::<K>]> {
    // SAFETY: Data structure filled with zeroes is a valid invariant
    let mut output =
        unsafe { Box::<[u8; TABLE_1_PARTIAL_YS_SIZE::<K>]>::new_zeroed().assume_init() };

    let key = Key::from(seed);
    let iv = Iv::<ChaCha8>::default();

    let mut cipher = ChaCha8::new(&key, &iv);

    cipher.write_keystream(output.as_mut_slice());

    output
}

/// Compute `y`s of the first table out of the ChaCha8 keystream
#[cfg(feature = "alloc")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
fn compute_table_1_ys<'a, const K: u8>(
    partial_ys: &[u8; TABLE_1_PARTIAL_YS_SIZE::<K>],
    ys: &'a mut [MaybeUninit<Y>; MAX_TABLE_SIZE::<K>],
) -> &'a [Y] {
    for ((ys, xs_batch_start), partial_ys) in ys
        .as_chunks_mut::<COMPUTE_F1_SIMD_FACTOR>()
        .0
        .iter_mut()
        .zip((X::ZERO..).step_by(COMPUTE_F1_SIMD_FACTOR))
        .zip(partial_ys.as_chunks::<{ TABLE_1_YS_BATCH_SIMD::<K> }>().0)
    {
        let xs =
            Simd::splat(u32::from(xs_batch_start)) + Simd::from_array(array::from_fn(|i| i as u32));
        let ys_batch = compute_f1_simd::<K>(xs, partial_ys);

        ys.write_copy_of_slice(&ys_batch);
    }

    // SAFETY: The keystream covers the whole table, so all elements were initialized
    unsafe { ys.assume_init_ref() }
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
    const LN2_NUM: u128 = 693_147;
    const LN2_DEN: u128 = 1_000_000;

    // `k + security_bits` for the union bound over ~2^k intervals
    let ks = k as u128 + security_bits as u128;
    // Compute numerator for the expression under the square root:
    // `3 * lambda * (k + security_bits) * LN2_NUM`
    let num = 3u128 * LAMBDA as u128 * ks * LN2_NUM;
    // Denominator for ln(2): `LN2_DEN`
    let den = LN2_DEN;

    let ceil_div = num.div_ceil(den);

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
) -> Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]> {
    // SAFETY: Contents is `MaybeUninit`
    let mut buckets = unsafe {
        Box::<[[MaybeUninit<(Position, Y)>; REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]>::new_uninit()
            .assume_init()
    };

    group_by_buckets_internal::<K>(ys, &mut buckets);

    // SAFETY: All entries are initialized
    unsafe { Box::from_raw(Box::into_raw(buckets).cast()) }
}

/// The part of [`group_by_buckets()`] that works with already allocated memory
#[cfg(feature = "alloc")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
fn group_by_buckets_internal<const K: u8>(
    ys: &[Y],
    buckets: &mut [[MaybeUninit<(Position, Y)>; REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>],
) {
    let mut bucket_lengths = [0_u16; NUM_BUCKETS::<K>];

    for (&y, position) in ys.iter().zip(Position::ZERO..) {
        let bucket_index = (u32::from(y) / u32::from(PARAM_BC)) as usize;

        // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
        unsafe {
            hint::assert_unchecked(bucket_index < NUM_BUCKETS::<K>);
        }
        let bucket_length = bucket_lengths
            .get_mut(bucket_index)
            .expect("Bucket index is within bounds as asserted above; qed");
        let bucket = buckets
            .get_mut(bucket_index)
            .expect("Bucket index is within bounds as asserted above; qed");

        // Entries past `REDUCED_BUCKET_SIZE` are thrown away
        if let Some(entry) = bucket.get_mut(usize::from(*bucket_length)) {
            entry.write((position, y));
            *bucket_length += 1;
        }
    }

    // SAFETY: Bucket lengths are limited to `REDUCED_BUCKET_SIZE` above
    unsafe {
        fill_bucket_tails::<K>(buckets, &bucket_lengths);
    }
}

/// Pad buckets that have fewer than [`REDUCED_BUCKET_SIZE`] entries with sentinel values.
///
/// # Safety
/// Bucket lengths must not exceed [`REDUCED_BUCKET_SIZE`].
#[cfg(feature = "alloc")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn fill_bucket_tails<const K: u8>(
    buckets: &mut [[MaybeUninit<(Position, Y)>; REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>],
    bucket_lengths: &[u16; NUM_BUCKETS::<K>],
) {
    for (bucket, &bucket_length) in buckets.iter_mut().zip(bucket_lengths) {
        let bucket_length = usize::from(bucket_length);
        // SAFETY: Guaranteed by function contract
        unsafe {
            hint::assert_unchecked(bucket_length <= REDUCED_BUCKET_SIZE);
        }

        bucket[bucket_length..].write_filled((Position::SENTINEL, Y::SENTINEL));
    }
}

/// Count how many `y`s of a single chunk belong to each bucket.
///
/// # Safety
/// `counts` must be the number of initialized `y`s in each entry of `ys`.
#[cfg(feature = "parallel")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn count_ys_in_buckets<const K: u8>(
    ys: &[[MaybeUninit<Y>; REDUCED_MATCHES_COUNT]],
    counts: &[u16],
    chunk_offsets: &mut [u16; NUM_BUCKETS::<K>],
) {
    for (ys, &count) in ys.iter().zip(counts) {
        // SAFETY: Function contract guarantees that this many `y`s are initialized, hence the
        // count is also within bounds
        let ys = unsafe { ys.get_unchecked(..usize::from(count)).assume_init_ref() };

        for &y in ys {
            let bucket_index = (u32::from(y) / u32::from(PARAM_BC)) as usize;

            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            unsafe {
                *chunk_offsets.get_unchecked_mut(bucket_index) += 1;
            }
        }
    }
}

/// Write `y`s of a single chunk into the buckets they belong to, starting at the offsets reserved
/// for this chunk.
///
/// # Safety
/// `counts` must be the number of initialized `y`s in each entry of `ys`, `batch_start` must be
/// the position of the first `y` of `ys`, `chunk_offsets` must be the offsets within buckets that
/// are reserved exclusively for this chunk.
#[cfg(feature = "parallel")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
#[expect(clippy::type_complexity, reason = "Internal API")]
unsafe fn scatter_ys_into_buckets<const K: u8>(
    ys: &[[MaybeUninit<Y>; REDUCED_MATCHES_COUNT]],
    counts: &[u16],
    chunk_offsets: &[u16; NUM_BUCKETS::<K>],
    batch_start: Position,
    buckets: &[[SyncUnsafeCell<MaybeUninit<(Position, Y)>>; REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>],
) {
    let mut bucket_offsets = *chunk_offsets;

    for ((ys, &count), batch_start) in ys
        .iter()
        .zip(counts)
        .zip((batch_start..).step_by(REDUCED_MATCHES_COUNT))
    {
        // SAFETY: Function contract guarantees that this many `y`s are initialized, hence the
        // count is also within bounds
        let ys = unsafe { ys.get_unchecked(..usize::from(count)).assume_init_ref() };

        for (&y, position) in ys.iter().zip(batch_start..) {
            let bucket_index = (u32::from(y) / u32::from(PARAM_BC)) as usize;

            // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
            unsafe {
                hint::assert_unchecked(bucket_index < NUM_BUCKETS::<K>);
            }
            let bucket_offset = bucket_offsets
                .get_mut(bucket_index)
                .expect("Bucket index is within bounds as asserted above; qed");
            let bucket = buckets
                .get(bucket_index)
                .expect("Bucket index is within bounds as asserted above; qed");

            // Entries past `REDUCED_BUCKET_SIZE` are thrown away
            if let Some(entry) = bucket.get(usize::from(*bucket_offset)) {
                // SAFETY: Function contract guarantees that offsets are exclusive to this chunk,
                // so this is the only place where this entry is accessed
                unsafe { &mut *entry.get() }.write((position, y));
                *bucket_offset += 1;
            }
        }
    }
}

/// Similar to [`group_by_buckets()`], but processes buckets instead of a flat list of `y`s.
///
/// Done as a counting sort: the first pass counts how many `y`s each chunk of the input
/// contributes to each bucket, which after a prefix sum tells every chunk where in each bucket its
/// `y`s go, so that the second (and by far the most expensive) pass can scatter them in parallel.
///
/// Both passes use parallel iterators rather than `rayon::broadcast()` that the rest of this
/// module prefers. A broadcast has to reach every thread of the pool before it makes progress, and
/// these two are called six times per set of tables while other sets are typically being built on
/// the same pool, at which point waiting for the whole pool costs several times more than the
/// grouping itself.
///
/// # Safety
/// `counts` must be the number of initialized `y`s in each entry of `ys`.
#[cfg(feature = "parallel")]
unsafe fn group_by_buckets_from_buckets<const K: u8>(
    ys: &[[MaybeUninit<Y>; REDUCED_MATCHES_COUNT]; NUM_BUCKET_PAIRS::<K>],
    counts: &[u16; NUM_BUCKET_PAIRS::<K>],
) -> Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]> {
    let chunk_size = GROUP_BY_BUCKETS_CHUNK_SIZE::<K>;
    // The last chunk is smaller unless bucket pairs divide evenly
    let chunk_range = |chunk_index: usize| {
        let start = chunk_index * chunk_size;

        start..(start + chunk_size).min(NUM_BUCKET_PAIRS::<K>)
    };

    // A chunk only ever counts a subset of a bucket, and a bucket holds at most
    // `MAX_BUCKET_SIZE` entries, so counts and the offsets they turn into both fit `u16`
    // SAFETY: Zeroes are the correct initial counts
    let mut chunk_offsets = unsafe {
        Box::<[[u16; NUM_BUCKETS::<K>]; GROUP_BY_BUCKETS_CHUNKS::<K>]>::new_zeroed().assume_init()
    };

    chunk_offsets
        .par_iter_mut()
        .enumerate()
        .for_each(|(chunk_index, chunk_offsets)| {
            let chunk_range = chunk_range(chunk_index);
            let (ys, counts) = (&ys[chunk_range.clone()], &counts[chunk_range]);

            // SAFETY: Guaranteed by function contract
            unsafe {
                count_ys_in_buckets::<K>(ys, counts, chunk_offsets);
            }
        });

    // Turn counts into offsets, ending up with the number of `y`s in each bucket
    let mut bucket_lengths = [0_u16; NUM_BUCKETS::<K>];
    for chunk_offsets in &mut *chunk_offsets {
        for (chunk_offset, bucket_length) in chunk_offsets.iter_mut().zip(&mut bucket_lengths) {
            let offset = *bucket_length;
            // Buckets are limited to `REDUCED_BUCKET_SIZE`, anything past that is thrown away,
            // which also keeps offsets within `u16`
            *bucket_length = (*bucket_length + *chunk_offset).min(REDUCED_BUCKET_SIZE as u16);
            *chunk_offset = offset;
        }
    }

    // Each element is wrapped individually because chunks that share a bucket write different
    // elements of it concurrently, and a `&mut` to the whole bucket would claim unique access to
    // elements belonging to other chunks
    // SAFETY: Contents is `MaybeUninit`
    let buckets = unsafe { Box::<_>::new_uninit().assume_init() };

    chunk_offsets
        .par_iter()
        .enumerate()
        .for_each(|(chunk_index, chunk_offsets)| {
            let chunk_range = chunk_range(chunk_index);
            let batch_start = Position::from((chunk_range.start * REDUCED_MATCHES_COUNT) as u32);
            let (ys, counts) = (&ys[chunk_range.clone()], &counts[chunk_range]);

            // SAFETY: Guaranteed by function contract, offsets of different chunks were made
            // disjoint by the prefix sum above
            unsafe {
                scatter_ys_into_buckets::<K>(ys, counts, chunk_offsets, batch_start, &buckets);
            }
        });

    let mut buckets = strip_sync_unsafe_cell_elements(buckets);

    // SAFETY: Bucket lengths were limited to `REDUCED_BUCKET_SIZE` by the prefix sum above
    unsafe {
        fill_bucket_tails::<K>(&mut buckets, &bucket_lengths);
    }

    // SAFETY: All entries are initialized
    unsafe { Box::from_raw(Box::into_raw(buckets).cast()) }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone)]
struct Match {
    left_position: Position,
    left_y: Y,
    right_position: Position,
}

/// `partial_y_offset` is in bits within `partial_y`
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub(super) fn compute_f1<const K: u8>(x: X, seed: &Seed) -> Y {
    const U32S_PER_BLOCK: usize = size_of::<ChaCha8Block>() / size_of::<u32>();

    let skip_bits = u32::from(K) * u32::from(x);
    let skip_u32s = skip_bits / u32::BITS;
    let partial_y_offset = skip_bits % u32::BITS;

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

    // `K` bits of `partial_y` followed by `PARAM_EXT` extra bits that will be cleared
    let pre_y = hi.funnel_shl(lo, partial_y_offset) >> (u32::BITS - u32::from(K + PARAM_EXT));
    // Mask for clearing the rest of bits of `pre_y`.
    let pre_y_mask = u32::MAX << PARAM_EXT;

    // Extract `PARAM_EXT` most significant bits from `x` and store in the final offset of
    // eventual `y` with the rest of bits being zero (`x` is `0..2^K`)
    let pre_ext = u32::from(x) >> (K - PARAM_EXT);

    // Combine all of the bits together:
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    Y::from((pre_y & pre_y_mask) | pre_ext)
}

#[cfg(any(feature = "alloc", test))]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub(super) fn compute_f1_simd<const K: u8>(
    xs: Simd<u32, COMPUTE_F1_SIMD_FACTOR>,
    partial_ys: &[u8; TABLE_1_YS_BATCH_SIMD::<K>],
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
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn find_matches_in_buckets<'a>(
    left_bucket_index: u32,
    left_bucket: &[(Position, Y); REDUCED_BUCKET_SIZE],
    right_bucket: &[(Position, Y); REDUCED_BUCKET_SIZE],
    // `PARAM_M * 2` corresponds to the upper bound number of matches a single `y` in the
    // left bucket might have here
    matches: &'a mut [MaybeUninit<Match>; REDUCED_MATCHES_COUNT + usize::from(PARAM_M) * 2],
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

    let left_targets = LeftTargets::new(left_base % 2 == 1);
    let mut next_match_index = 0;

    for &(left_position, y) in left_bucket {
        // `next_match_index >= REDUCED_MATCHES_COUNT` is crucial to make sure
        if left_position == Position::SENTINEL || next_match_index >= REDUCED_MATCHES_COUNT {
            // Sentinel values are padded to the end of the bucket
            break;
        }

        let r = R::from((u32::from(y) - left_base) as u16);

        for r_target in left_targets.calculate(r) {
            // SAFETY: Targets are always limited to `PARAM_BC`
            let [right_position_a, right_position_b] = unsafe { rmap.get(r_target) };

            if right_position_a != Position::SENTINEL {
                // SAFETY: Iteration will stop before `REDUCED_MATCHES_COUNT + PARAM_M * 2`
                // elements is inserted
                unsafe { matches.get_unchecked_mut(next_match_index) }.write(Match {
                    left_position,
                    left_y: y,
                    right_position: right_position_a,
                });
                next_match_index += 1;

                if right_position_b != Position::SENTINEL {
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

    // SAFETY: Initialized this many matches, which is also why the number of matches is within
    // bounds
    unsafe { matches.get_unchecked(..next_match_index).assume_init_ref() }
}

/// Simplified version of [`find_matches_in_buckets`] for verification purposes.
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub(super) fn has_match(left_y: Y, right_y: Y) -> bool {
    let left_bucket_index = u32::from(left_y) / u32::from(PARAM_BC);
    let left_r = R::from((u32::from(left_y) - left_bucket_index * u32::from(PARAM_BC)) as u16);
    let right_r = R::from((u32::from(right_y) % u32::from(PARAM_BC)) as u16);

    LeftTargets::new(left_bucket_index % 2 == 1).contains(left_r, right_r)
}

#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub(super) fn compute_fn<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    y: Y,
    left_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
    right_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
) -> (Y, Metadata<K, TABLE_NUMBER>) {
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
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
fn compute_fn_simd<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    left_ys: [Y; COMPUTE_FN_SIMD_FACTOR],
    left_metadatas: [Metadata<K, PARENT_TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
    right_metadatas: [Metadata<K, PARENT_TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
) -> (
    Simd<u32, COMPUTE_FN_SIMD_FACTOR>,
    [Metadata<K, TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
) {
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
                ab_blake3::single_block_hash(&input.as_flattened()[..input_len])
                    .expect("Exactly a single block worth of bytes; qed")
            } else {
                let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
                let input_a = y_bits | left_metadata_bits | right_bits_a;

                ab_blake3::single_block_hash(&input_a.to_be_bytes()[..num_bytes_with_data])
                    .expect("Exactly a single block worth of bytes; qed")
            }
        },
        )*
        ]
    });

    let y_outputs = Simd::from_array(
        hashes.map(|hash| u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])),
    ) >> (u32::BITS - y_size_bits(K) as u32);

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
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn match_to_result<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    m: &Match,
) -> (Y, [Position; 2], Metadata<K, TABLE_NUMBER>)
where
    Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
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
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn match_to_result_simd<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    matches: &[Match; COMPUTE_FN_SIMD_FACTOR],
) -> (
    Simd<u32, COMPUTE_FN_SIMD_FACTOR>,
    [[Position; 2]; COMPUTE_FN_SIMD_FACTOR],
    [Metadata<K, TABLE_NUMBER>; COMPUTE_FN_SIMD_FACTOR],
)
where
    Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
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
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn matches_to_results<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    matches: &[Match],
    ys: &mut [MaybeUninit<Y>],
    positions: &mut [MaybeUninit<[Position; 2]>],
    metadatas: &mut [MaybeUninit<Metadata<K, TABLE_NUMBER>>],
) where
    Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
{
    let (grouped_matches, other_matches) = matches.as_chunks::<COMPUTE_FN_SIMD_FACTOR>();
    let grouped_matches_len = grouped_matches.as_flattened().len();
    // SAFETY: Function contract guarantees that outputs are at least as long as `matches`
    let (grouped_ys, other_ys) = unsafe { ys.split_at_mut_unchecked(grouped_matches_len) };
    let grouped_ys = grouped_ys.as_chunks_mut::<COMPUTE_FN_SIMD_FACTOR>().0;
    // SAFETY: Function contract guarantees that outputs are at least as long as `matches`
    let (grouped_positions, other_positions) =
        unsafe { positions.split_at_mut_unchecked(grouped_matches_len) };
    let grouped_positions = grouped_positions
        .as_chunks_mut::<COMPUTE_FN_SIMD_FACTOR>()
        .0;
    // SAFETY: Function contract guarantees that outputs are at least as long as `matches`
    let (grouped_metadatas, other_metadatas) =
        unsafe { metadatas.split_at_mut_unchecked(grouped_matches_len) };
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
        let ys_group = Y::array_from_repr(ys_group.to_array());
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

/// Find matches between a pair of adjacent buckets of the parent table and turn them into the
/// results of the current table, returns the number of matches processed.
///
/// # Safety
/// Buckets must come from `parent_table`, `ys`, `positions` and `metadatas` must have at least as
/// many elements as there are matches in the pair of buckets (at most [`REDUCED_MATCHES_COUNT`]).
#[cfg(feature = "alloc")]
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn bucket_pair_to_results<
    const K: u8,
    const TABLE_NUMBER: u8,
    const PARENT_TABLE_NUMBER: u8,
>(
    parent_table: &Table<K, PARENT_TABLE_NUMBER>,
    left_bucket_index: u32,
    [left_bucket, right_bucket]: &[[(Position, Y); REDUCED_BUCKET_SIZE]; 2],
    ys: &mut [MaybeUninit<Y>],
    positions: &mut [MaybeUninit<[Position; 2]>],
    metadatas: &mut [MaybeUninit<Metadata<K, TABLE_NUMBER>>],
) -> usize
where
    Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
{
    let mut matches = [MaybeUninit::uninit(); _];
    // SAFETY: Positions are taken from `Table::buckets()` and correspond to initialized values
    let matches = unsafe {
        find_matches_in_buckets(left_bucket_index, left_bucket, right_bucket, &mut matches)
    };
    // Throw away some successful matches that are not that necessary
    let matches = &matches[..matches.len().min(REDUCED_MATCHES_COUNT)];

    // SAFETY: Guaranteed by function contract
    let (ys, positions, metadatas) = unsafe {
        (
            ys.get_unchecked_mut(..matches.len()),
            positions.get_unchecked_mut(..matches.len()),
            metadatas.get_unchecked_mut(..matches.len()),
        )
    };

    // SAFETY: Matches come from the parent table and the size of `ys`, `positions` and `metadatas`
    // is the same as the number of matches
    unsafe {
        matches_to_results(parent_table, matches, ys, positions, metadatas);
    }

    matches.len()
}

/// Subspace's little-endian s-bucket convention: maps a table-7 entry's `first_k_bits` to its
/// s-bucket, returning a value `>= Record::NUM_S_BUCKETS` for entries whose low `K - 16` bits are
/// set (those are discarded). Consensus verification derives the challenge from the s-bucket with
/// the same little-endian byte layout, so this convention is fixed.
#[cfg(feature = "alloc")]
#[inline(always)]
fn little_endian_s_bucket(first_k_bits: u32, k: u8) -> u32 {
    let low_bits = u32::from(k) - 16;
    if first_k_bits & ((1 << low_bits) - 1) != 0 {
        return u32::MAX;
    }
    let cs_lo = (first_k_bits >> (u32::from(k) - 8)) & 0xff;
    let cs_hi = (first_k_bits >> low_bits) & 0xff;
    cs_lo | (cs_hi << 8)
}

/// Find matches between a pair of adjacent buckets of the parent table, turn them into proof
/// targets of the last table and hand each of them over to `store_target`, which is called at most
/// [`REDUCED_MATCHES_COUNT`] times.
///
/// # Safety
/// Buckets must come from `parent_table`.
#[cfg(feature = "alloc")]
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn bucket_pair_to_proof_targets<const K: u8>(
    parent_table: &Table<K, 6>,
    left_bucket_index: u32,
    [left_bucket, right_bucket]: &[[(Position, Y); REDUCED_BUCKET_SIZE]; 2],
    mut store_target: impl FnMut(u16, [Position; 2]),
) {
    let mut matches = [MaybeUninit::uninit(); _];
    // SAFETY: Positions are taken from `Table::buckets()` and correspond to initialized values
    let matches = unsafe {
        find_matches_in_buckets(left_bucket_index, left_bucket, right_bucket, &mut matches)
    };
    // Throw away some successful matches that are not that necessary
    let matches = &matches[..matches.len().min(REDUCED_MATCHES_COUNT)];

    let (grouped_matches, other_matches) = matches.as_chunks::<COMPUTE_FN_SIMD_FACTOR>();

    for grouped_matches in grouped_matches {
        // SAFETY: Matches come from the parent table
        let (ys_group, positions_group, _) =
            unsafe { match_to_result_simd::<_, 7, _>(parent_table, grouped_matches) };

        let s_buckets = ys_group >> Simd::splat(u32::from(PARAM_EXT));

        for (s_bucket, p) in s_buckets.to_array().into_iter().zip(positions_group) {
            let Ok(s_bucket) = u16::try_from(little_endian_s_bucket(s_bucket, K)) else {
                continue;
            };

            store_target(s_bucket, p);
        }
    }
    for other_match in other_matches {
        // SAFETY: Matches come from the parent table
        let (y, p, _) = unsafe { match_to_result::<_, 7, _>(parent_table, other_match) };

        let Ok(s_bucket) = u16::try_from(little_endian_s_bucket(y.first_k_bits(), K)) else {
            continue;
        };

        store_target(s_bucket, p);
    }
}

/// Store a proof target unless a target for this s-bucket was already found
#[cfg(feature = "alloc")]
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
fn store_proof_target(
    table_6_proof_targets: &mut [[Position; 2]; const { Record::NUM_S_BUCKETS }],
    s_bucket: u16,
    positions: [Position; 2],
) {
    // There is an s-bucket for every possible `u16`, which is what makes the indexing below
    // statically within bounds
    const {
        assert!(Record::NUM_S_BUCKETS == usize::from(u16::MAX) + 1);
    }

    let target = &mut table_6_proof_targets[usize::from(s_bucket)];
    if target == &[Position::ZERO; 2] {
        *target = positions;
    }
}

/// Similar to [`Table`], but smaller size for later processing stages
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub(super) enum PrunedTable<const K: u8, const TABLE_NUMBER: u8> {
    First,
    /// Other tables
    Other {
        /// Left and right entry positions in a previous table encoded into bits
        positions: Box<[MaybeUninit<[Position; 2]>; MAX_TABLE_SIZE::<K>]>,
    },
    /// Other tables
    #[cfg(feature = "parallel")]
    OtherBuckets {
        /// Left and right entry positions in a previous table encoded into bits.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        positions:
            Box<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; NUM_BUCKET_PAIRS::<K>]>,
    },
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> PrunedTable<K, TABLE_NUMBER> {
    /// Get `[left_position, right_position]` of a previous table for a specified position in a
    /// current table.
    ///
    /// # Safety
    /// `self` must not be [`Self::First`], `position` must come from [`Table::buckets()`] or
    /// [`Self::position()`] and not be a sentinel value.
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) unsafe fn position(&self, position: Position) -> [Position; 2] {
        match self {
            Self::First => {
                // SAFETY: Guaranteed by function contract
                unsafe { hint::unreachable_unchecked() }
            }
            Self::Other { positions } => {
                // SAFETY: All non-sentinel positions returned by [`Self::buckets()`] are valid
                unsafe { positions.get_unchecked(usize::from(position)).assume_init() }
            }
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { positions } => {
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
pub(super) enum Table<const K: u8, const TABLE_NUMBER: u8> {
    /// First table
    First {
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]>,
    },
    /// Other tables
    Other {
        /// Left and right entry positions in a previous table encoded into bits
        positions: Box<[MaybeUninit<[Position; 2]>; MAX_TABLE_SIZE::<K>]>,
        /// Metadata corresponding to each entry
        metadatas: Box<[MaybeUninit<Metadata<K, TABLE_NUMBER>>; MAX_TABLE_SIZE::<K>]>,
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]>,
    },
    /// Other tables
    #[cfg(feature = "parallel")]
    OtherBuckets {
        /// Left and right entry positions in a previous table encoded into bits.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        positions:
            Box<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; NUM_BUCKET_PAIRS::<K>]>,
        /// Metadata corresponding to each entry.
        ///
        /// Only positions from the `buckets` field are guaranteed to be initialized.
        metadatas: Box<
            [[MaybeUninit<Metadata<K, TABLE_NUMBER>>; REDUCED_MATCHES_COUNT];
                NUM_BUCKET_PAIRS::<K>],
        >,
        /// Each bucket contains positions of `Y` values that belong to it and corresponding `y`.
        ///
        /// Buckets are padded with sentinel values to `REDUCED_BUCKETS_SIZE`.
        buckets: Box<[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>]>,
    },
}

#[cfg(feature = "alloc")]
impl<const K: u8> Table<K, 1> {
    /// Create the table
    pub(super) fn create(seed: Seed) -> Self {
        // `MAX_BUCKET_SIZE` is not actively used, but is an upper-bound reference for the other
        // parameters
        debug_assert!(
            MAX_BUCKET_SIZE >= bucket_size_upper_bound(K, BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS),
            "Max bucket size is not sufficiently large"
        );

        let partial_ys = partial_ys::<K>(seed);

        // SAFETY: Contents is `MaybeUninit`
        let mut ys =
            unsafe { Box::<[MaybeUninit<Y>; MAX_TABLE_SIZE::<K>]>::new_uninit().assume_init() };

        let ys = compute_table_1_ys::<K>(&partial_ys, &mut ys);

        // TODO: Try to group buckets in the process of collecting `y`s
        let buckets = group_by_buckets::<K>(ys);

        Self::First { buckets }
    }

    /// Create the table, leverages available parallelism
    #[cfg(feature = "parallel")]
    pub(super) fn create_parallel(seed: Seed) -> Self {
        // `MAX_BUCKET_SIZE` is not actively used, but is an upper-bound reference for the other
        // parameters
        debug_assert!(
            MAX_BUCKET_SIZE >= bucket_size_upper_bound(K, BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS),
            "Max bucket size is not sufficiently large"
        );

        let partial_ys = partial_ys::<K>(seed);

        // SAFETY: Contents is `MaybeUninit`
        let mut ys =
            unsafe { Box::<[MaybeUninit<Y>; MAX_TABLE_SIZE::<K>]>::new_uninit().assume_init() };

        let ys = compute_table_1_ys::<K>(&partial_ys, &mut ys);

        // TODO: Try to group buckets in the process of collecting `y`s
        let buckets = group_by_buckets::<K>(ys);

        Self::First { buckets }
    }
}

#[cfg(feature = "alloc")]
pub(super) impl(self) trait SupportedOtherTables {}

#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 2> {}
#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 3> {}
#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 4> {}
#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 5> {}
#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 6> {}
#[cfg(feature = "alloc")]
impl<const K: u8> SupportedOtherTables for Table<K, 7> {}

#[cfg(feature = "alloc")]
pub(super) impl(self) trait NotLastTable {}

#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 1> {}
#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 2> {}
#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 3> {}
#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 4> {}
#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 5> {}
#[cfg(feature = "alloc")]
impl<const K: u8> NotLastTable for Table<K, 6> {}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: SupportedOtherTables,
{
    /// Creates a new [`TABLE_NUMBER`] table. There also exists [`Self::create_parallel()`] that
    /// trades CPU efficiency and memory usage for lower latency and with multiple parallel calls,
    /// better overall performance.
    pub(super) fn create<const PARENT_TABLE_NUMBER: u8>(
        parent_table: Table<K, PARENT_TABLE_NUMBER>,
    ) -> (Self, PrunedTable<K, PARENT_TABLE_NUMBER>)
    where
        Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
    {
        // SAFETY: Contents is `MaybeUninit`
        let mut ys =
            unsafe { Box::<[MaybeUninit<Y>; MAX_TABLE_SIZE::<K>]>::new_uninit().assume_init() };
        // SAFETY: Contents is `MaybeUninit`
        let mut positions = unsafe {
            Box::<[MaybeUninit<[Position; 2]>; MAX_TABLE_SIZE::<K>]>::new_uninit().assume_init()
        };
        // SAFETY: Contents is `MaybeUninit`
        let mut metadatas = unsafe {
            Box::<[MaybeUninit<Metadata<K, TABLE_NUMBER>>; MAX_TABLE_SIZE::<K>]>::new_uninit()
                .assume_init()
        };

        let initialized_elements =
            Self::create_internal(&parent_table, &mut ys, &mut positions, &mut metadatas);

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

    /// The part of [`Self::create()`] that works with already allocated memory, returns the number
    /// of initialized elements in each of the outputs
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn create_internal<const PARENT_TABLE_NUMBER: u8>(
        parent_table: &Table<K, PARENT_TABLE_NUMBER>,
        ys: &mut [MaybeUninit<Y>; MAX_TABLE_SIZE::<K>],
        positions: &mut [MaybeUninit<[Position; 2]>; MAX_TABLE_SIZE::<K>],
        metadatas: &mut [MaybeUninit<Metadata<K, TABLE_NUMBER>>; MAX_TABLE_SIZE::<K>],
    ) -> usize
    where
        Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
    {
        let mut initialized_elements = 0_usize;

        for (buckets, left_bucket_index) in parent_table.buckets().array_windows().zip(0..) {
            // SAFETY: Already initialized this many elements, preallocated length is an upper
            // bound and is always sufficient
            let (ys, positions, metadatas) = unsafe {
                (
                    ys.get_unchecked_mut(initialized_elements..),
                    positions.get_unchecked_mut(initialized_elements..),
                    metadatas.get_unchecked_mut(initialized_elements..),
                )
            };

            // SAFETY: Buckets are taken from `parent_table`, preallocated length is an upper bound
            // and is always sufficient
            initialized_elements += unsafe {
                bucket_pair_to_results::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                    parent_table,
                    left_bucket_index,
                    buckets,
                    ys,
                    positions,
                    metadatas,
                )
            };
        }

        initialized_elements
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// performance (though not efficiency of CPU and memory usage), if you create multiple tables
    /// in parallel, prefer this method for better overall performance.
    #[cfg(feature = "parallel")]
    pub(super) fn create_parallel<const PARENT_TABLE_NUMBER: u8>(
        parent_table: Table<K, PARENT_TABLE_NUMBER>,
    ) -> (Self, PrunedTable<K, PARENT_TABLE_NUMBER>)
    where
        Table<K, PARENT_TABLE_NUMBER>: NotLastTable,
    {
        // SAFETY: Contents is `MaybeUninit`
        let ys = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; NUM_BUCKET_PAIRS::<K>]>::new_uninit().assume_init()
        };
        // SAFETY: Contents is `MaybeUninit`
        let positions = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; NUM_BUCKET_PAIRS::<K>]>::new_uninit().assume_init()
        };
        // SAFETY: Contents is `MaybeUninit`
        let metadatas = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; NUM_BUCKET_PAIRS::<K>]>::new_uninit().assume_init()
        };
        let global_results_counts =
            array::from_fn::<_, { NUM_BUCKET_PAIRS::<K> }, _>(|_| SyncUnsafeCell::new(0u16));

        let buckets = parent_table.buckets();
        // Iterate over buckets in batches, such that a cache line worth of bytes is taken from
        // `global_results_counts` each time to avoid unnecessary false sharing
        let bucket_batch_size = CACHE_LINE_SIZE / size_of::<u16>();
        let bucket_batch_index = AtomicUsize::new(0);

        rayon::broadcast(|_ctx| {
            loop {
                let bucket_batch_index = bucket_batch_index.fetch_add(1, Ordering::Relaxed);

                let buckets_batch = buckets
                    .array_windows()
                    .enumerate()
                    .skip(bucket_batch_index * bucket_batch_size)
                    .take(bucket_batch_size);

                if buckets_batch.is_empty() {
                    break;
                }

                for (left_bucket_index, buckets) in buckets_batch {
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

                    // SAFETY: Buckets are taken from `parent_table`, the size of `ys`, `positions`
                    // and `metadatas` is larger or equal to the number of matches
                    *count = unsafe {
                        bucket_pair_to_results::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                            &parent_table,
                            left_bucket_index as u32,
                            buckets,
                            ys,
                            positions,
                            metadatas,
                        ) as u16
                    };
                }
            }
        });

        let parent_table = parent_table.prune();

        let ys = strip_sync_unsafe_cell(ys);
        let positions = strip_sync_unsafe_cell(positions);
        let metadatas = strip_sync_unsafe_cell(metadatas);

        let global_results_counts = global_results_counts.map(SyncUnsafeCell::into_inner);

        // SAFETY: `global_results_counts` corresponds to the number of initialized `ys`
        let buckets = unsafe { group_by_buckets_from_buckets::<K>(&ys, &global_results_counts) };

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
    /// `self` must not be [`Self::First`], `position` must come from [`Self::buckets()`] or
    /// [`Self::position()`] or [`PrunedTable::position()`] and not be a sentinel value.
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) unsafe fn position(&self, position: Position) -> [Position; 2] {
        #[expect(
            clippy::rest_pattern_accessible_field,
            reason = "Do not need other fields"
        )]
        match self {
            Self::First { .. } => {
                // SAFETY: Guaranteed by function contract
                unsafe { hint::unreachable_unchecked() }
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
impl<const K: u8> Table<K, 7>
where
    Self: SupportedOtherTables,
{
    /// Proof targets from the last table into the previous table, one for each
    /// [`Record::NUM_S_BUCKETS`].
    pub(super) fn create_proof_targets(
        parent_table: Table<K, 6>,
    ) -> (
        Box<[[Position; 2]; const { Record::NUM_S_BUCKETS }]>,
        PrunedTable<K, 6>,
    )
    where
        Table<K, 6>: NotLastTable,
    {
        // SAFETY: Data structure filled with zeroes is a valid invariant
        let mut table_6_proof_targets = unsafe {
            Box::<[[Position; 2]; const { Record::NUM_S_BUCKETS }]>::new_zeroed().assume_init()
        };

        Self::create_proof_targets_internal(&parent_table, &mut table_6_proof_targets);

        let parent_table = parent_table.prune();

        (table_6_proof_targets, parent_table)
    }

    /// The part of [`Self::create_proof_targets()`] that works with already allocated memory
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn create_proof_targets_internal(
        parent_table: &Table<K, 6>,
        table_6_proof_targets: &mut [[Position; 2]; const { Record::NUM_S_BUCKETS }],
    ) {
        for (buckets, left_bucket_index) in parent_table.buckets().array_windows().zip(0..) {
            // SAFETY: Buckets are taken from `parent_table`
            unsafe {
                bucket_pair_to_proof_targets(
                    parent_table,
                    left_bucket_index,
                    buckets,
                    |s_bucket, positions| {
                        store_proof_target(table_6_proof_targets, s_bucket, positions);
                    },
                );
            }
        }
    }

    /// Almost the same as [`Self::create_proof_targets()`], but uses parallelism internally for
    /// better performance (though not efficiency of CPU and memory usage), if you create multiple
    /// tables in parallel, prefer this method for better overall performance.
    #[cfg(feature = "parallel")]
    pub(super) fn create_proof_targets_parallel(
        parent_table: Table<K, 6>,
    ) -> (
        Box<[[Position; 2]; const { Record::NUM_S_BUCKETS }]>,
        PrunedTable<K, 6>,
    )
    where
        Table<K, 6>: NotLastTable,
    {
        // SAFETY: Contents is `MaybeUninit`
        let buckets_positions = unsafe {
            Box::<[SyncUnsafeCell<[MaybeUninit<_>; REDUCED_MATCHES_COUNT]>; NUM_BUCKET_PAIRS::<K>]>::new_uninit().assume_init()
        };
        let global_results_counts =
            array::from_fn::<_, { NUM_BUCKET_PAIRS::<K> }, _>(|_| SyncUnsafeCell::new(0u16));

        let buckets = parent_table.buckets();
        // Iterate over buckets in batches, such that a cache line worth of bytes is taken from
        // `global_results_counts` each time to avoid unnecessary false sharing
        let bucket_batch_size = CACHE_LINE_SIZE / size_of::<u16>();
        let bucket_batch_index = AtomicUsize::new(0);

        rayon::broadcast(|_ctx| {
            loop {
                let bucket_batch_index = bucket_batch_index.fetch_add(1, Ordering::Relaxed);

                let buckets_batch = buckets
                    .array_windows()
                    .enumerate()
                    .skip(bucket_batch_index * bucket_batch_size)
                    .take(bucket_batch_size);

                if buckets_batch.is_empty() {
                    break;
                }

                for (left_bucket_index, buckets) in buckets_batch {
                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let buckets_positions =
                        unsafe { &mut *buckets_positions.get_unchecked(left_bucket_index).get() };
                    // SAFETY: This is the only place where `left_bucket_index`'s entry is accessed
                    // at this time, and it is guaranteed to be in range
                    let count = unsafe {
                        &mut *global_results_counts.get_unchecked(left_bucket_index).get()
                    };

                    let mut num_targets = 0_usize;
                    let store_target = |s_bucket, positions| {
                        // SAFETY: Targets are stored at most `REDUCED_MATCHES_COUNT` times, which
                        // is the size of `buckets_positions`
                        unsafe {
                            hint::assert_unchecked(num_targets < REDUCED_MATCHES_COUNT);
                        }
                        buckets_positions[num_targets].write((s_bucket, positions));
                        num_targets += 1;
                    };

                    // SAFETY: Buckets are taken from `parent_table`
                    unsafe {
                        bucket_pair_to_proof_targets(
                            &parent_table,
                            left_bucket_index as u32,
                            buckets,
                            store_target,
                        );
                    }

                    *count = num_targets as u16;
                }
            }
        });

        let parent_table = parent_table.prune();

        let buckets_positions = strip_sync_unsafe_cell(buckets_positions);
        let global_results_counts = global_results_counts.map(SyncUnsafeCell::into_inner);

        // SAFETY: Data structure filled with zeroes is a valid invariant
        let mut table_6_proof_targets = unsafe {
            Box::<[[Position; 2]; const { Record::NUM_S_BUCKETS }]>::new_zeroed().assume_init()
        };

        // SAFETY: `global_results_counts` corresponds to the number of initialized targets
        unsafe {
            Self::merge_proof_targets(
                &buckets_positions,
                &global_results_counts,
                &mut table_6_proof_targets,
            );
        }

        (table_6_proof_targets, parent_table)
    }

    /// Merge proof targets found by [`Self::create_proof_targets_parallel()`] in parallel.
    ///
    /// # Safety
    /// `counts` must be the number of initialized targets in each entry of `buckets_targets`.
    #[cfg(feature = "parallel")]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    #[expect(clippy::type_complexity, reason = "Internal API")]
    unsafe fn merge_proof_targets(
        buckets_targets: &[[MaybeUninit<(u16, [Position; 2])>; REDUCED_MATCHES_COUNT];
             NUM_BUCKET_PAIRS::<K>],
        counts: &[u16; NUM_BUCKET_PAIRS::<K>],
        table_6_proof_targets: &mut [[Position; 2]; const { Record::NUM_S_BUCKETS }],
    ) {
        for (targets, &count) in buckets_targets.iter().zip(counts) {
            // SAFETY: Function contract guarantees that this many targets are initialized, hence
            // the count is also within bounds
            let targets = unsafe {
                targets
                    .get_unchecked(..usize::from(count))
                    .assume_init_ref()
            };

            for &(s_bucket, positions) in targets {
                store_proof_target(table_6_proof_targets, s_bucket, positions);
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: NotLastTable,
{
    /// Returns `None` for an invalid position or for table number 7.
    ///
    /// # Safety
    /// `position` must come from [`Self::buckets()`] and not be a sentinel value.
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    unsafe fn metadata(&self, position: Position) -> Metadata<K, TABLE_NUMBER> {
        #[expect(
            clippy::rest_pattern_accessible_field,
            reason = "Do not need other fields"
        )]
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
impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER> {
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn prune(self) -> PrunedTable<K, TABLE_NUMBER> {
        #[expect(
            clippy::rest_pattern_accessible_field,
            reason = "Do not need other fields"
        )]
        match self {
            Self::First { .. } => PrunedTable::First,
            Self::Other { positions, .. } => PrunedTable::Other { positions },
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { positions, .. } => PrunedTable::OtherBuckets { positions },
        }
    }

    /// Positions of `y`s grouped by the bucket they belong to
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) fn buckets(&self) -> &[[(Position, Y); REDUCED_BUCKET_SIZE]; NUM_BUCKETS::<K>] {
        #[expect(
            clippy::rest_pattern_accessible_field,
            reason = "Do not need other fields"
        )]
        match self {
            Self::First { buckets } => buckets,
            Self::Other { buckets, .. } => buckets,
            #[cfg(feature = "parallel")]
            Self::OtherBuckets { buckets, .. } => buckets,
        }
    }
}
