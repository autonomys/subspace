#[cfg(test)]
mod tests;
pub(super) mod types;

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT, PARAM_M};
use crate::chiapos::table::types::{Metadata, Position, X, Y};
use crate::chiapos::utils::EvaluatableUsize;
use crate::chiapos::Seed;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha8, Key, Nonce};
use core::mem;
use core::simd::num::SimdUint;
use core::simd::Simd;
#[cfg(any(feature = "parallel", test))]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(feature = "parallel", test))]
use rayon::prelude::*;
use seq_macro::seq;
use subspace_core_primitives::crypto::{blake3_hash, blake3_hash_list};

pub(super) const COMPUTE_F1_SIMD_FACTOR: usize = 8;

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

/// ChaCha8 [`Vec`] sufficient for the whole first table for [`K`].
/// Prefer [`partial_y`] if you need partial y just for a single `x`.
fn partial_ys<const K: u8>(seed: Seed) -> Vec<u8> {
    let output_len_bits = usize::from(K) * (1 << K);
    let mut output = vec![0; output_len_bits.div_ceil(u8::BITS as usize)];

    let key = Key::from(seed);
    let nonce = Nonce::default();

    let mut cipher = ChaCha8::new(&key, &nonce);

    cipher.apply_keystream(&mut output);

    output
}

/// ChaCha8 byte for a single `y` at `x` in the first table for [`K`], returns bytes and offset (in
/// bits) within those bytes at which data start.
/// Prefer [`partial_ys`] if you process the whole first table.
pub(super) fn partial_y<const K: u8>(
    seed: Seed,
    x: X,
) -> ([u8; (K as usize * 2).div_ceil(u8::BITS as usize)], usize) {
    let skip_bits = usize::from(K) * usize::from(x);
    let skip_bytes = skip_bits / u8::BITS as usize;
    let skip_bits = skip_bits % u8::BITS as usize;

    let mut output = [0; (K as usize * 2).div_ceil(u8::BITS as usize)];

    let key = Key::from(seed);
    let nonce = Nonce::default();

    let mut cipher = ChaCha8::new(&key, &nonce);

    cipher.seek(skip_bytes);
    cipher.apply_keystream(&mut output);

    (output, skip_bits)
}

fn calculate_left_targets() -> Vec<Vec<Vec<Position>>> {
    let param_b = u32::from(PARAM_B);
    let param_c = u32::from(PARAM_C);

    (0..=1u32)
        .map(|parity| {
            (0..u32::from(PARAM_BC))
                .map(|r| {
                    let c = r / param_c;

                    (0..u32::from(PARAM_M))
                        .map(|m| {
                            let target = ((c + m) % param_b) * param_c
                                + (((2 * m + parity) * (2 * m + parity) + r) % param_c);
                            Position::from(target)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn calculate_left_target_on_demand(parity: usize, r: usize, m: usize) -> usize {
    let param_b = usize::from(PARAM_B);
    let param_c = usize::from(PARAM_C);

    let c = r / param_c;

    ((c + m) % param_b) * param_c + (((2 * m + parity) * (2 * m + parity) + r) % param_c)
}

/// Caches that can be used to optimize creation of multiple [`Tables`](super::Tables).
#[derive(Debug, Clone)]
pub struct TablesCache<const K: u8> {
    buckets: Vec<Bucket>,
    rmap_scratch: Vec<RmapItem>,
    left_targets: Vec<Vec<Vec<Position>>>,
}

impl<const K: u8> Default for TablesCache<K> {
    /// Create new instance
    fn default() -> Self {
        Self {
            buckets: Vec::new(),
            rmap_scratch: Vec::new(),
            left_targets: calculate_left_targets(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Match {
    left_position: Position,
    left_y: Y,
    right_position: Position,
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
struct Bucket {
    /// Bucket index
    bucket_index: u32,
    /// Start position of this bucket in the table
    start_position: Position,
    /// Size of this bucket
    size: Position,
}

#[derive(Debug, Default, Copy, Clone)]
pub(super) struct RmapItem {
    count: Position,
    start_position: Position,
}

/// `partial_y_offset` is in bits
pub(super) fn compute_f1<const K: u8>(x: X, partial_y: &[u8], partial_y_offset: usize) -> Y {
    let partial_y_length =
        (partial_y_offset % u8::BITS as usize + usize::from(K)).div_ceil(u8::BITS as usize);
    let mut pre_y_bytes = 0u64.to_be_bytes();
    pre_y_bytes[..partial_y_length]
        .copy_from_slice(&partial_y[partial_y_offset / u8::BITS as usize..][..partial_y_length]);
    // Contains `K` desired bits of `partial_y` in the final offset of eventual `y` with the rest
    // of bits being in undefined state
    let pre_y = u64::from_be_bytes(pre_y_bytes)
        >> (u64::BITS as usize - usize::from(K + PARAM_EXT) - partial_y_offset % u8::BITS as usize);
    let pre_y = pre_y as u32;
    // Mask for clearing the rest of bits of `pre_y`.
    let pre_y_mask = (u32::MAX << usize::from(PARAM_EXT))
        & (u32::MAX >> (u32::BITS as usize - usize::from(K + PARAM_EXT)));

    // Extract `PARAM_EXT` most significant bits from `x` and store in the final offset of
    // eventual `y` with the rest of bits being in undefined state.
    let pre_ext = u32::from(x) >> (usize::from(K - PARAM_EXT));
    // Mask for clearing the rest of bits of `pre_ext`.
    let pre_ext_mask = u32::MAX >> (u32::BITS as usize - usize::from(PARAM_EXT));

    // Combine all of the bits together:
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    Y::from((pre_y & pre_y_mask) | (pre_ext & pre_ext_mask))
}

pub(super) fn compute_f1_simd<const K: u8>(
    xs: [X; COMPUTE_F1_SIMD_FACTOR],
    partial_ys: &[u8; K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize],
) -> [Y; COMPUTE_F1_SIMD_FACTOR] {
    // Each element contains `K` desired bits of `partial_ys` in the final offset of eventual `ys`
    // with the rest of bits being in undefined state
    let pre_ys_bytes: Simd<_, COMPUTE_F1_SIMD_FACTOR> = Simd::from(seq!(N in 0..8 {
        [
        #(
        {
            #[allow(clippy::erasing_op, clippy::identity_op)]
            let partial_y_offset = N * usize::from(K);
            let partial_y_length =
                (partial_y_offset % u8::BITS as usize + usize::from(K)).div_ceil(u8::BITS as usize);
            let mut pre_y_bytes = 0u64.to_be_bytes();
            pre_y_bytes[..partial_y_length].copy_from_slice(
                &partial_ys[partial_y_offset / u8::BITS as usize..][..partial_y_length],
            );

            u64::from_be_bytes(pre_y_bytes)
        },
        )*
        ]
    }));
    let pre_ys_right_offset: Simd<_, COMPUTE_F1_SIMD_FACTOR> = Simd::from(seq!(N in 0..8 {
        [
        #(
        {
            #[allow(clippy::erasing_op, clippy::identity_op)]
            let partial_y_offset = N * u32::from(K);
            u64::from(u64::BITS - u32::from(K + PARAM_EXT) - partial_y_offset % u8::BITS)
        },
        )*
        ]
    }));
    // TODO: both this and above operations are most likely possible on x86-64 with a special
    //  intrinsic in a more efficient way
    let pre_ys = pre_ys_bytes >> pre_ys_right_offset;

    // Mask for clearing the rest of bits of `pre_ys`.
    let pre_ys_mask = Simd::splat(
        (u32::MAX << usize::from(PARAM_EXT))
            & (u32::MAX >> (u32::BITS as usize - usize::from(K + PARAM_EXT))),
    );

    // SAFETY: `X` is `#[repr(transparent)]` and guaranteed to have the same memory layout as `u32`
    let xs =
        unsafe { mem::transmute::<[X; COMPUTE_F1_SIMD_FACTOR], [u32; COMPUTE_F1_SIMD_FACTOR]>(xs) };
    // Extract `PARAM_EXT` most significant bits from `xs` and store in the final offset of
    // eventual `ys` with the rest of bits being in undefined state.
    let pre_exts = Simd::from(xs) >> Simd::splat(u32::from(K - PARAM_EXT));

    // Mask for clearing the rest of bits of `pre_exts`.
    let pre_exts_mask = Simd::splat(u32::MAX >> (u32::BITS as usize - usize::from(PARAM_EXT)));

    // Combine all of the bits together:
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    // NOTE: `pre_exts_mask` is unnecessary here and makes no difference, but it allows compiler to
    // generate faster code 🤷‍
    let ys = (pre_ys.cast() & pre_ys_mask) | (pre_exts & pre_exts_mask);

    // SAFETY: `Y` is `#[repr(transparent)]` and guaranteed to have the same memory layout as `u32`
    unsafe { mem::transmute(ys.to_array()) }
}

/// `rmap_scratch` is just an optimization to reuse allocations between calls.
///
/// For verification purposes use [`num_matches`] instead.
///
/// Returns `None` if either of buckets is empty.
fn find_matches<'a>(
    left_bucket_ys: &'a [Y],
    left_bucket_start_position: Position,
    right_bucket_ys: &'a [Y],
    right_bucket_start_position: Position,
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<Position>>],
) -> Option<impl Iterator<Item = Match> + 'a> {
    // Clear and set to correct size with zero values
    rmap_scratch.clear();
    rmap_scratch.resize_with(usize::from(PARAM_BC), RmapItem::default);
    let rmap = rmap_scratch;

    // Both left and right buckets can be empty
    let first_left_bucket_y = *left_bucket_ys.first()?;
    let first_right_bucket_y = *right_bucket_ys.first()?;
    // Since all entries in a bucket are obtained after division by `PARAM_BC`, we can compute
    // quotient more efficiently by subtracting base value rather than computing remainder of
    // division
    let base = (usize::from(first_right_bucket_y) / usize::from(PARAM_BC)) * usize::from(PARAM_BC);
    for (&y, right_position) in right_bucket_ys.iter().zip(right_bucket_start_position..) {
        let r = usize::from(y) - base;

        // Same `y` and as the result `r` can appear in the table multiple times, in which case
        // they'll all occupy consecutive slots in `right_bucket` and all we need to store is just
        // the first position and number of elements.
        if rmap[r].count == Position::ZERO {
            rmap[r].start_position = right_position;
        }
        rmap[r].count += Position::ONE;
    }
    let rmap = rmap.as_slice();

    // Same idea as above, but avoids division by leveraging the fact that each bucket is exactly
    // `PARAM_BC` away from the previous one in terms of divisor by `PARAM_BC`
    let base = base - usize::from(PARAM_BC);
    let parity = (usize::from(first_left_bucket_y) / usize::from(PARAM_BC)) % 2;
    let left_targets = &left_targets[parity];

    Some(
        left_bucket_ys
            .iter()
            .zip(left_bucket_start_position..)
            .flat_map(move |(&y, left_position)| {
                let r = usize::from(y) - base;
                let left_targets = &left_targets[r];

                (0..usize::from(PARAM_M)).flat_map(move |m| {
                    let r_target = left_targets[m];
                    let rmap_item = rmap[usize::from(r_target)];

                    (rmap_item.start_position..rmap_item.start_position + rmap_item.count).map(
                        move |right_position| Match {
                            left_position,
                            left_y: y,
                            right_position,
                        },
                    )
                })
            }),
    )
}

/// Simplified version of [`find_matches`] for verification purposes.
pub(super) fn num_matches(left_y: Y, right_y: Y) -> usize {
    let right_r = usize::from(right_y) % usize::from(PARAM_BC);
    let parity = (usize::from(left_y) / usize::from(PARAM_BC)) % 2;
    let left_r = usize::from(left_y) % usize::from(PARAM_BC);

    let mut matches = 0;
    for m in 0..usize::from(PARAM_M) {
        let r_target = calculate_left_target_on_demand(parity, left_r, m);
        if r_target == right_r {
            matches += 1;
        }
    }

    matches
}

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

    // Only supports `K` from 15 to 25 (otherwise math will not be correct when concatenating y,
    // left metadata and right metadata)
    let hash = {
        // Take only bytes where bits were set
        let num_bytes_with_data = (y_size_bits(K) + metadata_size_bits(K, PARENT_TABLE_NUMBER) * 2)
            .div_ceil(u8::BITS as usize);

        // Collect `K` most significant bits of `y` at the final offset of eventual `input_a`
        let y_bits = u128::from(y) << (u128::BITS as usize - y_size_bits(K));

        // Move bits of `left_metadata` at the final offset of eventual `input_a`
        let left_metadata_bits =
            left_metadata << (u128::BITS as usize - parent_metadata_bits - y_size_bits(K));

        // Part of the `right_bits` at the final offset of eventual `input_a`
        let y_and_left_bits = y_size_bits(K) + parent_metadata_bits;
        let right_bits_start_offset = u128::BITS as usize - parent_metadata_bits;

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

            blake3_hash_list(&[
                &input_a.to_be_bytes(),
                &input_b.to_be_bytes()
                    [..right_bits_pushed_into_input_b.div_ceil(u8::BITS as usize)],
            ])
        } else {
            let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
            let input_a = y_bits | left_metadata_bits | right_bits_a;

            blake3_hash(&input_a.to_be_bytes()[..num_bytes_with_data])
        }
    };

    let y_output = Y::from(
        u32::from_be_bytes(
            hash[..mem::size_of::<u32>()]
                .try_into()
                .expect("Hash if statically guaranteed to have enough bytes; qed"),
        ) >> (u32::BITS as usize - y_size_bits(K)),
    );

    let metadata_size_bits = metadata_size_bits(K, TABLE_NUMBER);

    let metadata = if TABLE_NUMBER < 4 {
        (left_metadata << parent_metadata_bits) | right_metadata
    } else if metadata_size_bits > 0 {
        // For K under 25 it is guaranteed that metadata + bit offset will always fit into u128.
        // We collect bytes necessary, potentially with extra bits at the start and end of the bytes
        // that will be taken care of later.
        let metadata = u128::from_be_bytes(
            hash[y_size_bits(K) / u8::BITS as usize..][..mem::size_of::<u128>()]
                .try_into()
                .expect("Always enough bits for any K; qed"),
        );
        // Remove extra bits at the beginning
        let metadata = metadata << (y_size_bits(K) % u8::BITS as usize);
        // Move bits into correct location
        metadata >> (u128::BITS as usize - metadata_size_bits)
    } else {
        0
    };

    (y_output, Metadata::from(metadata))
}

fn match_to_result<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    last_table: &Table<K, PARENT_TABLE_NUMBER>,
    m: Match,
) -> (Y, [Position; 2], Metadata<K, TABLE_NUMBER>)
where
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    let left_metadata = last_table
        .metadata(m.left_position)
        .expect("Position resulted from matching is correct; qed");
    let right_metadata = last_table
        .metadata(m.right_position)
        .expect("Position resulted from matching is correct; qed");

    let (y, metadata) =
        compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(m.left_y, left_metadata, right_metadata);

    (y, [m.left_position, m.right_position], metadata)
}

fn match_and_compute_fn<'a, const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    last_table: &'a Table<K, PARENT_TABLE_NUMBER>,
    left_bucket: Bucket,
    right_bucket: Bucket,
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<Position>>],
    results_table: &mut Vec<(Y, [Position; 2], Metadata<K, TABLE_NUMBER>)>,
) where
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    let Some(matches) = find_matches(
        &last_table.ys()[usize::from(left_bucket.start_position)..]
            [..usize::from(left_bucket.size)],
        left_bucket.start_position,
        &last_table.ys()[usize::from(right_bucket.start_position)..]
            [..usize::from(right_bucket.size)],
        right_bucket.start_position,
        rmap_scratch,
        left_targets,
    ) else {
        return;
    };

    matches.for_each(|m| {
        results_table.push(match_to_result(last_table, m));
    });
}

#[derive(Debug)]
pub(super) enum Table<const K: u8, const TABLE_NUMBER: u8>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// First table with contents of entries split into separate vectors for more efficient access
    First {
        /// Derived values computed from `x`
        ys: Vec<Y>,
        /// X values
        xs: Vec<X>,
    },
    /// Other tables
    Other {
        /// Derived values computed from previous table
        ys: Vec<Y>,
        /// Left and right entry positions in a previous table encoded into bits
        positions: Vec<[Position; 2]>,
        /// Metadata corresponding to each entry
        metadatas: Vec<Metadata<K, TABLE_NUMBER>>,
    },
}

impl<const K: u8> Table<K, 1>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
{
    /// Create the table
    pub(super) fn create(seed: Seed) -> Self
    where
        EvaluatableUsize<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>: Sized,
    {
        let partial_ys = partial_ys::<K>(seed);

        let mut t_1 = Vec::with_capacity(1_usize << K);
        for (x_start, partial_ys) in X::all::<K>().step_by(COMPUTE_F1_SIMD_FACTOR).zip(
            partial_ys
                .array_chunks::<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>()
                .copied(),
        ) {
            let xs: [_; COMPUTE_F1_SIMD_FACTOR] = seq!(N in 0..8 {
                [
                #(
                #[allow(clippy::erasing_op, clippy::identity_op)]
                {
                    x_start + X::from(N)
                },
                )*
                ]
            });

            let ys = compute_f1_simd::<K>(xs, &partial_ys);
            t_1.extend(ys.into_iter().zip(xs));
        }

        t_1.sort_unstable();

        let (ys, xs) = t_1.into_iter().unzip();

        Self::First { ys, xs }
    }

    /// Create the table, leverages available parallelism
    #[cfg(any(feature = "parallel", test))]
    pub(super) fn create_parallel(seed: Seed) -> Self
    where
        EvaluatableUsize<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>: Sized,
    {
        let partial_ys = partial_ys::<K>(seed);

        let mut t_1 = Vec::with_capacity(1_usize << K);
        for (x_start, partial_ys) in X::all::<K>().step_by(COMPUTE_F1_SIMD_FACTOR).zip(
            partial_ys
                .array_chunks::<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>()
                .copied(),
        ) {
            let xs: [_; COMPUTE_F1_SIMD_FACTOR] = seq!(N in 0..8 {
                [
                #(
                #[allow(clippy::erasing_op, clippy::identity_op)]
                {
                    x_start + X::from(N)
                },
                )*
                ]
            });

            let ys = compute_f1_simd::<K>(xs, &partial_ys);
            t_1.extend(ys.into_iter().zip(xs));
        }

        t_1.par_sort_unstable();

        let (ys, xs) = t_1.into_iter().unzip();

        Self::First { ys, xs }
    }

    /// All `x`s as [`BitSlice`], for individual `x`s needs to be slices into [`K`] bits slices
    pub(super) fn xs(&self) -> &[X] {
        match self {
            Table::First { xs, .. } => xs,
            _ => {
                unreachable!()
            }
        }
    }
}

mod private {
    pub(in super::super) trait SupportedOtherTables {}
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 2> where
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 3> where
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 4> where
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 5> where
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 6> where
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 7> where
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized
{
}

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: private::SupportedOtherTables,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// Creates new [`TABLE_NUMBER`] table. There also exists [`Self::create_parallel()`] that
    /// trades CPU efficiency and memory usage for lower latency.
    pub(super) fn create<const PARENT_TABLE_NUMBER: u8>(
        last_table: &Table<K, PARENT_TABLE_NUMBER>,
        cache: &mut TablesCache<K>,
    ) -> Self
    where
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        let buckets = &mut cache.buckets;
        let rmap_scratch = &mut cache.rmap_scratch;
        let left_targets = &cache.left_targets;

        let mut bucket = Bucket {
            bucket_index: 0,
            start_position: Position::ZERO,
            size: Position::ZERO,
        };

        let last_y = *last_table
            .ys()
            .last()
            .expect("List of y values is never empty; qed");
        buckets.clear();
        buckets.reserve(1 + usize::from(last_y) / usize::from(PARAM_BC));
        last_table
            .ys()
            .iter()
            .zip(Position::ZERO..)
            .for_each(|(&y, position)| {
                let bucket_index = u32::from(y) / u32::from(PARAM_BC);

                if bucket_index == bucket.bucket_index {
                    bucket.size += Position::ONE;
                    return;
                }

                buckets.push(bucket);

                bucket = Bucket {
                    bucket_index,
                    start_position: position,
                    size: Position::ONE,
                };
            });
        // Iteration stopped, but we did not store the last bucket yet
        buckets.push(bucket);

        let num_values = 1 << K;
        let mut t_n = Vec::with_capacity(num_values);
        buckets
            .array_windows::<2>()
            .for_each(|&[left_bucket, right_bucket]| {
                match_and_compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                    last_table,
                    left_bucket,
                    right_bucket,
                    rmap_scratch,
                    left_targets,
                    &mut t_n,
                );
            });

        t_n.sort_unstable();

        let mut ys = Vec::with_capacity(t_n.len());
        let mut positions = Vec::with_capacity(t_n.len());
        let mut metadatas = Vec::with_capacity(t_n.len());

        for (y, [left_position, right_position], metadata) in t_n {
            ys.push(y);
            positions.push([left_position, right_position]);
            // Last table doesn't have metadata
            if metadata_size_bits(K, TABLE_NUMBER) > 0 {
                metadatas.push(metadata);
            }
        }

        Self::Other {
            ys,
            positions,
            metadatas,
        }
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// performance (though not efficiency of CPU and memory usage), if you create multiple tables
    /// in parallel, prefer [`Self::create()`] for better overall performance.
    // TODO: Cache more allocations in this function to improve performance further
    #[cfg(any(feature = "parallel", test))]
    pub(super) fn create_parallel<const PARENT_TABLE_NUMBER: u8>(
        last_table: &Table<K, PARENT_TABLE_NUMBER>,
        cache: &mut TablesCache<K>,
    ) -> Self
    where
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        let buckets = &mut cache.buckets;
        let left_targets = &cache.left_targets;

        let mut bucket = Bucket {
            bucket_index: 0,
            start_position: Position::ZERO,
            size: Position::ZERO,
        };

        let last_y = *last_table
            .ys()
            .last()
            .expect("List of y values is never empty; qed");
        buckets.clear();
        buckets.reserve(1 + usize::from(last_y) / usize::from(PARAM_BC));
        last_table
            .ys()
            .iter()
            .zip(Position::ZERO..)
            .for_each(|(&y, position)| {
                let bucket_index = u32::from(y) / u32::from(PARAM_BC);

                if bucket_index == bucket.bucket_index {
                    bucket.size += Position::ONE;
                    return;
                }

                buckets.push(bucket);

                bucket = Bucket {
                    bucket_index,
                    start_position: position,
                    size: Position::ONE,
                };
            });
        // Iteration stopped, but we did not store the last bucket yet
        buckets.push(bucket);

        let counter = AtomicUsize::new(0);

        let t_n = rayon::broadcast(|_ctx| {
            let mut entries = Vec::new();
            let mut rmap_scratch = Vec::new();

            loop {
                let offset = counter.fetch_add(1, Ordering::Relaxed);
                if offset >= buckets.len() - 1 {
                    break;
                }

                match_and_compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                    last_table,
                    buckets[offset],
                    buckets[offset + 1],
                    &mut rmap_scratch,
                    left_targets,
                    &mut entries,
                );
            }

            entries
        });

        let mut t_n = t_n.into_iter().flatten().collect::<Vec<_>>();
        t_n.par_sort_unstable();

        let mut ys = Vec::with_capacity(t_n.len());
        let mut positions = Vec::with_capacity(t_n.len());
        let mut metadatas = Vec::with_capacity(t_n.len());

        for (y, [left_position, right_position], metadata) in t_n.drain(..) {
            ys.push(y);
            positions.push([left_position, right_position]);
            // Last table doesn't have metadata
            if metadata_size_bits(K, TABLE_NUMBER) > 0 {
                metadatas.push(metadata);
            }
        }

        // Drop from a background thread, which typically helps with overall concurrency
        rayon::spawn(move || {
            drop(t_n);
        });

        Self::Other {
            ys,
            positions,
            metadatas,
        }
    }
}

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// All `y`s as [`BitSlice`], for individual `x`s needs to be slices into [`K`] bits slices
    pub(super) fn ys(&self) -> &[Y] {
        let (Table::First { ys, .. } | Table::Other { ys, .. }) = self;
        ys
    }

    /// Returns `None` on invalid position or first table, `Some(left_position, right_position)` in
    /// previous table on success
    pub(super) fn position(&self, position: Position) -> Option<[Position; 2]> {
        match self {
            Table::First { .. } => None,
            Table::Other { positions, .. } => positions.get(usize::from(position)).copied(),
        }
    }

    /// Returns `None` on invalid position or for table number 7
    pub(super) fn metadata(&self, position: Position) -> Option<Metadata<K, TABLE_NUMBER>> {
        match self {
            Table::First { xs, .. } => xs.get(usize::from(position)).map(|&x| Metadata::from(x)),
            Table::Other { metadatas, .. } => metadatas.get(usize::from(position)).copied(),
        }
    }
}
