#[cfg(test)]
mod tests;
pub(super) mod types;

extern crate alloc;

use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT, PARAM_M};
use crate::chiapos::table::types::{Metadata, Position, X, Y};
use crate::chiapos::Seed;
use alloc::vec;
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha8, Key, Nonce};
use core::mem;
#[cfg(any(feature = "parallel", test))]
use rayon::prelude::*;

/// Compute the size of `y` in bits
pub(super) const fn y_size_bits(k: u8) -> usize {
    k as usize + PARAM_EXT as usize
}

/// Metadata size in bits
pub const fn metadata_size_bits(k: u8, table_number: u8) -> usize {
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
    let skip_bits = usize::from(K) * x as usize;
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

fn calculate_left_targets() -> Vec<Vec<Vec<usize>>> {
    let param_b = usize::from(PARAM_B);
    let param_c = usize::from(PARAM_C);

    (0..=1usize)
        .map(|parity| {
            (0..usize::from(PARAM_BC))
                .map(|r| {
                    let c = r / param_c;

                    (0..usize::from(PARAM_M))
                        .map(|m| {
                            ((c + m) % param_b) * param_c
                                + (((2 * m + parity) * (2 * m + parity) + r) % param_c)
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
#[derive(Debug)]
pub struct TablesCache<const K: u8> {
    left_bucket: Bucket,
    right_bucket: Bucket,
    rmap_scratch: Vec<RmapItem>,
    left_targets: Vec<Vec<Vec<usize>>>,
}

impl<const K: u8> Default for TablesCache<K> {
    /// Create new instance
    fn default() -> Self {
        // Pair of buckets that are a sliding window of 2 buckets across the whole table
        let left_bucket = Bucket::default();
        let right_bucket = Bucket::default();

        let left_targets = calculate_left_targets();
        // TODO: This is the capacity chiapos allocates it with, check if it is correct
        let rmap_scratch = Vec::with_capacity(usize::from(PARAM_BC));

        Self {
            left_bucket,
            right_bucket,
            rmap_scratch,
            left_targets,
        }
    }
}

#[derive(Debug)]
pub(super) struct Match {
    left_index: Position,
    left_y: Y,
    right_index: Position,
}

#[derive(Debug, Clone)]
struct Bucket {
    /// Bucket index
    bucket_index: usize,
    /// `y` values in this bucket
    ys: Vec<Y>,
    /// Start position of this bucket in the table
    start_position: Position,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            bucket_index: 0,
            // TODO: Currently twice the average size (*2), re-consider size in the future if it is
            //  typically exceeded
            ys: Vec::with_capacity(usize::from(PARAM_BC) / (1 << PARAM_EXT) * 2),
            start_position: 0,
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub(super) struct RmapItem {
    count: usize,
    start_index: Position,
}

/// `partial_y_offset` is in bits
pub(super) fn compute_f1<const K: u8>(x: u32, partial_y: &[u8], partial_y_offset: usize) -> u32 {
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
    // eventual `y` with the rest of bits set to `0` with the rest of bits being in undefined state.
    let pre_ext = x >> (usize::from(K) - usize::from(PARAM_EXT));
    // Mask for clearing the rest of bits of `pre_ext`.
    let pre_ext_mask = u32::MAX >> (u32::BITS as usize - usize::from(PARAM_EXT));

    // Combine all of the bits together:
    // [padding zero bits][`K` bits rom `partial_y`][`PARAM_EXT` bits from `x`]
    (pre_y & pre_y_mask) | (pre_ext & pre_ext_mask)
}

/// `rmap_scratch` is just an optimization to reuse allocations between calls.
///
/// For verification purposes use [`num_matches`] instead.
///
/// Returns `None` if either of buckets is empty.
fn find_matches<'a>(
    left_bucket_ys: &'a [Y],
    right_bucket_ys: &'a [Y],
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<usize>>],
) -> Option<impl Iterator<Item = Match> + 'a> {
    // Clear and set to correct size with zero values
    rmap_scratch.clear();
    rmap_scratch.resize_with(usize::from(PARAM_BC), RmapItem::default);
    let rmap = rmap_scratch;

    // Both left and right buckets can be empty
    let first_left_bucket_y = *left_bucket_ys.first()? as usize;
    let first_right_bucket_y = *right_bucket_ys.first()? as usize;
    // Since all entries in a bucket are obtained after division by `PARAM_BC`, we can compute
    // quotient more efficiently by subtracting base value rather than computing remainder of
    // division
    let base = (first_right_bucket_y / usize::from(PARAM_BC)) * usize::from(PARAM_BC);
    for (&y, right_index) in right_bucket_ys.iter().zip(0u32..) {
        let r = y as usize - base;

        // Same `y` and as the result `r` can appear in the table multiple times, in which case
        // they'll all occupy consecutive slots in `right_bucket` and all we need to store is just
        // the first position and number of elements.
        if rmap[r].count == 0 {
            rmap[r].start_index = right_index;
        }
        rmap[r].count += 1;
    }
    let rmap = rmap.as_slice();

    // Same idea as above, but avoids division by leveraging the fact that each bucket is exactly
    // `PARAM_BC` away from the previous one in terms of divisor by `PARAM_BC`
    let base = base - usize::from(PARAM_BC);
    let parity = (first_left_bucket_y / usize::from(PARAM_BC)) % 2;
    let left_targets = &left_targets[parity];

    Some(
        left_bucket_ys
            .iter()
            .zip(0u32..)
            .flat_map(move |(&y, left_index)| {
                let r = y as usize - base;
                let left_targets = &left_targets[r];

                (0..usize::from(PARAM_M)).flat_map(move |m| {
                    let r_target = left_targets[m];
                    let rmap_item = rmap[r_target];

                    (rmap_item.start_index..)
                        .take(rmap_item.count)
                        .map(move |right_index| Match {
                            left_index,
                            left_y: y,
                            right_index,
                        })
                })
            }),
    )
}

/// Simplified version of [`find_matches`] for verification purposes.
pub(super) fn num_matches(left_y: Y, right_y: Y) -> usize {
    let right_r = right_y as usize % usize::from(PARAM_BC);
    let parity = (left_y as usize / usize::from(PARAM_BC)) % 2;
    let left_r = left_y as usize % usize::from(PARAM_BC);

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
    left_metadata: Metadata,
    right_metadata: Metadata,
) -> (Y, Metadata) {
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
            let mut hasher = blake3::Hasher::new();

            hasher.update(&input_a.to_be_bytes());
            hasher.update(
                &input_b.to_be_bytes()
                    [..right_bits_pushed_into_input_b.div_ceil(u8::BITS as usize)],
            );
            hasher.finalize()
        } else {
            let right_bits_a = right_metadata << (right_bits_start_offset - y_and_left_bits);
            let input_a = y_bits | left_metadata_bits | right_bits_a;

            blake3::hash(&input_a.to_be_bytes()[..num_bytes_with_data])
        }
    };

    let y_output = u32::from_be_bytes(
        hash.as_bytes()[..mem::size_of::<u32>()]
            .try_into()
            .expect("Hash if statically guaranteed to have enough bytes; qed"),
    ) >> (u32::BITS as usize - y_size_bits(K));

    let metadata_size_bits = metadata_size_bits(K, TABLE_NUMBER);

    let metadata = if TABLE_NUMBER < 4 {
        (left_metadata << parent_metadata_bits) | right_metadata
    } else if metadata_size_bits > 0 {
        // For K under 25 it is guaranteed that metadata + bit offset will always fit into u128.
        // We collect bytes necessary, potentially with extra bits at the start and end of the bytes
        // that will be taken care of later.
        let metadata = u128::from_be_bytes(
            hash.as_bytes()[y_size_bits(K) / u8::BITS as usize..][..mem::size_of::<u128>()]
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

    (y_output, metadata)
}

fn match_and_compute_fn<'a, const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    last_table: &'a Table<K, PARENT_TABLE_NUMBER>,
    left_bucket: &'a Bucket,
    right_bucket: &'a Bucket,
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<usize>>],
) -> impl Iterator<Item = (Y, Metadata, [Position; 2])> + 'a {
    let maybe_matches = find_matches(
        &left_bucket.ys,
        &right_bucket.ys,
        rmap_scratch,
        left_targets,
    );

    maybe_matches.into_iter().flat_map(|matches| {
        matches.map(|m| {
            let left_position = left_bucket.start_position + m.left_index;
            let right_position = right_bucket.start_position + m.right_index;
            let left_metadata = last_table
                .metadata(left_position)
                .expect("Position resulted from matching is correct; qed");
            let right_metadata = last_table
                .metadata(right_position)
                .expect("Position resulted from matching is correct; qed");

            let (y, metadata) = compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                m.left_y,
                left_metadata,
                right_metadata,
            );
            (y, metadata, [left_position, right_position])
        })
    })
}

#[derive(Debug)]
pub(super) enum Table<const K: u8, const TABLE_NUMBER: u8> {
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
        metadatas: Vec<Metadata>,
    },
}

impl<const K: u8> Table<K, 1> {
    /// Create the table
    pub(super) fn create(seed: Seed) -> Self {
        let partial_ys = partial_ys::<K>(seed);

        let mut t_1 = (0..1u32 << K)
            .map(|x| {
                let partial_y_offset = x as usize * usize::from(K);
                let y = compute_f1::<K>(x, &partial_ys, partial_y_offset);

                (y, x)
            })
            .collect::<Vec<_>>();

        t_1.sort_unstable();

        let (ys, xs) = t_1.into_iter().unzip();

        Self::First { ys, xs }
    }

    /// Create the table, leverages available parallelism
    #[cfg(any(feature = "parallel", test))]
    pub(super) fn create_parallel(seed: Seed) -> Self {
        let partial_ys = partial_ys::<K>(seed);

        let mut t_1 = (0..1u32 << K)
            .map(|x| {
                let partial_y_offset = x as usize * usize::from(K);
                let y = compute_f1::<K>(x, &partial_ys, partial_y_offset);

                (y, x)
            })
            .collect::<Vec<_>>();

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

impl<const K: u8> private::SupportedOtherTables for Table<K, 2> {}

impl<const K: u8> private::SupportedOtherTables for Table<K, 3> {}

impl<const K: u8> private::SupportedOtherTables for Table<K, 4> {}

impl<const K: u8> private::SupportedOtherTables for Table<K, 5> {}

impl<const K: u8> private::SupportedOtherTables for Table<K, 6> {}

impl<const K: u8> private::SupportedOtherTables for Table<K, 7> {}

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: private::SupportedOtherTables,
{
    /// Creates new [`TABLE_NUMBER`] table. There also exists [`Self::create_parallel()`] that
    /// trades CPU efficiency and memory usage for lower latency.
    pub(super) fn create<const PARENT_TABLE_NUMBER: u8>(
        last_table: &Table<K, PARENT_TABLE_NUMBER>,
        cache: &mut TablesCache<K>,
    ) -> Self {
        let left_bucket = &mut cache.left_bucket;
        let right_bucket = &mut cache.right_bucket;
        let rmap_scratch = &mut cache.rmap_scratch;
        let left_targets = &cache.left_targets;

        // Clear input variables just in case
        left_bucket.bucket_index = 0;
        left_bucket.ys.clear();
        left_bucket.start_position = 0;
        right_bucket.bucket_index = 1;
        right_bucket.ys.clear();
        right_bucket.start_position = 0;

        let num_values = 1 << K;
        let mut t_n = Vec::with_capacity(num_values);
        for (&y, position) in last_table.ys().iter().zip(0u32..) {
            let bucket_index = y as usize / usize::from(PARAM_BC);

            if bucket_index == left_bucket.bucket_index {
                left_bucket.ys.push(y);
                continue;
            } else if bucket_index == right_bucket.bucket_index {
                if right_bucket.ys.is_empty() {
                    right_bucket.start_position = position;
                }
                right_bucket.ys.push(y);
                continue;
            }

            t_n.extend(
                match_and_compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                    last_table,
                    left_bucket,
                    right_bucket,
                    rmap_scratch,
                    left_targets,
                ),
            );

            if bucket_index == right_bucket.bucket_index + 1 {
                // Move right bucket into left bucket while reusing existing allocations
                mem::swap(left_bucket, right_bucket);
                right_bucket.bucket_index = bucket_index;
                right_bucket.ys.clear();
                right_bucket.start_position = position;

                right_bucket.ys.push(y);
            } else {
                // We have skipped some buckets, clean up both left and right buckets
                left_bucket.bucket_index = bucket_index;
                left_bucket.ys.clear();
                left_bucket.start_position = position;

                left_bucket.ys.push(y);

                right_bucket.bucket_index = bucket_index + 1;
                right_bucket.ys.clear();
            }
        }
        // Iteration stopped, but we did not process contents of the last pair of buckets yet
        t_n.extend(
            match_and_compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                last_table,
                left_bucket,
                right_bucket,
                rmap_scratch,
                left_targets,
            ),
        );

        t_n.sort_unstable();

        let mut ys = Vec::with_capacity(num_values);
        let mut positions = Vec::with_capacity(num_values);
        let mut metadatas = Vec::with_capacity(num_values);

        for (y, metadata, [left_position, right_position]) in t_n {
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
    #[cfg(any(feature = "parallel", test))]
    pub(super) fn create_parallel<const PARENT_TABLE_NUMBER: u8>(
        last_table: &Table<K, PARENT_TABLE_NUMBER>,
        cache: &mut TablesCache<K>,
    ) -> Self {
        let left_bucket = &mut cache.left_bucket;
        let right_bucket = &mut cache.right_bucket;
        let left_targets = &cache.left_targets;

        // Clear input variables just in case
        left_bucket.bucket_index = 0;
        left_bucket.ys.clear();
        left_bucket.start_position = 0;
        right_bucket.bucket_index = 1;
        right_bucket.ys.clear();
        right_bucket.start_position = 0;

        // Experimentally found that this value seems reasonable
        let mut buckets = Vec::with_capacity(usize::from(PARAM_BC) / (1 << PARAM_EXT) * 3);
        for (&y, position) in last_table.ys().iter().zip(0u32..) {
            let bucket_index = y as usize / usize::from(PARAM_BC);

            if bucket_index == left_bucket.bucket_index {
                left_bucket.ys.push(y);
                continue;
            } else if bucket_index == right_bucket.bucket_index {
                if right_bucket.ys.is_empty() {
                    right_bucket.start_position = position;
                }
                right_bucket.ys.push(y);
                continue;
            }

            buckets.push(left_bucket.clone());

            if bucket_index == right_bucket.bucket_index + 1 {
                // Move right bucket into left bucket while reusing existing allocations
                mem::swap(left_bucket, right_bucket);
                right_bucket.bucket_index = bucket_index;
                right_bucket.ys.clear();
                right_bucket.start_position = position;

                right_bucket.ys.push(y);
            } else {
                // We have skipped some buckets, clean up both left and right buckets
                left_bucket.bucket_index = bucket_index;
                left_bucket.ys.clear();
                left_bucket.start_position = position;

                left_bucket.ys.push(y);

                right_bucket.bucket_index = bucket_index + 1;
                right_bucket.ys.clear();
            }
        }
        // Iteration stopped, but we did not store the last two buckets yet
        buckets.push(left_bucket.clone());
        buckets.push(right_bucket.clone());

        let num_values = 1 << K;
        let mut t_n = Vec::with_capacity(num_values);
        t_n.par_extend(buckets.par_windows(2).flat_map_iter(|buckets| {
            match_and_compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
                last_table,
                &buckets[0],
                &buckets[1],
                &mut Vec::new(),
                left_targets,
            )
            .collect::<Vec<_>>()
        }));

        // Drop in thread pool to return faster from here
        rayon::spawn(move || {
            drop(buckets);
        });

        t_n.par_sort_unstable();

        let mut ys = Vec::with_capacity(num_values);
        let mut positions = Vec::with_capacity(num_values);
        let mut metadatas = Vec::with_capacity(num_values);

        for (y, metadata, [left_position, right_position]) in t_n {
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
}

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER> {
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
            Table::Other { positions, .. } => positions.get(position as usize).copied(),
        }
    }

    /// Returns `None` on invalid position or for table number 7
    pub(super) fn metadata(&self, position: Position) -> Option<Metadata> {
        match self {
            Table::First { xs, .. } => xs.get(position as usize).map(|&x| u128::from(x)),
            Table::Other { metadatas, .. } => metadatas.get(position as usize).copied(),
        }
    }
}
