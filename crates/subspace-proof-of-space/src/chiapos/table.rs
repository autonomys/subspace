#[cfg(test)]
mod tests;
pub(super) mod types;

extern crate alloc;

use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT, PARAM_M};
use crate::chiapos::table::types::{CopyBitsDestination, Metadata, Position, X, Y};
use crate::chiapos::utils::EvaluatableUsize;
use crate::chiapos::Seed;
use alloc::vec::Vec;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha8, Key, Nonce};
use core::mem;

/// Compute the size of `x` in bytes
pub const fn x_size_bytes(k: u8) -> usize {
    usize::from(k).div_ceil(u8::BITS as usize)
}

/// Compute the size of `y` in bits
pub(super) const fn y_size_bits(k: u8) -> usize {
    usize::from(k) + usize::from(PARAM_EXT)
}

/// Compute the size of `y` in bytes
pub const fn y_size_bytes(k: u8) -> usize {
    y_size_bits(k).div_ceil(u8::BITS as usize)
}

/// Metadata size in bits
pub const fn metadata_size_bits(k: u8, table_number: u8) -> usize {
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

/// Max size in bits for any table
pub(crate) const fn max_metadata_size_bits(k: u8) -> usize {
    metadata_size_bits(k, 1)
        .max(metadata_size_bits(k, 2))
        .max(metadata_size_bits(k, 3))
        .max(metadata_size_bits(k, 4))
        .max(metadata_size_bits(k, 5))
        .max(metadata_size_bits(k, 6))
        .max(metadata_size_bits(k, 7))
}

/// Metadata size in bytes rounded up
pub const fn metadata_size_bytes(k: u8, table_number: u8) -> usize {
    metadata_size_bits(k, table_number).div_ceil(u8::BITS as usize)
}

pub const fn fn_hashing_input_bytes(k: u8) -> usize {
    (y_size_bits(k) + max_metadata_size_bits(k) * 2).div_ceil(u8::BITS as usize)
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
    x: usize,
) -> ([u8; (K as usize * 2).div_ceil(u8::BITS as usize)], usize) {
    let skip_bits = usize::from(K) * x;
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
pub struct TablesCache<const K: u8>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    left_bucket: Bucket<K>,
    right_bucket: Bucket<K>,
    rmap_scratch: Vec<RmapItem>,
    left_targets: Vec<Vec<Vec<usize>>>,
}

impl<const K: u8> Default for TablesCache<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
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
pub(super) struct Match<const K: u8>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    left_index: usize,
    left_y: Y<K>,
    right_index: usize,
}

#[derive(Debug)]
struct Bucket<const K: u8>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    /// Bucket index
    bucket_index: usize,
    /// `y` values in this bucket
    ys: Vec<Y<K>>,
    /// Start position of this bucket in the table
    start_position: usize,
}

impl<const K: u8> Default for Bucket<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
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
    start_index: usize,
}

/// Y value will be in the first bits of returned byte array, `partial_y_offset` is in bits
pub(super) fn compute_f1<const K: u8>(x: X<K>, partial_y: &[u8], partial_y_offset: usize) -> Y<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    let mut y = Y::default();

    // Copy partial y value derived from ChaCha8 stream
    y.copy_bits_from(partial_y, partial_y_offset, K, 0_usize);
    // And `PARAM_EXT` most significant bits from `x`
    y.copy_bits_from(&x, 0_usize, PARAM_EXT, K);

    y
}

/// `rmap_scratch` is just an optimization to reuse allocations between calls.
///
/// For verification purposes use [`num_matches`] instead.
///
/// Returns `None` if either of buckets is empty.
fn find_matches<'a, const K: u8>(
    left_bucket_ys: &'a [Y<K>],
    right_bucket_ys: &'a [Y<K>],
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<usize>>],
) -> Option<impl Iterator<Item = Match<K>> + 'a>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    // Clear and set to correct size with zero values
    rmap_scratch.clear();
    rmap_scratch.resize_with(usize::from(PARAM_BC), RmapItem::default);
    let rmap = rmap_scratch;

    // Both left and right buckets can be empty
    let first_left_bucket_y = usize::from(left_bucket_ys.first()?);
    let first_right_bucket_y = usize::from(right_bucket_ys.first()?);
    // Since all entries in a bucket are obtained after division by `PARAM_BC`, we can compute
    // quotient more efficiently by subtracting base value rather than computing remainder of
    // division
    let base = (first_right_bucket_y / usize::from(PARAM_BC)) * usize::from(PARAM_BC);
    for (right_index, y) in right_bucket_ys.iter().enumerate() {
        let r = usize::from(y) - base;

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
            .enumerate()
            .flat_map(move |(left_index, y)| {
                let r = usize::from(y) - base;
                let left_targets = &left_targets[r];

                (0..usize::from(PARAM_M)).flat_map(move |m| {
                    let r_target = left_targets[m];
                    let rmap_item = rmap[r_target];

                    (rmap_item.start_index..)
                        .take(rmap_item.count)
                        .map(move |right_index| Match {
                            left_index,
                            left_y: *y,
                            right_index,
                        })
                })
            }),
    )
}

/// Simplified version of [`find_matches`] for verification purposes.
pub(super) fn num_matches<const K: u8>(left_y: &Y<K>, right_y: &Y<K>) -> usize
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
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
    y: Y<K>,
    left_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
    right_metadata: Metadata<K, PARENT_TABLE_NUMBER>,
) -> (Y<K>, Metadata<K, TABLE_NUMBER>)
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized,
{
    let hash = {
        let mut input = [0; fn_hashing_input_bytes(K)];

        input.copy_bits_from(&y, 0_usize, y_size_bits(K), 0_usize);
        input.copy_bits_from(
            &left_metadata,
            0_usize,
            metadata_size_bits(K, PARENT_TABLE_NUMBER),
            y_size_bits(K),
        );
        input.copy_bits_from(
            &right_metadata,
            0_usize,
            metadata_size_bits(K, PARENT_TABLE_NUMBER),
            y_size_bits(K) + metadata_size_bits(K, PARENT_TABLE_NUMBER),
        );

        // Take only bytes where bits were set
        let num_bytes_with_data = (y_size_bits(K) + metadata_size_bits(K, PARENT_TABLE_NUMBER) * 2)
            .div_ceil(u8::BITS as usize);
        blake3::hash(&input[..num_bytes_with_data])
    };
    let mut y_output = Y::default();
    y_output.copy_bits_from(hash.as_bytes(), 0_usize, y_size_bits(K), 0_usize);

    let mut metadata = Metadata::default();

    if TABLE_NUMBER < 4 {
        metadata.copy_bits_from(
            &left_metadata,
            0_usize,
            metadata_size_bits(K, PARENT_TABLE_NUMBER),
            0_usize,
        );
        metadata.copy_bits_from(
            &right_metadata,
            0_usize,
            metadata_size_bits(K, PARENT_TABLE_NUMBER),
            metadata_size_bits(K, PARENT_TABLE_NUMBER),
        );
    } else if metadata_size_bits(K, TABLE_NUMBER) > 0 {
        metadata.copy_bits_from(
            hash.as_bytes(),
            y_size_bits(K),
            metadata_size_bits(K, TABLE_NUMBER),
            0_usize,
        );
    }

    (y_output, metadata)
}

fn match_and_compute_fn<'a, const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    last_table: &'a Table<K, PARENT_TABLE_NUMBER>,
    left_bucket: &'a Bucket<K>,
    right_bucket: &'a Bucket<K>,
    rmap_scratch: &'a mut Vec<RmapItem>,
    left_targets: &'a [Vec<Vec<usize>>],
) -> impl Iterator<Item = (Y<K>, Metadata<K, TABLE_NUMBER>, [Position<K>; 2])> + 'a
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized,
{
    let maybe_matches = find_matches::<K>(
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
            (
                y,
                metadata,
                [
                    Position::from(left_position),
                    Position::from(right_position),
                ],
            )
        })
    })
}

#[derive(Debug)]
pub(super) enum Table<const K: u8, const TABLE_NUMBER: u8>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// First table with contents of entries split into separate vectors for more efficient access
    First {
        /// Derived values computed from `x`
        ys: Vec<Y<K>>,
        /// X values
        xs: Vec<X<K>>,
    },
    /// Other tables
    Other {
        /// Derived values computed from previous table
        ys: Vec<Y<K>>,
        /// Left and right entry positions in a previous table encoded into bits
        positions: Vec<[Position<K>; 2]>,
        /// Metadata corresponding to each entry
        metadatas: Vec<Metadata<K, TABLE_NUMBER>>,
    },
}

impl<const K: u8> Table<K, 1>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
{
    /// Create the table
    pub(super) fn create(seed: Seed) -> Self {
        let partial_ys = partial_ys::<K>(seed);

        let mut t_1 = (0..1 << K)
            .map(|x| {
                let partial_y_offset = x * usize::from(K);
                let x = X::from(x);
                let y = compute_f1::<K>(x, &partial_ys, partial_y_offset);

                (y, x)
            })
            .collect::<Vec<_>>();

        t_1.sort_unstable_by_key(|(y, ..)| *y);

        let (ys, xs) = t_1.into_iter().unzip();

        Self::First { ys, xs }
    }

    /// All `x`s as [`BitSlice`], for individual `x`s needs to be slices into [`K`] bits slices
    pub(super) fn xs(&self) -> &[X<K>] {
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

impl<const K: u8> private::SupportedOtherTables for Table<K, 2>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 3>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 4>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 5>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 6>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
{
}

impl<const K: u8> private::SupportedOtherTables for Table<K, 7>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
{
}

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    Self: private::SupportedOtherTables,
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized,
{
    pub(super) fn create<const PARENT_TABLE_NUMBER: u8>(
        last_table: &Table<K, PARENT_TABLE_NUMBER>,
        cache: &mut TablesCache<K>,
    ) -> Self
    where
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
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
        // TODO: Parallelize something here?
        // TODO: [unstable] `group_by` can be used here:
        //  https://doc.rust-lang.org/std/primitive.slice.html#method.group_by
        for (position, &y) in last_table.ys().iter().enumerate() {
            let bucket_index = usize::from(&y) / usize::from(PARAM_BC);

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

            t_n.extend(match_and_compute_fn(
                last_table,
                left_bucket,
                right_bucket,
                rmap_scratch,
                left_targets,
            ));

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
        t_n.extend(match_and_compute_fn(
            last_table,
            left_bucket,
            right_bucket,
            rmap_scratch,
            left_targets,
        ));

        t_n.sort_unstable_by_key(|(y, ..)| *y);

        let mut ys = Vec::with_capacity(num_values);
        let mut positions = Vec::with_capacity(num_values);
        let mut metadatas = Vec::with_capacity(num_values);

        for (y, metadata, [left_position, right_position]) in t_n {
            ys.push(y);
            positions.push([left_position, right_position]);
            if TABLE_NUMBER != 7 {
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

impl<const K: u8, const TABLE_NUMBER: u8> Table<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// All `y`s as [`BitSlice`], for individual `x`s needs to be slices into [`K`] bits slices
    pub(super) fn ys(&self) -> &[Y<K>] {
        let (Table::First { ys, .. } | Table::Other { ys, .. }) = self;
        ys
    }

    /// Returns `None` on invalid position or first table, `Some(left_position, right_position)` in
    /// previous table on success
    pub(super) fn position(&self, position: Position<K>) -> Option<[Position<K>; 2]> {
        match self {
            Table::First { .. } => None,
            Table::Other { positions, .. } => positions.get(usize::from(position)).copied(),
        }
    }

    /// Returns `None` on invalid position or for table number 7
    pub(super) fn metadata(&self, position: usize) -> Option<Metadata<K, TABLE_NUMBER>> {
        match self {
            Table::First { xs, .. } => {
                // This is a bit awkward since we store `K` bits in each `x`, but we also
                // technically have `metadata_size_bits` function that is supposed to point to the
                // number of bytes metadata has for table 1. They are the same and trying to slice
                // it will cause overhead. Use assertion here instead that will be removed by
                // compiler and not incurring any overhead.
                assert_eq!(metadata_size_bits(K, TABLE_NUMBER), usize::from(K));

                xs.get(position).map(|x| {
                    let mut metadata = Metadata::default();
                    metadata.copy_bits_from(x, 0_usize, K, 0_usize);
                    metadata
                })
            }
            Table::Other { metadatas, .. } => metadatas.get(position).copied(),
        }
    }
}
