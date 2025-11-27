#[cfg(test)]
mod tests;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub use crate::chiapos::table::TablesCache;
use crate::chiapos::table::types::{Metadata, Position, X, Y};
use crate::chiapos::table::{
    COMPUTE_F1_SIMD_FACTOR, Table, compute_f1, compute_fn, has_match, metadata_size_bytes,
    partial_y,
};
use crate::chiapos::utils::EvaluatableUsize;
use crate::chiapos::{Challenge, Quality, Seed};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::mem;
use sha2::{Digest, Sha256};

/// Pick position in `table_number` based on challenge bits
const fn pick_position(
    [left_position, right_position]: [Position; 2],
    last_5_challenge_bits: u8,
    table_number: u8,
) -> Position {
    if ((last_5_challenge_bits >> (table_number - 2)) & 1) == 0 {
        left_position
    } else {
        right_position
    }
}

/// Collection of Chia tables
#[derive(Debug)]
pub(super) struct TablesGeneric<const K: u8>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
{
    table_1: Table<K, 1>,
    table_2: Table<K, 2>,
    table_3: Table<K, 3>,
    table_4: Table<K, 4>,
    table_5: Table<K, 5>,
    table_6: Table<K, 6>,
    table_7: Table<K, 7>,
}

impl<const K: u8> TablesGeneric<K>
where
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    EvaluatableUsize<{ K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize }>: Sized,
    EvaluatableUsize<{ 64 * K as usize / 8 }>: Sized,
{
    /// Create Chia proof of space tables. There also exists [`Self::create_parallel()`] that trades
    /// CPU efficiency and memory usage for lower latency.
    pub(super) fn create(seed: Seed, cache: &mut TablesCache<K>) -> Self {
        let table_1 = Table::<K, 1>::create(seed);
        let table_2 = Table::<K, 2>::create(&table_1, cache);
        let table_3 = Table::<K, 3>::create(&table_2, cache);
        let table_4 = Table::<K, 4>::create(&table_3, cache);
        let table_5 = Table::<K, 5>::create(&table_4, cache);
        let table_6 = Table::<K, 6>::create(&table_5, cache);
        let table_7 = Table::<K, 7>::create(&table_6, cache);

        Self {
            table_1,
            table_2,
            table_3,
            table_4,
            table_5,
            table_6,
            table_7,
        }
    }

    /// Almost the same as [`Self::create()`], but uses parallelism internally for better
    /// performance (though not efficiency of CPU and memory usage), if you create multiple tables
    /// in parallel, prefer [`Self::create()`] for better overall performance.
    #[cfg(any(feature = "parallel", test))]
    pub(super) fn create_parallel(seed: Seed, cache: &mut TablesCache<K>) -> Self {
        let table_1 = Table::<K, 1>::create_parallel(seed);
        let table_2 = Table::<K, 2>::create_parallel(&table_1, cache);
        let table_3 = Table::<K, 3>::create_parallel(&table_2, cache);
        let table_4 = Table::<K, 4>::create_parallel(&table_3, cache);
        let table_5 = Table::<K, 5>::create_parallel(&table_4, cache);
        let table_6 = Table::<K, 6>::create_parallel(&table_5, cache);
        let table_7 = Table::<K, 7>::create_parallel(&table_6, cache);

        Self {
            table_1,
            table_2,
            table_3,
            table_4,
            table_5,
            table_6,
            table_7,
        }
    }

    /// Find proof of space quality for given challenge.
    pub(super) fn find_quality<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = Quality> + 'a {
        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;

        let ys = self.table_7.ys();
        // We take advantage of the fact that entries are sorted by `y` (as big-endian numbers) to
        // quickly seek to desired offset
        let first_k_challenge_bits = u32::from_be_bytes(
            challenge[..mem::size_of::<u32>()]
                .try_into()
                .expect("Challenge is known to statically have enough bytes; qed"),
        ) >> (u32::BITS as usize - usize::from(K));
        let mut first_matching_element = ys
            .binary_search_by(|&y| y.first_k_bits::<K>().cmp(&first_k_challenge_bits))
            .unwrap_or_else(|insert| insert);

        // We only compare first K bits above, which is why `binary_search_by` is not guaranteed to
        // find the very first match in case there are multiple
        for index in (0..first_matching_element).rev() {
            if ys[index].first_k_bits::<K>() == first_k_challenge_bits {
                first_matching_element = index;
            } else {
                break;
            }
        }

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        ys[first_matching_element..]
            .iter()
            .take_while(move |&&y| {
                // Check if first K bits of `y` match
                y.first_k_bits::<K>() == first_k_challenge_bits
            })
            .zip(Position::from(first_matching_element as u32)..)
            .map(move |(_y, position)| {
                let positions = self
                    .table_7
                    .position(position)
                    .expect("Internally generated pointers must be correct; qed");
                let positions = self
                    .table_6
                    .position(pick_position(positions, last_5_challenge_bits, 6))
                    .expect("Internally generated pointers must be correct; qed");
                let positions = self
                    .table_5
                    .position(pick_position(positions, last_5_challenge_bits, 5))
                    .expect("Internally generated pointers must be correct; qed");
                let positions = self
                    .table_4
                    .position(pick_position(positions, last_5_challenge_bits, 4))
                    .expect("Internally generated pointers must be correct; qed");
                let positions = self
                    .table_3
                    .position(pick_position(positions, last_5_challenge_bits, 3))
                    .expect("Internally generated pointers must be correct; qed");
                let [left_position, right_position] = self
                    .table_2
                    .position(pick_position(positions, last_5_challenge_bits, 2))
                    .expect("Internally generated pointers must be correct; qed");

                let left_x = *self
                    .table_1
                    .xs()
                    .get(usize::from(left_position))
                    .expect("Internally generated pointers must be correct; qed");
                let right_x = *self
                    .table_1
                    .xs()
                    .get(usize::from(right_position))
                    .expect("Internally generated pointers must be correct; qed");

                let mut hasher = Sha256::new();
                hasher.update(challenge);
                let left_right_xs = (u64::from(left_x) << (u64::BITS as usize - usize::from(K)))
                    | (u64::from(right_x) << (u64::BITS as usize - usize::from(K * 2)));
                hasher.update(
                    &left_right_xs.to_be_bytes()[..(K as usize * 2).div_ceil(u8::BITS as usize)],
                );
                hasher.finalize().into()
            })
    }

    /// Find proof of space for given challenge.
    pub(super) fn find_proof<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = [u8; 64 * K as usize / 8]> + 'a {
        let ys = self.table_7.ys();
        // We take advantage of the fact that entries are sorted by `y` (as big-endian numbers) to
        // quickly seek to desired offset
        let first_k_challenge_bits = u32::from_be_bytes(
            challenge[..mem::size_of::<u32>()]
                .try_into()
                .expect("Challenge is known to statically have enough bytes; qed"),
        ) >> (u32::BITS as usize - usize::from(K));
        let mut first_matching_element = ys
            .binary_search_by(|&y| y.first_k_bits::<K>().cmp(&first_k_challenge_bits))
            .unwrap_or_else(|insert| insert);

        // We only compare first K bits above, which is why `binary_search_by` is not guaranteed to
        // find the very first match in case there are multiple
        for index in (0..first_matching_element).rev() {
            if ys[index].first_k_bits::<K>() == first_k_challenge_bits {
                first_matching_element = index;
            } else {
                break;
            }
        }

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        ys[first_matching_element..]
            .iter()
            .take_while(move |&&y| {
                // Check if first K bits of `y` match
                y.first_k_bits::<K>() == first_k_challenge_bits
            })
            .zip(Position::from(first_matching_element as u32)..)
            .map(move |(_y, position)| {
                let mut proof = [0u8; 64 * K as usize / 8];

                self.table_7
                    .position(position)
                    .expect("Internally generated pointers must be correct; qed")
                    .into_iter()
                    .flat_map(|position| {
                        self.table_6
                            .position(position)
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .flat_map(|position| {
                        self.table_5
                            .position(position)
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .flat_map(|position| {
                        self.table_4
                            .position(position)
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .flat_map(|position| {
                        self.table_3
                            .position(position)
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .flat_map(|position| {
                        self.table_2
                            .position(position)
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .map(|position| {
                        self.table_1
                            .xs()
                            .get(usize::from(position))
                            .expect("Internally generated pointers must be correct; qed")
                    })
                    .enumerate()
                    .for_each(|(offset, &x)| {
                        let x_offset_in_bits = usize::from(K) * offset;
                        // Collect bytes where bits of `x` will be written
                        let proof_bytes = &mut proof[x_offset_in_bits / u8::BITS as usize..]
                            [..(x_offset_in_bits % u8::BITS as usize + usize::from(K))
                                .div_ceil(u8::BITS as usize)];

                        // Bits of `x` already shifted to correct location as they will appear in
                        // `proof`
                        let x_shifted = u32::from(x)
                            << (u32::BITS as usize
                                - (usize::from(K) + x_offset_in_bits % u8::BITS as usize));

                        // Copy `x` bits into proof
                        x_shifted
                            .to_be_bytes()
                            .iter()
                            .zip(proof_bytes)
                            .for_each(|(from, to)| {
                                *to |= from;
                            });
                    });

                proof
            })
    }

    /// Verify proof of space for given seed and challenge.
    ///
    /// Returns quality on successful verification.
    pub(super) fn verify(
        seed: Seed,
        challenge: &Challenge,
        proof_of_space: &[u8; 64 * K as usize / 8],
    ) -> Option<Quality>
    where
        EvaluatableUsize<{ (K as usize * 2).div_ceil(u8::BITS as usize) }>: Sized,
    {
        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;
        let first_k_challenge_bits = u32::from_be_bytes(
            challenge[..mem::size_of::<u32>()]
                .try_into()
                .expect("Challenge is known to statically have enough bytes; qed"),
        ) >> (u32::BITS as usize - usize::from(K));

        let ys_and_metadata = (0..64_usize)
            .map(|offset| {
                let mut pre_x_bytes = 0u64.to_be_bytes();
                let offset_in_bits = usize::from(K) * offset;
                let bytes_to_copy = (offset_in_bits % u8::BITS as usize + usize::from(K))
                    .div_ceil(u8::BITS as usize);
                // Copy full bytes that contain bits of `x`
                pre_x_bytes[..bytes_to_copy].copy_from_slice(
                    &proof_of_space[offset_in_bits / u8::BITS as usize..][..bytes_to_copy],
                );
                // Extract `pre_x` whose last `K` bits start with `x`
                let pre_x = u64::from_be_bytes(pre_x_bytes)
                    >> (u64::BITS as usize - (usize::from(K) + offset_in_bits % u8::BITS as usize));
                // Convert to desired type and clear extra bits
                let x = X::from(pre_x as u32 & (u32::MAX >> (u32::BITS as usize - usize::from(K))));

                let (partial_y, partial_y_offset) = partial_y::<K>(seed, x);
                let y = compute_f1::<K>(x, &partial_y, partial_y_offset);

                (y, Metadata::from(x))
            })
            .collect::<Vec<_>>();

        Self::collect_ys_and_metadata::<2, 1>(&ys_and_metadata)
            .and_then(|ys_and_metadata| Self::collect_ys_and_metadata::<3, 2>(&ys_and_metadata))
            .and_then(|ys_and_metadata| Self::collect_ys_and_metadata::<4, 3>(&ys_and_metadata))
            .and_then(|ys_and_metadata| Self::collect_ys_and_metadata::<5, 4>(&ys_and_metadata))
            .and_then(|ys_and_metadata| Self::collect_ys_and_metadata::<6, 5>(&ys_and_metadata))
            .and_then(|ys_and_metadata| Self::collect_ys_and_metadata::<7, 6>(&ys_and_metadata))
            .filter(|ys_and_metadata| {
                let (y, _metadata) = ys_and_metadata
                    .first()
                    .expect("On success returns exactly one entry; qed");

                // Check if first K bits of `y` match
                y.first_k_bits::<K>() == first_k_challenge_bits
            })
            .map(|_| {
                let mut quality_index = 0_usize.to_be_bytes();
                quality_index[0] = last_5_challenge_bits;
                let quality_index = usize::from_be_bytes(quality_index);

                let mut hasher = Sha256::new();
                hasher.update(challenge);

                // NOTE: this works correctly, but may overflow if `quality_index` is changed to
                // not be zero-initialized anymore
                let left_right_xs_bit_offset = quality_index * usize::from(K * 2);
                // Collect `left_x` and `right_x` bits, potentially with extra bits at the beginning
                // and the end
                let left_right_xs_bytes =
                    &proof_of_space[left_right_xs_bit_offset / u8::BITS as usize..]
                        [..(left_right_xs_bit_offset % u8::BITS as usize + usize::from(K * 2))
                            .div_ceil(u8::BITS as usize)];

                let mut left_right_xs = 0u64.to_be_bytes();
                left_right_xs[..left_right_xs_bytes.len()].copy_from_slice(left_right_xs_bytes);
                // Move `left_x` and `right_x` bits to most significant bits
                let left_right_xs = u64::from_be_bytes(left_right_xs)
                    << (left_right_xs_bit_offset % u8::BITS as usize);
                // Clear extra bits
                let left_right_xs_mask = u64::MAX << (u64::BITS as usize - usize::from(K * 2));
                let left_right_xs = left_right_xs & left_right_xs_mask;

                hasher.update(
                    &left_right_xs.to_be_bytes()[..usize::from(K * 2).div_ceil(u8::BITS as usize)],
                );

                hasher.finalize().into()
            })
    }

    fn collect_ys_and_metadata<const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
        ys_and_metadata: &[(Y, Metadata<K, PARENT_TABLE_NUMBER>)],
    ) -> Option<Vec<(Y, Metadata<K, TABLE_NUMBER>)>>
    where
        EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        ys_and_metadata
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[(left_y, left_metadata), (right_y, right_metadata)]| {
                has_match(left_y, right_y).then_some(compute_fn::<
                    K,
                    TABLE_NUMBER,
                    PARENT_TABLE_NUMBER,
                >(
                    left_y, left_metadata, right_metadata
                ))
            })
            .collect()
    }
}
