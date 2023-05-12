#[cfg(test)]
mod tests;

use crate::chiapos::table::types::{CopyBitsDestination, Metadata, Position, X, Y};
pub use crate::chiapos::table::TablesCache;
use crate::chiapos::table::{
    compute_f1, compute_fn, fn_hashing_input_bytes, max_metadata_size_bits, metadata_size_bytes,
    num_matches, partial_y, x_size_bytes, y_size_bits, y_size_bytes, Table,
};
use crate::chiapos::utils::EvaluatableUsize;
use crate::chiapos::{Challenge, Quality, Seed};
use bitvec::prelude::*;
use core::mem;
use sha2::{Digest, Sha256};

/// Pick position in `table_number` based on challenge bits
const fn pick_position<const K: u8>(
    [left_position, right_position]: [Position<K>; 2],
    last_5_challenge_bits: u8,
    table_number: u8,
) -> Position<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    if ((last_5_challenge_bits >> (table_number - 2)) & 1) == 0 {
        left_position
    } else {
        right_position
    }
}

pub const fn quality_hashing_buffer_bytes(k: u8) -> usize {
    mem::size_of::<Challenge>() + (usize::from(k) * 2).div_ceil(u8::BITS as usize)
}

/// Collection of Chia tables
#[derive(Debug)]
pub(super) struct TablesGeneric<const K: u8>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
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
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 1) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 2) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 3) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 4) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 5) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 6) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized,
    EvaluatableUsize<{ quality_hashing_buffer_bytes(K) }>: Sized,
    EvaluatableUsize<{ 64 * K as usize / 8 }>: Sized,
{
    /// Create Chia proof of space tables.
    ///
    /// Advanced version of [`Self::create_simple`] that allows to reuse allocations using cache.
    ///
    /// ## Panics
    /// Panics when [`K`] is too large due to values not fitting into [`ValueNumberT`]. Also
    /// panics if `K` is too large for buckets to be kept in memory on current platform.
    pub(super) fn create(seed: Seed, cache: &mut TablesCache<K>) -> Self {
        let heap_size_bits = usize::MAX as u128 * u128::from(u8::BITS);
        let num_values = 1 << K;
        // Check that space for `y` values can be allocated on the heap
        assert!(num_values * y_size_bits(K) as u128 <= heap_size_bits);
        // Check that positions can be allocated on the heap
        assert!(num_values * u128::from(K) * 2 <= heap_size_bits);
        // Check that metadata can be allocated on the heap
        assert!(num_values * max_metadata_size_bits(K) as u128 * 2 <= heap_size_bits);
        // `y` must fit into `usize`
        assert!(y_size_bits(K) <= usize::BITS as usize);

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

    /// Find proof of space quality for given challenge.
    pub(super) fn find_quality<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = Quality> + 'a
    where
        EvaluatableUsize<{ mem::size_of::<Challenge>() + K as usize * 2 }>: Sized,
    {
        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;

        let ys = self.table_7.ys();
        // We take advantage of the fact that entries are sorted by `y` (as big-endian numbers) to
        // quickly seek to desired offset
        let mut first_k_challenge_bits = Y::<K>::default();
        first_k_challenge_bits.copy_bits_from(challenge, 0_usize, usize::from(K), 0_usize);
        let first_matching_element = ys
            .binary_search(&first_k_challenge_bits)
            .unwrap_or_else(|insert| insert);

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        ys[first_matching_element..]
            .iter()
            .take_while(move |&y| {
                let mut y_k_bits = Y::<K>::default();
                y_k_bits.copy_bits_from(y, 0_usize, usize::from(K), 0_usize);
                // Check if first K bits match
                y_k_bits == first_k_challenge_bits
            })
            .zip(first_matching_element..)
            .map(move |(_y, position)| {
                let positions = self
                    .table_7
                    .position(Position::<K>::from(position))
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

                let left_x = self
                    .table_1
                    .xs()
                    .get(usize::from(left_position))
                    .expect("Internally generated pointers must be correct; qed");
                let right_x = self
                    .table_1
                    .xs()
                    .get(usize::from(right_position))
                    .expect("Internally generated pointers must be correct; qed");

                let mut buffer = [0; mem::size_of::<Challenge>() + K as usize * 2];

                buffer[..mem::size_of::<Challenge>()].copy_from_slice(challenge);
                buffer.copy_bits_from(
                    left_x,
                    0_usize,
                    usize::from(K),
                    mem::size_of::<Challenge>() * u8::BITS as usize,
                );
                buffer.copy_bits_from(
                    right_x,
                    0_usize,
                    usize::from(K),
                    mem::size_of::<Challenge>() * u8::BITS as usize + usize::from(K),
                );

                let mut hasher = Sha256::new();
                hasher.update(buffer);
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
        let mut first_k_challenge_bits = Y::<K>::default();
        first_k_challenge_bits.copy_bits_from(challenge, 0_usize, usize::from(K), 0_usize);
        let first_matching_element = ys
            .binary_search(&first_k_challenge_bits)
            .unwrap_or_else(|insert| insert);

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        ys[first_matching_element..]
            .iter()
            .take_while(move |&y| {
                let mut y_k_bits = Y::<K>::default();
                y_k_bits.copy_bits_from(y, 0_usize, usize::from(K), 0_usize);
                // Check if first K bits match
                y_k_bits == first_k_challenge_bits
            })
            .zip(first_matching_element..)
            .map(move |(_y, position)| {
                let mut proof = [0u8; 64 * K as usize / 8];

                self.table_7
                    .position(Position::<K>::from(position))
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
                    .for_each(|(offset, x)| {
                        proof.copy_bits_from(x, 0_usize, usize::from(K), usize::from(K) * offset)
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
        EvaluatableUsize<{ mem::size_of::<Challenge>() + K as usize * 2 }>: Sized,
    {
        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;

        let ys_and_metadata = (0..64_usize)
            .map(|offset| {
                let mut x = X::default();
                x.copy_bits_from(
                    proof_of_space,
                    usize::from(K) * offset,
                    usize::from(K),
                    0_usize,
                );

                let (partial_y, partial_y_offset) = partial_y::<K>(seed, usize::from(&x));
                let y = compute_f1::<K>(x, &partial_y, partial_y_offset);

                let mut metadata = Metadata::<K, 1>::default();
                metadata.copy_bits_from(&x, 0_usize, K, 0_usize);
                (y, metadata)
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

                y.starts_with(&challenge.view_bits::<Msb0>()[..usize::from(K)])
            })
            .map(|_| {
                let mut buffer = [0; mem::size_of::<Challenge>() + K as usize * 2];

                buffer[..mem::size_of::<Challenge>()].copy_from_slice(challenge);
                let mut quality_index = 0_usize.to_be_bytes();
                quality_index[0] = last_5_challenge_bits;
                let quality_index = usize::from_be_bytes(quality_index);

                buffer.copy_bits_from(
                    proof_of_space,
                    quality_index * usize::from(K) * 2,
                    usize::from(K) * 2,
                    mem::size_of::<Challenge>() * u8::BITS as usize,
                );

                let mut hasher = Sha256::new();
                hasher.update(buffer);
                hasher.finalize().into()
            })
    }

    fn collect_ys_and_metadata<const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
        ys_and_metadata: &[(Y<K>, Metadata<K, PARENT_TABLE_NUMBER>)],
    ) -> Option<Vec<(Y<K>, Metadata<K, TABLE_NUMBER>)>>
    where
        EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        ys_and_metadata
            .array_chunks::<2>()
            .map(|&[(left_y, left_metadata), (right_y, right_metadata)]| {
                (num_matches(&left_y, &right_y) == 1).then_some(compute_fn(
                    left_y,
                    left_metadata,
                    right_metadata,
                ))
            })
            .collect()
    }
}
