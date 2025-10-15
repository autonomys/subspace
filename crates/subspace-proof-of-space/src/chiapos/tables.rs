//! `chiapos` precalculated tables.

#[cfg(all(feature = "alloc", test))]
mod tests;

use crate::chiapos::Seed;
#[cfg(feature = "alloc")]
pub use crate::chiapos::table::TablesCache;
#[cfg(feature = "alloc")]
use crate::chiapos::table::types::Position;
use crate::chiapos::table::types::{Metadata, X, Y};
use crate::chiapos::table::{
    COMPUTE_F1_SIMD_FACTOR, compute_f1, compute_fn, has_match, metadata_size_bytes, num_buckets,
};
#[cfg(feature = "alloc")]
use crate::chiapos::table::{PrunedTable, Table};
use crate::chiapos::utils::EvaluatableUsize;
#[cfg(any(feature = "full-chiapos", test))]
use crate::chiapos::{Challenge, Quality};
use core::array;
use core::mem::MaybeUninit;
#[cfg(any(feature = "full-chiapos", test))]
use sha2::{Digest, Sha256};

/// Pick position in `table_number` based on challenge bits
#[cfg(all(feature = "alloc", any(feature = "full-chiapos", test)))]
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
    EvaluatableUsize<{ metadata_size_bytes(K, 7) }>: Sized,
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    #[cfg(feature = "alloc")]
    table_2: PrunedTable<K, 2>,
    #[cfg(feature = "alloc")]
    table_3: PrunedTable<K, 3>,
    #[cfg(feature = "alloc")]
    table_4: PrunedTable<K, 4>,
    #[cfg(feature = "alloc")]
    table_5: PrunedTable<K, 5>,
    #[cfg(feature = "alloc")]
    table_6: PrunedTable<K, 6>,
    #[cfg(feature = "alloc")]
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
    [(); 1 << K]:,
    [(); num_buckets(K)]:,
    [(); num_buckets(K) - 1]:,
{
    /// Create Chia proof of space tables. There also exists [`Self::create_parallel()`] that trades
    /// CPU efficiency and memory usage for lower latency.
    #[cfg(feature = "alloc")]
    pub(super) fn create(seed: Seed, cache: &TablesCache) -> Self {
        let table_1 = Table::<K, 1>::create(seed);
        let (table_2, _) = Table::<K, 2>::create(table_1, cache);
        let (table_3, table_2) = Table::<K, 3>::create(table_2, cache);
        let (table_4, table_3) = Table::<K, 4>::create(table_3, cache);
        let (table_5, table_4) = Table::<K, 5>::create(table_4, cache);
        let (table_6, table_5) = Table::<K, 6>::create(table_5, cache);
        let (table_7, table_6) = Table::<K, 7>::create(table_6, cache);

        Self {
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
    #[cfg(feature = "parallel")]
    pub(super) fn create_parallel(seed: Seed, cache: &TablesCache) -> Self {
        let table_1 = Table::<K, 1>::create_parallel(seed);
        let (table_2, _) = Table::<K, 2>::create_parallel(table_1, cache);
        let (table_3, table_2) = Table::<K, 3>::create_parallel(table_2, cache);
        let (table_4, table_3) = Table::<K, 4>::create_parallel(table_3, cache);
        let (table_5, table_4) = Table::<K, 5>::create_parallel(table_4, cache);
        let (table_6, table_5) = Table::<K, 6>::create_parallel(table_5, cache);
        let (table_7, table_6) = Table::<K, 7>::create_parallel(table_6, cache);

        Self {
            table_2,
            table_3,
            table_4,
            table_5,
            table_6,
            table_7,
        }
    }

    /// Find proof of space quality for a given challenge
    #[cfg(all(feature = "alloc", any(feature = "full-chiapos", test)))]
    pub(super) fn find_quality<'a>(
        &'a self,
        challenge: &'a Challenge,
    ) -> impl Iterator<Item = Quality> + 'a {
        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;

        let first_k_challenge_bits = u32::from_be_bytes(
            challenge[..size_of::<u32>()]
                .try_into()
                .expect("Challenge is known to statically have enough bytes; qed"),
        ) >> (u32::BITS as usize - usize::from(K));

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        self.table_7.buckets()[Y::bucket_range_from_first_k_bits(first_k_challenge_bits)]
            .iter()
            .flat_map(move |positions| {
                positions
                    .iter()
                    .take_while(|&&(position, _y)| position != Position::SENTINEL)
                    .filter(move |&&(_position, y)| y.first_k_bits() == first_k_challenge_bits)
            })
            .map(move |&(position, _y)| {
                // SAFETY: Internally generated positions that come from the parent table
                let positions = unsafe { self.table_7.position(position) };
                // SAFETY: Internally generated positions that come from the parent table
                let positions = unsafe {
                    self.table_6
                        .position(pick_position(positions, last_5_challenge_bits, 6))
                };
                // SAFETY: Internally generated positions that come from the parent table
                let positions = unsafe {
                    self.table_5
                        .position(pick_position(positions, last_5_challenge_bits, 5))
                };
                // SAFETY: Internally generated positions that come from the parent table
                let positions = unsafe {
                    self.table_4
                        .position(pick_position(positions, last_5_challenge_bits, 4))
                };
                // SAFETY: Internally generated positions that come from the parent table
                let positions = unsafe {
                    self.table_3
                        .position(pick_position(positions, last_5_challenge_bits, 3))
                };
                // SAFETY: Internally generated positions that come from the parent table
                let [left_position, right_position] = unsafe {
                    self.table_2
                        .position(pick_position(positions, last_5_challenge_bits, 2))
                };

                // X matches position
                let left_x = X::from(u32::from(left_position));
                let right_x = X::from(u32::from(right_position));

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

    /// Find proof of space for a given challenge
    #[cfg(feature = "alloc")]
    pub(super) fn find_proof<'a>(
        &'a self,
        first_challenge_bytes: [u8; 4],
    ) -> impl Iterator<Item = [u8; 64 * K as usize / 8]> + 'a {
        let first_k_challenge_bits =
            u32::from_be_bytes(first_challenge_bytes) >> (u32::BITS as usize - usize::from(K));

        // Iterate just over elements that are matching `first_k_challenge_bits` prefix
        self.table_7.buckets()[Y::bucket_range_from_first_k_bits(first_k_challenge_bits)]
            .iter()
            .flat_map(move |positions| {
                positions
                    .iter()
                    .take_while(|&&(position, _y)| position != Position::SENTINEL)
                    .filter(move |&&(_position, y)| y.first_k_bits() == first_k_challenge_bits)
            })
            .map(move |&(position, _y)| {
                let mut proof = [0u8; 64 * K as usize / 8];

                // SAFETY: Internally generated positions that come from the parent table
                unsafe { self.table_7.position(position) }
                    .into_iter()
                    .flat_map(|position| {
                        // SAFETY: Internally generated positions that come from the parent table
                        unsafe { self.table_6.position(position) }
                    })
                    .flat_map(|position| {
                        // SAFETY: Internally generated positions that come from the parent table
                        unsafe { self.table_5.position(position) }
                    })
                    .flat_map(|position| {
                        // SAFETY: Internally generated positions that come from the parent table
                        unsafe { self.table_4.position(position) }
                    })
                    .flat_map(|position| {
                        // SAFETY: Internally generated positions that come from the parent table
                        unsafe { self.table_3.position(position) }
                    })
                    .flat_map(|position| {
                        // SAFETY: Internally generated positions that come from the parent table
                        unsafe { self.table_2.position(position) }
                    })
                    .map(|position| {
                        // X matches position
                        X::from(u32::from(position))
                    })
                    .enumerate()
                    .for_each(|(offset, x)| {
                        let x_offset_in_bits = usize::from(K) * offset;
                        // Collect bytes where bits of `x` will be written
                        let proof_bytes = &mut proof[x_offset_in_bits / u8::BITS as usize..]
                            [..(x_offset_in_bits % u8::BITS as usize + usize::from(K))
                                .div_ceil(u8::BITS as usize)];

                        // Bits of `x` already shifted to the correct location as they will appear
                        // in `proof`
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

    /// Verify proof of space for a given seed and challenge
    pub(super) fn verify_only(
        seed: &Seed,
        first_challenge_bytes: [u8; 4],
        proof_of_space: &[u8; 64 * K as usize / 8],
    ) -> bool
    where
        EvaluatableUsize<{ (K as usize * 2).div_ceil(u8::BITS as usize) }>: Sized,
    {
        let first_k_challenge_bits =
            u32::from_be_bytes(first_challenge_bytes) >> (u32::BITS as usize - usize::from(K));

        let ys_and_metadata = array::from_fn::<_, 64, _>(|offset| {
            let mut pre_x_bytes = 0u64.to_be_bytes();
            let offset_in_bits = usize::from(K) * offset;
            let bytes_to_copy =
                (offset_in_bits % u8::BITS as usize + usize::from(K)).div_ceil(u8::BITS as usize);
            // Copy full bytes that contain bits of `x`
            pre_x_bytes[..bytes_to_copy].copy_from_slice(
                &proof_of_space[offset_in_bits / u8::BITS as usize..][..bytes_to_copy],
            );
            // Extract `pre_x` whose last `K` bits start with `x`
            let pre_x = u64::from_be_bytes(pre_x_bytes)
                >> (u64::BITS as usize - (usize::from(K) + offset_in_bits % u8::BITS as usize));
            // Convert to the desired type and clear extra bits
            let x = X::from(pre_x as u32 & (u32::MAX >> (u32::BITS as usize - usize::from(K))));

            let y = compute_f1::<K>(x, seed);

            (y, Metadata::from(x))
        });

        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<2, 1, 64>(&ys_and_metadata, &mut next_ys_and_metadata);
        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<3, 2, 32>(ys_and_metadata, &mut next_ys_and_metadata);
        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<4, 3, 16>(ys_and_metadata, &mut next_ys_and_metadata);
        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<5, 4, 8>(ys_and_metadata, &mut next_ys_and_metadata);
        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<6, 5, 4>(ys_and_metadata, &mut next_ys_and_metadata);
        let mut next_ys_and_metadata = [MaybeUninit::uninit(); _];
        let ys_and_metadata =
            Self::collect_ys_and_metadata::<7, 6, 2>(ys_and_metadata, &mut next_ys_and_metadata);

        let Some((y, _metadata)) = ys_and_metadata.first() else {
            return false;
        };

        // Check if the first K bits of `y` match
        y.first_k_bits() == first_k_challenge_bits
    }

    /// Verify proof of space for a given seed and challenge.
    ///
    /// Similar to [`Self::verify_only()`], but also returns quality on successful verification.
    #[cfg(any(feature = "full-chiapos", test))]
    pub(super) fn verify(
        seed: &Seed,
        challenge: &Challenge,
        proof_of_space: &[u8; 64 * K as usize / 8],
    ) -> Option<Quality>
    where
        EvaluatableUsize<{ (K as usize * 2).div_ceil(u8::BITS as usize) }>: Sized,
    {
        if !Self::verify_only(
            seed,
            [challenge[0], challenge[1], challenge[2], challenge[3]],
            proof_of_space,
        ) {
            return None;
        }

        let last_5_challenge_bits = challenge[challenge.len() - 1] & 0b00011111;

        let mut quality_index = 0_usize.to_be_bytes();
        quality_index[0] = last_5_challenge_bits;
        let quality_index = usize::from_be_bytes(quality_index);

        // NOTE: this works correctly but may overflow if `quality_index` is changed to
        // not be zero-initialized anymore
        let left_right_xs_bit_offset = quality_index * usize::from(K * 2);
        // Collect `left_x` and `right_x` bits, potentially with extra bits at the beginning
        // and the end
        let left_right_xs_bytes = &proof_of_space[left_right_xs_bit_offset / u8::BITS as usize..]
            [..(left_right_xs_bit_offset % u8::BITS as usize + usize::from(K * 2))
                .div_ceil(u8::BITS as usize)];

        let mut left_right_xs = 0u64.to_be_bytes();
        left_right_xs[..left_right_xs_bytes.len()].copy_from_slice(left_right_xs_bytes);
        // Move `left_x` and `right_x` bits to most significant bits
        let left_right_xs =
            u64::from_be_bytes(left_right_xs) << (left_right_xs_bit_offset % u8::BITS as usize);
        // Clear extra bits
        let left_right_xs_mask = u64::MAX << (u64::BITS as usize - usize::from(K * 2));
        let left_right_xs = left_right_xs & left_right_xs_mask;

        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher
            .update(&left_right_xs.to_be_bytes()[..usize::from(K * 2).div_ceil(u8::BITS as usize)]);
        Some(hasher.finalize().into())
    }

    fn collect_ys_and_metadata<
        'a,
        const TABLE_NUMBER: u8,
        const PARENT_TABLE_NUMBER: u8,
        const N: usize,
    >(
        ys_and_metadata: &[(Y, Metadata<K, PARENT_TABLE_NUMBER>)],
        next_ys_and_metadata: &'a mut [MaybeUninit<(Y, Metadata<K, TABLE_NUMBER>)>; N],
    ) -> &'a [(Y, Metadata<K, TABLE_NUMBER>)]
    where
        EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
        EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    {
        let mut next_offset = 0_usize;
        for &[(left_y, left_metadata), (right_y, right_metadata)] in
            ys_and_metadata.as_chunks::<2>().0
        {
            if !has_match(left_y, right_y) {
                continue;
            }

            next_ys_and_metadata[next_offset].write(compute_fn::<
                K,
                TABLE_NUMBER,
                PARENT_TABLE_NUMBER,
            >(
                left_y, left_metadata, right_metadata
            ));
            next_offset += 1;
        }

        // SAFETY: Initialized `next_offset` elements
        unsafe { next_ys_and_metadata[..next_offset].assume_init_ref() }
    }
}
