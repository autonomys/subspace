//! Tests translated into Rust from
//! https://github.com/Chia-Network/chiapos/blob/a2049c5367fe60930533a995f7ffded538f04dc4/tests/test.cpp

use crate::chiapos::Seed;
#[cfg(feature = "alloc")]
use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT};
#[cfg(feature = "alloc")]
use crate::chiapos::table::types::Position;
use crate::chiapos::table::types::{Metadata, X, Y};
use crate::chiapos::table::{
    COMPUTE_F1_SIMD_FACTOR, compute_f1, compute_f1_simd, compute_fn, compute_fn_simd,
    metadata_size_bytes,
};
#[cfg(feature = "alloc")]
use crate::chiapos::table::{calculate_left_targets, find_matches_in_buckets};
use crate::chiapos::utils::EvaluatableUsize;
#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;
use core::simd::prelude::*;

/// Chia does this for some reason 🤷
fn to_chia_seed(seed: &Seed) -> Seed {
    let mut chia_seed = [1u8; 32];
    chia_seed[1..].copy_from_slice(&seed[..31]);
    chia_seed
}

#[test]
fn test_compute_f1_k25() {
    const K: u8 = 25;
    let seed = to_chia_seed(&[
        0, 2, 3, 4, 5, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 41, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 11, 15, 16,
    ]);

    let xs = [525, 526, 625_u32];
    let expected_ys = [2_016_650_816, 2_063_162_112, 1_930_299_520_u32];

    for (x, expected_y) in xs.into_iter().zip(expected_ys) {
        let x = X::from(x);
        let y = compute_f1::<K>(x, &seed);
        assert_eq!(y, Y::from(expected_y));

        // Make sure SIMD matches non-SIMD version
        let mut partial_ys = [0; K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize];
        let starts_with_partial_y_bits = y.first_k_bits() << (u32::BITS - u32::from(K));
        partial_ys[..size_of::<u32>()].copy_from_slice(&starts_with_partial_y_bits.to_be_bytes());
        let y = compute_f1_simd::<K>(Simd::splat(x.into()), &partial_ys);
        assert_eq!(y[0], Y::from(expected_y));
    }
}

#[test]
fn test_compute_f1_k22() {
    const K: u8 = 22;
    let seed = to_chia_seed(&[
        0, 2, 3, 4, 5, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 41, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 11, 15, 16,
    ]);

    let xs = [1_837_491, 1_837_491 + 1, 1_837_491 + 2, 1_837_491 + 255_u32];
    let expected_ys = [105_738_140, 192_213_404, 64_977_628, 91_711_644_u32];

    for (x, expected_y) in xs.into_iter().zip(expected_ys) {
        let x = X::from(x);
        let y = compute_f1::<K>(x, &seed);
        assert_eq!(y, Y::from(expected_y));

        // Make sure SIMD matches non-SIMD version
        let mut partial_ys = [0; K as usize * COMPUTE_F1_SIMD_FACTOR / u8::BITS as usize];
        let starts_with_partial_y_bits = y.first_k_bits() << (u32::BITS - u32::from(K));
        partial_ys[..size_of::<u32>()].copy_from_slice(&starts_with_partial_y_bits.to_be_bytes());
        let y = compute_f1_simd::<K>(Simd::splat(x.into()), &partial_ys);
        assert_eq!(y[0], Y::from(expected_y));
    }
}

#[cfg(feature = "alloc")]
fn check_match(yl: usize, yr: usize) -> bool {
    let yl = yl as i64;
    let yr = yr as i64;
    let param_b = i64::from(PARAM_B);
    let param_c = i64::from(PARAM_C);
    let param_bc = i64::from(PARAM_BC);
    let bl = yl / param_bc;
    let br = yr / param_bc;
    if bl + 1 != br {
        // Buckets don't match
        return false;
    }
    for m in 0..(1 << PARAM_EXT) {
        if (((yr % param_bc) / param_c - (yl % param_bc) / param_c) - m) % param_b == 0 {
            let mut c_diff = 2 * m + bl % 2;
            c_diff *= c_diff;

            if (((yr % param_bc) % param_c - (yl % param_bc) % param_c) - c_diff) % param_c == 0 {
                return true;
            }
        }
    }

    false
}

// TODO: This test should be rewritten into something more readable, currently it is more or less
//  direct translation from C++
#[cfg(feature = "alloc")]
#[test]
#[cfg_attr(miri, ignore)]
fn test_matches() {
    const K: u8 = 12;
    let seed = to_chia_seed(&[
        20, 2, 5, 4, 51, 52, 23, 84, 91, 10, 111, 12, 13, 24, 151, 16, 228, 211, 254, 45, 92, 198,
        204, 10, 9, 10, 11, 129, 139, 171, 15, 18,
    ]);

    let mut bucket_ys = BTreeMap::<usize, Vec<_>>::new();
    let mut x = X::from(0);
    for _ in 0..=1 << (K - 4) {
        for _ in 0..16 {
            let y = compute_f1::<K>(x, &seed);
            let bucket_index = usize::from(y) / usize::from(PARAM_BC);

            bucket_ys.entry(bucket_index).or_default().push(y);

            if x + X::from(1) > X::from((1 << K) - 1) {
                break;
            }

            x += X::from(1);
        }

        if x + X::from(1) > X::from((1 << K) - 1) {
            break;
        }
    }

    let left_targets = calculate_left_targets();
    let bucket_ys = bucket_ys.into_values().collect::<Vec<_>>();
    let mut total_matches = 0_usize;
    for (left_bucket_index, [left_bucket_ys, right_bucket_ys]) in
        bucket_ys.array_windows::<2>().enumerate()
    {
        let mut left_bucket = [(Position::SENTINEL, Y::SENTINEL); _];
        assert!(left_bucket_ys.len() <= left_bucket.len());
        for ((output, &y), index) in left_bucket
            .iter_mut()
            .zip(left_bucket_ys)
            .zip(0..left_bucket_ys.len())
        {
            let position = Position::from(index as u32);
            *output = (position, y);
        }
        let mut right_bucket = [(Position::SENTINEL, Y::SENTINEL); _];
        assert!(right_bucket_ys.len() <= right_bucket.len());
        for ((output, &y), index) in right_bucket
            .iter_mut()
            .zip(right_bucket_ys)
            .zip((left_bucket_ys.len()..).take(right_bucket_ys.len()))
        {
            let position = Position::from(index as u32);
            *output = (position, y);
        }
        let parent_table_ys = left_bucket_ys
            .iter()
            .copied()
            .chain(right_bucket_ys.iter().copied())
            .collect::<Vec<_>>();

        let mut matches = [MaybeUninit::uninit(); _];
        // SAFETY: Positions correspond to `y`s
        let matches = unsafe {
            find_matches_in_buckets(
                left_bucket_index as u32,
                &left_bucket,
                &right_bucket,
                &mut matches,
                &left_targets,
            )
        };
        for m in matches {
            // SAFETY: All `y`s are initialized
            let yl = usize::from(parent_table_ys[usize::from(m.left_position)]);
            // SAFETY: All `y`s are initialized
            let yr = usize::from(parent_table_ys[usize::from(m.right_position)]);

            assert!(check_match(yl, yr));
            total_matches += 1;
        }
    }

    assert!(
        total_matches > (1 << K) / 2,
        "total_matches {total_matches}"
    );
    assert!(
        total_matches < (1 << K) * 2,
        "total_matches {total_matches}"
    );
}

fn verify_fn<const K: u8, const TABLE_NUMBER: u8, const PARENT_TABLE_NUMBER: u8>(
    left_metadata: u128,
    right_metadata: u128,
    y: u32,
    y_output_expected: u32,
    metadata_expected: u128,
) where
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    let (y_output, metadata) = compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        Y::from(y),
        Metadata::from(left_metadata),
        Metadata::from(right_metadata),
    );
    assert_eq!(y_output, Y::from(y_output_expected));
    if metadata_expected != 0 {
        assert_eq!(metadata, Metadata::from(metadata_expected));
    }

    let (y_outputs, metadatas) = compute_fn_simd::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        [Y::from(y); _],
        [Metadata::from(left_metadata); _],
        [Metadata::from(right_metadata); _],
    );
    assert_eq!([y_output; _], y_outputs);
    if metadata_expected != 0 {
        assert_eq!([metadata; _], metadatas);
    }
}

#[test]
fn test_verify_fn() {
    const K: u8 = 16;

    verify_fn::<K, 2, 1>(0x44cb, 0x204f, 0x20a61a, 0x2af546, 0x44cb204f);
    verify_fn::<K, 2, 1>(0x3c5f, 0xfda9, 0x3988ec, 0x15293b, 0x3c5ffda9);
    verify_fn::<K, 3, 2>(
        0x35bf992d,
        0x7ce42c82,
        0x31e541,
        0xf73b3,
        0x35bf992d7ce42c82,
    );
    verify_fn::<K, 3, 2>(
        0x7204e52d,
        0xf1fd42a2,
        0x28a188,
        0x3fb0b5,
        0x7204e52df1fd42a2,
    );
    verify_fn::<K, 4, 3>(
        0x5b6e6e307d4bedc,
        0x8a9a021ea648a7dd,
        0x30cb4c,
        0x11ad5,
        0xd4bd0b144fc26138,
    );
    verify_fn::<K, 4, 3>(
        0xb9d179e06c0fd4f5,
        0xf06d3fef701966a0,
        0x1dd5b6,
        0xe69a2,
        0xd02115f512009d4d,
    );
    verify_fn::<K, 5, 4>(
        0xc2cd789a380208a9,
        0x19999e3fa46d6753,
        0x25f01e,
        0x1f22bd,
        0xabe423040a33,
    );
    verify_fn::<K, 5, 4>(
        0xbe3edc0a1ef2a4f0,
        0x4da98f1d3099fdf5,
        0x3feb18,
        0x31501e,
        0x7300a3a03ac5,
    );
    verify_fn::<K, 6, 5>(
        0xc965815a47c5,
        0xf5e008d6af57,
        0x1f121a,
        0x1cabbe,
        0xc8cc6947,
    );
    verify_fn::<K, 6, 5>(
        0xd420677f6cbd,
        0x5894aa2ca1af,
        0x2efde9,
        0xc2121,
        0x421bb8ec,
    );
    verify_fn::<K, 7, 6>(0x5fec898f, 0x82283d15, 0x14f410, 0x24c3c2, 0x0);
    verify_fn::<K, 7, 6>(0x64ac5db9, 0x7923986, 0x590fd, 0x1c74a2, 0x0);
}
