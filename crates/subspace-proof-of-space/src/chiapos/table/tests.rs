//! Tests translated into Rust from
//! https://github.com/Chia-Network/chiapos/blob/a2049c5367fe60930533a995f7ffded538f04dc4/tests/test.cpp

use crate::chiapos::constants::{PARAM_B, PARAM_BC, PARAM_C, PARAM_EXT};
use crate::chiapos::table::types::{Metadata, X, Y};
use crate::chiapos::table::{
    calculate_left_targets, compute_f1, compute_fn, find_matches, fn_hashing_input_bytes,
    metadata_size_bytes, partial_y, y_size_bytes,
};
use crate::chiapos::utils::EvaluatableUsize;
use crate::chiapos::Seed;
use std::collections::BTreeMap;

/// Chia does this for some reason 🤷‍
fn to_chia_seed(seed: &Seed) -> Seed {
    let mut chia_seed = [1u8; 32];
    chia_seed[1..].copy_from_slice(&seed[..31]);
    chia_seed
}

#[cfg(target_pointer_width = "64")]
#[test]
fn test_compute_f1_k35() {
    const K: u8 = 35;
    let seed = to_chia_seed(&[
        0, 2, 3, 4, 5, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 41, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 11, 15, 16,
    ]);

    let xs = [525, 526, 625_usize];
    let expected_ys = [948_868_477_184, 2_100_559_512_384, 1_455_233_158_208_usize];

    for (x, expected_y) in xs.into_iter().zip(expected_ys) {
        let (partial_y, partial_y_offset) = partial_y::<K>(seed, x);
        let y = compute_f1::<K>(X::from(x), &partial_y, partial_y_offset);
        let y = usize::from(&y);
        assert_eq!(y, expected_y);
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn test_compute_f1_k32() {
    const K: u8 = 32;
    let seed = to_chia_seed(&[
        0, 2, 3, 4, 5, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 41, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 11, 15, 16,
    ]);

    let xs = [
        192_837_491,
        192_837_491 + 1,
        192_837_491 + 2,
        192_837_491 + 255_usize,
    ];
    let expected_ys = [
        206_843_700_930,
        32_315_542_210,
        156_034_446_146,
        128_694_732_738_usize,
    ];

    for (x, expected_y) in xs.into_iter().zip(expected_ys) {
        let (partial_y, partial_y_offset) = partial_y::<K>(seed, x);
        let y = compute_f1::<K>(X::from(x), &partial_y, partial_y_offset);
        let y = usize::from(&y);
        assert_eq!(y, expected_y);
    }
}

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
#[test]
fn test_matches() {
    const K: u8 = 12;
    let seed = to_chia_seed(&[
        20, 2, 5, 4, 51, 52, 23, 84, 91, 10, 111, 12, 13, 24, 151, 16, 228, 211, 254, 45, 92, 198,
        204, 10, 9, 10, 11, 129, 139, 171, 15, 18,
    ]);

    let mut buckets = BTreeMap::<usize, Vec<_>>::new();
    let mut x = 0;
    for _ in 0..=1 << (K - 4) {
        for _ in 0..16 {
            let (partial_y, partial_y_offset) = partial_y::<K>(seed, x);
            let y = compute_f1::<K>(X::from(x), &partial_y, partial_y_offset);
            let bucket_index = usize::from(&y) / usize::from(PARAM_BC);

            buckets.entry(bucket_index).or_default().push(y);

            if x + 1 > (1 << K) - 1 {
                break;
            }

            x += 1;
        }

        if x + 1 > (1 << K) - 1 {
            break;
        }
    }

    let left_targets = calculate_left_targets();
    let mut rmap_scratch = Vec::new();
    let buckets = buckets.into_values().collect::<Vec<_>>();
    let mut total_matches = 0_usize;
    for [mut left_bucket, mut right_bucket] in buckets.array_windows::<2>().cloned() {
        left_bucket.sort_unstable();
        left_bucket.reverse();
        right_bucket.sort_unstable();
        right_bucket.reverse();

        let matches = find_matches::<K>(
            &left_bucket,
            &right_bucket,
            &mut rmap_scratch,
            &left_targets,
        );
        for m in matches.unwrap() {
            let yl = usize::from(left_bucket.get(m.left_index).unwrap());
            let yr = usize::from(right_bucket.get(m.right_index).unwrap());

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
    left_metadata: usize,
    right_metadata: usize,
    y: usize,
    y_output_expected: usize,
    metadata_expected: usize,
) where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ metadata_size_bytes(K, PARENT_TABLE_NUMBER) }>: Sized,
    EvaluatableUsize<{ fn_hashing_input_bytes(K) }>: Sized,
{
    let (y_output, metadata) = compute_fn::<K, TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        Y::<K>::from(y),
        Metadata::<K, PARENT_TABLE_NUMBER>::from(left_metadata),
        Metadata::<K, PARENT_TABLE_NUMBER>::from(right_metadata),
    );
    let y_output = usize::from(&y_output);
    assert_eq!(y_output, y_output_expected);
    if metadata_expected != 0 {
        assert_eq!(
            metadata,
            Metadata::<K, TABLE_NUMBER>::from(metadata_expected)
        );
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
