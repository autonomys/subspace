//! Tests translated into Rust from
//! https://github.com/Chia-Network/chiapos/blob/a2049c5367fe60930533a995f7ffded538f04dc4/tests/test.cpp

use crate::chiapos::Seed;
use crate::chiapos::constants::{NUM_TABLES, PARAM_BC, PARAM_EXT};
#[cfg(feature = "alloc")]
use crate::chiapos::constants::{PARAM_B, PARAM_C};
#[cfg(feature = "alloc")]
use crate::chiapos::table::types::Position;
use crate::chiapos::table::types::{Metadata, X, Y};
use crate::chiapos::table::{
    BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS, COMPUTE_F1_SIMD_FACTOR, REDUCED_BUCKET_SIZE,
    REDUCED_MATCHES_COUNT, compute_f1, compute_f1_simd, compute_fn, compute_fn_simd,
    metadata_size_bytes,
};
#[cfg(feature = "alloc")]
use crate::chiapos::table::{calculate_left_targets, find_matches_in_buckets};
use crate::chiapos::utils::EvaluatableUsize;
#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::f64::consts::{LN_2, PI, SQRT_2};
#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;
use core::simd::prelude::*;
use subspace_core_primitives::pieces::Record;

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
fn check_match(yl: u32, yr: u32) -> bool {
    let param_b = u64::from(PARAM_B);
    let param_c = u64::from(PARAM_C);
    let param_bc = u64::from(PARAM_BC);
    let yl = u64::from(yl);
    let yr = u64::from(yr);

    let bl = yl / param_bc;
    let br = yr / param_bc;
    if bl + 1 != br {
        // Buckets don't match
        return false;
    }

    let lp = (yl % param_bc) / param_c;
    let rp = (yr % param_bc) / param_c;
    let lc = (yl % param_bc) % param_c;
    let rc = (yr % param_bc) % param_c;

    for m in 0..(1 << PARAM_EXT) {
        if rp % param_b == (lp + m) % param_b {
            let mut c_diff = 2 * m + bl % 2;
            c_diff *= c_diff;

            if rc == (lc + c_diff) % param_c {
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
    for _ in 0..=1u32 << (K - 4) {
        for _ in 0..16u8 {
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
            let yl = u32::from(parent_table_ys[usize::from(m.left_position)]);
            let yr = u32::from(parent_table_ys[usize::from(m.right_position)]);

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
    let y_outputs = Y::array_from_repr(y_outputs.to_array());
    assert_eq!([y_output; _], y_outputs);
    if metadata_expected != 0 {
        assert_eq!([metadata; _], metadatas);
    }
}

#[test]
fn test_verify_fn() {
    const K: u8 = 16;

    verify_fn::<K, 2, 1>(0x44cb, 0x204f, 0x20_a61a, 0x2a_f546, 0x44cb_204f);
    verify_fn::<K, 2, 1>(0x3c5f, 0xfda9, 0x39_88ec, 0x15_293b, 0x3c5f_fda9);
    verify_fn::<K, 3, 2>(
        0x35bf_992d,
        0x7ce4_2c82,
        0x31_e541,
        0xf_73b3,
        0x35bf_992d_7ce4_2c82,
    );
    verify_fn::<K, 3, 2>(
        0x7204_e52d,
        0xf1fd_42a2,
        0x28_a188,
        0x3f_b0b5,
        0x7204_e52d_f1fd_42a2,
    );
    verify_fn::<K, 4, 3>(
        0x5b6_e6e3_07d4_bedc,
        0x8a9a_021e_a648_a7dd,
        0x30_cb4c,
        0x1_1ad5,
        0xd4bd_0b14_4fc2_6138,
    );
    verify_fn::<K, 4, 3>(
        0xb9d1_79e0_6c0f_d4f5,
        0xf06d_3fef_7019_66a0,
        0x1d_d5b6,
        0xe_69a2,
        0xd021_15f5_1200_9d4d,
    );
    verify_fn::<K, 5, 4>(
        0xc2cd_789a_3802_08a9,
        0x1999_9e3f_a46d_6753,
        0x25_f01e,
        0x1f_22bd,
        0xabe4_2304_0a33,
    );
    verify_fn::<K, 5, 4>(
        0xbe3e_dc0a_1ef2_a4f0,
        0x4da9_8f1d_3099_fdf5,
        0x3f_eb18,
        0x31_501e,
        0x7300_a3a0_3ac5,
    );
    verify_fn::<K, 6, 5>(
        0xc965_815a_47c5,
        0xf5e0_08d6_af57,
        0x1f_121a,
        0x1c_abbe,
        0xc8cc_6947,
    );
    verify_fn::<K, 6, 5>(
        0xd420_677f_6cbd,
        0x5894_aa2c_a1af,
        0x2e_fde9,
        0xc_2121,
        0x421b_b8ec,
    );
    verify_fn::<K, 7, 6>(0x5fec_898f, 0x8228_3d15, 0x14_f410, 0x24_c3c2, 0x0);
    verify_fn::<K, 7, 6>(0x64ac_5db9, 0x792_3986, 0x5_90fd, 0x1c_74a2, 0x0);
}

#[test]
fn test_proofs_lower_bound() {
    /// Calculates a probabilistic lower bound on the number of challenges (out of
    /// [`Record::NUM_S_BUCKETS`]) that will have at least one proof found, accounting for
    /// truncations in matches and bucket sizes.
    ///
    /// This is based on modeling the entry propagation rate over 6 steps (for 7 tables), assuming
    /// normal-distributed matches and bucket sizes with mean `lambda = PARAM_BC / 2^PARAM_EXT`.
    /// A variance factor is applied to account for higher variance observed in practice for small
    /// `k` due to clustering/non-uniformity.
    ///
    /// The bound ensures the probability that the actual number is below it is less than
    /// `2^{-security_bits}`, using Chernoff on the lower tail of the binomial distribution for
    /// non-empty challenge buckets.
    /// Uses floating-point for precision in tail loss calculation (exact normal formula for
    /// truncation rate with Abramowitz and Stegun erf approximation).
    fn proofs_lower_bound(
        security_bits: u8,
        reduced_matches_count: usize,
        reduced_bucket_size: usize,
    ) -> u64 {
        // Empirical variance factor to match observed higher variance/clustering for small `k`
        const V_FACTOR: f64 = 9.0;

        // Lambda is the expected number per bucket/pair, independent of `k`.
        let lambda = f64::from(PARAM_BC) / f64::from(2u32.pow(u32::from(PARAM_EXT)));

        // Rate for match truncation
        let match_truncation_rate =
            normal_rate_approx(lambda, reduced_matches_count as f64, V_FACTOR);
        // Rate for bucket truncation
        let bucket_truncation_rate =
            normal_rate_approx(lambda, reduced_bucket_size as f64, V_FACTOR);

        let step_rate = match_truncation_rate * bucket_truncation_rate;
        let overall_rate = step_rate.powi(i32::from(NUM_TABLES - 1));
        // Final lambda for each challenge (density after losses)
        let final_lambda_per_challenge = overall_rate;

        let num_challenges = Record::NUM_S_BUCKETS as f64;
        let prob_non_empty = 1.0 - (-final_lambda_per_challenge).exp();
        let expected_non_empty_count = num_challenges * prob_non_empty;

        // Chernoff lower tail: solve for delta where exp(-mu * delta^2 / 2) < 2^{-security_bits}
        let chernoff_inner = 2.0 * f64::from(security_bits) * LN_2 / expected_non_empty_count;
        let relative_deviation = chernoff_inner.sqrt();
        let lower_bound = expected_non_empty_count * (1.0 - relative_deviation);

        (lower_bound as i64).cast_unsigned()
    }

    /// Propagation rate for a truncation cap using the exact normal tail loss formula.
    /// Returns the fraction of entries retained after truncating at the cap, assuming a normal
    /// distribution.
    fn normal_rate_approx(mean: f64, cap: f64, variance_factor: f64) -> f64 {
        if cap >= mean + 10.0 * (variance_factor * mean).sqrt() {
            // Negligible loss for caps far above mean
            1.0
        } else if cap <= 0.0 {
            0.0
        } else {
            let sigma = (variance_factor * mean).sqrt();
            let z_score = (cap - mean) / sigma;
            if z_score <= -10.0 {
                // Cap far below mean: simple ratio
                cap / mean
            } else {
                let tail_prob = (z_score / SQRT_2).erfc() / 2.0;
                let density_at_z = (1.0 / (2.0 * PI).sqrt()) * (-z_score * z_score / 2.0).exp();
                let tail_loss = ((mean - cap) * tail_prob + sigma * density_at_z).max(0.0);
                1.0 - tail_loss / mean
            }
        }
    }

    // Ensure there are enough proofs found with overwhelming probability even for truncated
    // bucket size and number of matches.
    // TODO: LLM generated lower bound calculation formula, it may not be 100% correct, needs
    //  improvements.
    assert!(
        proofs_lower_bound(
            BUCKET_SIZE_UPPER_BOUND_SECURITY_BITS,
            REDUCED_MATCHES_COUNT,
            REDUCED_BUCKET_SIZE
        ) >= Record::NUM_CHUNKS as u64
    );
}
