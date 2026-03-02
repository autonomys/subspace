//! `chiapos` tables tests.

#![cfg(not(miri))]

extern crate std;

use crate::chiapos::constants::PARAM_BC;
use crate::chiapos::{Tables, TablesCache};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const K: u8 = 17;

/// The original REDUCED_BUCKET_SIZE value from PR #3712 that caused bucket overflow.
/// Kept here to document and test that the fix resolves the issue.
const ORIGINAL_REDUCED_BUCKET_SIZE: usize = 272;

#[test]
fn self_verification() {
    let seed = [1; 32];
    let cache = TablesCache::default();
    let tables = Tables::<K>::create(seed, &cache);
    #[cfg(feature = "parallel")]
    let tables_parallel = Tables::<K>::create_parallel(seed, &cache);

    for challenge_index in 0..1000_u32 {
        let mut challenge = [0; 32];
        challenge[..size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());
        let first_challenge_bytes = challenge[..4].try_into().unwrap();
        let qualities = tables.find_quality(&challenge).collect::<Vec<_>>();
        #[cfg(feature = "parallel")]
        assert_eq!(
            qualities,
            tables_parallel.find_quality(&challenge).collect::<Vec<_>>()
        );
        let proofs = tables.find_proof(first_challenge_bytes).collect::<Vec<_>>();
        #[cfg(feature = "parallel")]
        assert_eq!(
            proofs,
            tables_parallel
                .find_proof(first_challenge_bytes)
                .collect::<Vec<_>>()
        );

        assert_eq!(qualities.len(), proofs.len());

        for (quality, proof) in qualities.into_iter().zip(&proofs) {
            assert_eq!(
                Some(quality),
                Tables::<K>::verify(&seed, &challenge, proof),
                "challenge index {challenge_index}"
            );
            let mut bad_challenge = [0; 32];
            bad_challenge[..size_of::<u32>()].copy_from_slice(&(challenge_index + 1).to_le_bytes());
            assert!(
                Tables::<K>::verify(&seed, &bad_challenge, proof).is_none(),
                "challenge index {challenge_index}"
            );
        }
    }
}

/// Analyzes bucket size distribution for table 1 Y values computed from a seed.
///
/// Generates all 2^K Y values via compute_f1 and groups them into buckets (Y / PARAM_BC).
/// Returns (num_buckets, max_bucket_size, num_exceeding_original, total_would_be_dropped).
fn analyze_f1_bucket_distribution<const K: u8>(seed: &[u8; 32]) -> (usize, usize, usize, usize) {
    use crate::chiapos::table::compute_f1;
    use crate::chiapos::table::types::X;

    let mut bucket_counts = BTreeMap::<u32, usize>::new();
    for x in 0..1u32 << K {
        let y = compute_f1::<K>(X::from(x), seed);
        let bucket_index = u32::from(y) / u32::from(PARAM_BC);
        *bucket_counts.entry(bucket_index).or_insert(0) += 1;
    }

    let num_buckets = bucket_counts.len();
    let max_bucket_size = bucket_counts.values().copied().max().unwrap_or(0);
    let num_exceeding = bucket_counts
        .values()
        .filter(|&&c| c > ORIGINAL_REDUCED_BUCKET_SIZE)
        .count();
    let total_dropped: usize = bucket_counts
        .values()
        .filter(|&&c| c > ORIGINAL_REDUCED_BUCKET_SIZE)
        .map(|&c| c - ORIGINAL_REDUCED_BUCKET_SIZE)
        .sum();

    (num_buckets, max_bucket_size, num_exceeding, total_dropped)
}

/// Verifies that the original REDUCED_BUCKET_SIZE=272 was too small.
///
/// This test generates f1 Y values and counts them per bucket. With the original
/// REDUCED_BUCKET_SIZE=272, many buckets would overflow and entries would be silently
/// dropped, causing "Missing PoS proof" errors in production.
///
/// Math: Expected bucket size = PARAM_BC / 2^PARAM_EXT ≈ 15113/64 ≈ 236.
/// With std dev ≈ sqrt(236) ≈ 15.4, 272 was only ~2.3 sigma above mean.
/// The current REDUCED_BUCKET_SIZE=MAX_BUCKET_SIZE=512 eliminates overflow entirely.
#[test]
fn original_bucket_size_was_insufficient() {
    let seed = [1; 32];
    let (num_buckets, max_size, num_overflow, total_dropped) =
        analyze_f1_bucket_distribution::<K>(&seed);
    std::eprintln!(
        "Table 1 (K={K}): {num_buckets} buckets, max_size={max_size}, \
         {num_overflow} exceed original {ORIGINAL_REDUCED_BUCKET_SIZE}, \
         {total_dropped} entries would have been dropped"
    );
    assert!(
        num_overflow > 0,
        "Expected at least one bucket to exceed the original \
         REDUCED_BUCKET_SIZE={ORIGINAL_REDUCED_BUCKET_SIZE}"
    );
}

/// Verifies the current REDUCED_BUCKET_SIZE (MAX_BUCKET_SIZE=512) has no overflow.
#[test]
fn current_bucket_size_has_no_overflow() {
    use crate::chiapos::table::REDUCED_BUCKET_SIZE;

    let seed = [1; 32];
    let (_, max_size, _, _) = analyze_f1_bucket_distribution::<K>(&seed);
    std::eprintln!("Table 1 (K={K}): max_bucket_size={max_size}, REDUCED_BUCKET_SIZE={REDUCED_BUCKET_SIZE}");
    assert!(
        max_size <= REDUCED_BUCKET_SIZE,
        "max bucket size {max_size} exceeds REDUCED_BUCKET_SIZE={REDUCED_BUCKET_SIZE}"
    );
}
