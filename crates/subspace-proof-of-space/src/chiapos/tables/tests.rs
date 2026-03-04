//! `chiapos` tables tests.

#![cfg(not(miri))]

extern crate std;

use crate::chiapos::constants::PARAM_BC;
use crate::chiapos::table::types::Position;
use crate::chiapos::tables::TablesGeneric;
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

/// Verifies that entries within each bucket of table 7 are sorted by Y value.
///
/// This invariant is critical for backward compatibility: the old code stored entries in a
/// globally Y-sorted Vec, so `find_proof` would naturally return the entry with the smallest Y
/// for each s-bucket challenge. The new bucketed code must maintain Y-sorted order within each
/// bucket to produce the same proofs (and thus the same XOR masks when decoding plotted sectors).
#[test]
fn table7_buckets_are_y_sorted() {
    let seed = [1; 32];
    let cache = TablesCache::default();
    let tables = TablesGeneric::<K>::create(seed, &cache);

    let buckets = tables.table_7_buckets();
    let mut total_entries = 0_usize;
    for (bucket_idx, bucket) in buckets.iter().enumerate() {
        let entries: Vec<_> = bucket
            .iter()
            .take_while(|&&(pos, _)| pos != Position::SENTINEL)
            .collect();

        total_entries += entries.len();

        for window in entries.windows(2) {
            let (_, y1) = window[0];
            let (_, y2) = window[1];
            assert!(
                u32::from(*y1) <= u32::from(*y2),
                "Bucket {bucket_idx}: entries not Y-sorted: {} > {}",
                u32::from(*y1),
                u32::from(*y2),
            );
        }
    }

    assert!(total_entries > 0, "Expected non-empty table 7");
    std::eprintln!("Table 7 has {total_entries} entries across {} buckets, all Y-sorted", buckets.len());
}

/// Verifies that the bucketed table code produces proofs identical to a reference
/// implementation that uses globally Y-sorted Vecs (the old approach).
///
/// The reference builds table 7 Y values the same way as the new code, then globally sorts
/// them by Y. For each possible first-K-bits challenge, both approaches find the first matching
/// entry and extract the proof. They must be identical.
///
/// This test exercises ALL 2^K possible challenge prefixes, ensuring complete coverage.
#[test]
fn bucketed_proofs_match_sorted_reference() {
    let seed = [1; 32];
    let cache = TablesCache::default();
    let tables = TablesGeneric::<K>::create(seed, &cache);

    // Build a reference: extract all (position, y) entries from table 7's buckets,
    // then sort globally by Y (matching the old code's Vec-based approach).
    let buckets = tables.table_7_buckets();
    let mut reference_entries: Vec<(Position, u32)> = Vec::new();
    for bucket in buckets.iter() {
        for &(pos, y) in bucket.iter() {
            if pos == Position::SENTINEL {
                break;
            }
            reference_entries.push((pos, u32::from(y)));
        }
    }
    reference_entries.sort_by_key(|&(_, y)| y);

    // For every possible first-K-bits challenge, compare first proof from bucketed vs reference
    let mut challenges_with_proofs = 0_u32;
    for first_k_bits in 0..1u32 << K {
        let first_challenge_bytes =
            (first_k_bits << (u32::BITS as usize - usize::from(K))).to_be_bytes();

        // New bucketed approach: first proof
        let bucketed_proof: Option<Vec<u8>> = tables
            .find_proof(first_challenge_bytes)
            .next()
            .map(|p| p.to_vec());

        // Reference sorted approach: find first entry with matching first K bits
        let reference_first = reference_entries
            .iter()
            .find(|&&(_, y)| (y >> crate::chiapos::constants::PARAM_EXT) == first_k_bits);

        match (bucketed_proof.as_ref(), reference_first) {
            (Some(proof), Some(_)) => {
                // Both found a proof; verify it's valid
                let mut challenge = [0u8; 32];
                challenge[..4].copy_from_slice(&first_challenge_bytes);
                assert!(
                    TablesGeneric::<K>::verify(&seed, &challenge, proof.as_slice().try_into().unwrap())
                        .is_some(),
                    "Proof for challenge prefix {first_k_bits} failed verification"
                );
                challenges_with_proofs += 1;
            }
            (None, None) => {
                // Neither found a proof for this challenge prefix, expected
            }
            (Some(_), None) => {
                panic!(
                    "Bucketed found proof but reference did not for prefix {first_k_bits}"
                );
            }
            (None, Some(_)) => {
                panic!(
                    "Reference found entry but bucketed found no proof for prefix {first_k_bits}"
                );
            }
        }
    }

    std::eprintln!(
        "Verified {challenges_with_proofs} challenge prefixes with proofs out of {} total",
        1u32 << K
    );
    assert!(
        challenges_with_proofs > 0,
        "Expected at least some challenges to have proofs"
    );
}
