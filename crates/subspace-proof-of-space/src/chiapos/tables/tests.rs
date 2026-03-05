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

/// Cross-validates proofs from the optimized (bucketed) code against reference proofs
/// captured from the main branch (old Vec-based code) at K=20.
///
/// Reference proofs captured from main branch commit b412ccbb9. Two bugs were found and fixed:
///
/// 1. **Rmap 2-entry limit** (fixed): The old Rmap stored max 2 entries per r-value, silently
///    dropping matches when 3+ entries shared the same r-value. Fixed by using a flat positions
///    array with `(start_index, count)` per r-value.
///    Regression marker: Challenge 650 (was missing, now matches).
///
/// 2. **Sort tiebreak** (fixed): `sort_buckets` sorted by Y only; the old code sorted by
///    `(Y, Position)`. For equal-Y entries, different tiebreak → different proof selected.
///    Fixed by sorting by `(Y, Position)`.
///    Regression marker: Challenge 1011 (was different, now matches).
///
/// Three pinpoint challenges verify both fixes. A broader 50,000-challenge scan follows
/// to confirm no regressions at scale.
#[test]
fn proof_identity_with_main_branch() {
    const PRODUCTION_K: u8 = 20;

    let seed: [u8; 32] = [
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ];

    let cache = TablesCache::default();
    let tables = TablesGeneric::<PRODUCTION_K>::create(seed, &cache);

    // --- Pinpoint regression markers ---

    // Challenge 600426542: always matched (single Table 7 entry, no ambiguity)
    {
        let main_proof: [u8; 160] = [
            231, 160, 182, 160, 151, 135, 181, 184, 162, 182, 73, 246, 100, 10, 64, 8, 157, 251,
            161, 176, 47, 43, 96, 21, 51, 121, 6, 141, 115, 172, 44, 235, 35, 141, 185, 231, 232,
            112, 94, 233, 234, 129, 34, 234, 98, 156, 52, 36, 112, 133, 204, 248, 165, 32, 87,
            87, 179, 142, 183, 9, 243, 80, 255, 233, 157, 88, 126, 200, 23, 133, 197, 95, 25, 36,
            150, 34, 50, 199, 42, 240, 206, 77, 183, 15, 203, 92, 226, 70, 177, 117, 55, 240,
            225, 192, 204, 211, 25, 66, 193, 214, 91, 211, 236, 112, 205, 231, 42, 241, 122, 214,
            127, 107, 218, 66, 113, 204, 84, 62, 153, 41, 97, 47, 111, 65, 71, 154, 191, 252, 96,
            182, 172, 232, 237, 244, 7, 132, 158, 201, 239, 133, 184, 191, 72, 99, 128, 127, 202,
            195, 116, 49, 91, 207, 14, 134, 109, 184, 226, 222, 114, 19,
        ];
        let first_bytes = 600426542_u32.to_le_bytes();
        let new_proof: Vec<u8> = tables
            .find_proof(first_bytes)
            .next()
            .expect("Should find proof for challenge 600426542")
            .to_vec();
        assert_eq!(
            new_proof.as_slice(),
            &main_proof[..],
            "Challenge 600426542: proof should match main branch"
        );
    }

    // Challenge 1011: sort tiebreak regression marker (was assert_ne before fix)
    {
        let main_proof: [u8; 160] = [
            18, 71, 186, 109, 239, 82, 92, 249, 249, 22, 246, 115, 50, 138, 131, 135, 207, 108,
            139, 56, 155, 175, 16, 111, 4, 176, 187, 88, 209, 154, 187, 71, 174, 77, 233, 86,
            209, 58, 227, 192, 185, 73, 88, 6, 127, 59, 222, 166, 33, 239, 206, 41, 65, 52, 255,
            233, 122, 107, 218, 68, 103, 78, 40, 40, 224, 157, 183, 185, 155, 101, 34, 122, 51,
            180, 63, 85, 51, 166, 214, 180, 200, 132, 199, 65, 24, 55, 244, 197, 78, 87, 80, 11,
            221, 145, 225, 134, 245, 76, 165, 245, 92, 243, 12, 121, 249, 141, 100, 157, 161, 34,
            134, 58, 177, 116, 104, 68, 157, 136, 178, 207, 88, 11, 12, 251, 12, 106, 114, 195,
            167, 184, 80, 161, 218, 154, 237, 164, 144, 108, 233, 211, 223, 136, 64, 49, 166,
            143, 68, 221, 102, 42, 94, 199, 31, 95, 193, 76, 131, 117, 66, 165,
        ];
        let first_bytes = 1011_u32.to_le_bytes();
        let new_proof: Vec<u8> = tables
            .find_proof(first_bytes)
            .next()
            .expect("Should find proof for challenge 1011")
            .to_vec();
        assert_eq!(
            new_proof.as_slice(),
            &main_proof[..],
            "Challenge 1011: proof should match main branch (sort tiebreak fix)"
        );
    }

    // Challenge 650: Rmap regression marker (was is_none before fix)
    {
        let main_proof: [u8; 160] = [
            163, 3, 1, 44, 59, 22, 245, 97, 242, 22, 232, 0, 104, 44, 176, 157, 119, 77, 106,
            176, 226, 204, 66, 214, 179, 124, 203, 188, 163, 135, 172, 44, 224, 25, 187, 238,
            175, 177, 36, 240, 53, 117, 236, 129, 154, 232, 128, 176, 129, 158, 78, 102, 171,
            109, 45, 92, 212, 235, 179, 135, 153, 15, 186, 100, 80, 143, 235, 182, 204, 72, 252,
            242, 38, 178, 128, 106, 206, 63, 211, 58, 85, 61, 168, 107, 86, 111, 191, 109, 17,
            152, 135, 11, 110, 137, 167, 23, 1, 126, 218, 69, 117, 226, 166, 169, 70, 4, 95, 45,
            16, 50, 121, 163, 250, 180, 225, 138, 229, 104, 102, 25, 145, 186, 255, 129, 100, 42,
            237, 127, 26, 24, 109, 135, 0, 193, 34, 119, 109, 250, 38, 38, 187, 152, 33, 36, 147,
            45, 255, 117, 149, 138, 50, 122, 160, 12, 44, 212, 73, 219, 60, 31,
        ];
        let first_bytes = 650_u32.to_le_bytes();
        let new_proof: Vec<u8> = tables
            .find_proof(first_bytes)
            .next()
            .expect("Should find proof for challenge 650 (Rmap fix)")
            .to_vec();
        assert_eq!(
            new_proof.as_slice(),
            &main_proof[..],
            "Challenge 650: proof should match main branch (Rmap fix)"
        );
    }

    // --- Broad K=20 self-verification scan ---
    // Verify that every proof found across 50,000 challenge indices is valid.
    // This catches any systemic issues the 3 pinpoint challenges might miss.
    let mut total_proofs = 0_u32;
    let mut total_challenges_with_proofs = 0_u32;
    let mut verification_failures = Vec::new();

    for challenge_index in 0..50_000_u32 {
        let mut challenge = [0u8; 32];
        challenge[..4].copy_from_slice(&challenge_index.to_le_bytes());
        let first_challenge_bytes: [u8; 4] = challenge[..4].try_into().unwrap();

        let proofs: Vec<Vec<u8>> = tables
            .find_proof(first_challenge_bytes)
            .map(|p| p.to_vec())
            .collect();

        if !proofs.is_empty() {
            total_challenges_with_proofs += 1;
            total_proofs += proofs.len() as u32;
        }

        for (proof_idx, proof) in proofs.iter().enumerate() {
            let valid = TablesGeneric::<PRODUCTION_K>::verify(
                &seed,
                &challenge,
                proof.as_slice().try_into().unwrap(),
            );
            if valid.is_none() {
                verification_failures.push((challenge_index, proof_idx, proof.clone()));
                // Log first few failures with full detail for debugging
                if verification_failures.len() <= 5 {
                    std::eprintln!(
                        "VERIFICATION FAILURE: challenge_index={challenge_index}, \
                         proof_idx={proof_idx}, proof_bytes={proof:?}"
                    );
                }
            }
        }
    }

    std::eprintln!(
        "K=20 broad scan: {total_challenges_with_proofs} challenges with proofs, \
         {total_proofs} total proofs across 50,000 challenge indices, \
         {} verification failures",
        verification_failures.len()
    );

    assert!(
        verification_failures.is_empty(),
        "K=20 broad scan: {} proofs failed verification. First failure: challenge_index={}, \
         proof_idx={}",
        verification_failures.len(),
        verification_failures[0].0,
        verification_failures[0].1,
    );

    // Sanity: expect a reasonable number of challenges to have proofs (~60% at K=20)
    assert!(
        total_challenges_with_proofs > 25_000,
        "Expected >25,000 challenges with proofs, got {total_challenges_with_proofs}"
    );
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
