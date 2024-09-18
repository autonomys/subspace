use crate::chiapos::{Seed, Tables};
use std::mem;

const K: u8 = 17;

/// Chia does this for some reason 🤷‍
fn to_chia_seed(seed: &Seed) -> Seed {
    let mut chia_seed = [1u8; 32];
    chia_seed[1..].copy_from_slice(&seed[..31]);
    chia_seed
}

#[test]
fn test_against_chiapos() {
    let seed = [1; 32];
    let original_table = subspace_chiapos::Table::generate(&seed);
    let chia_seed = to_chia_seed(&seed);
    let tables = Tables::<K>::create_simple(chia_seed);

    for challenge_index in (0..1u32 << 16).map(|_| rand::random::<u32>()) {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());

        let maybe_original_proof = original_table
            .find_quality(challenge_index)
            .map(|quality| quality.create_proof());

        {
            let found_proofs = tables.find_proof(&challenge).collect::<Vec<_>>();

            // Due to bugs (https://github.com/Chia-Network/chiapos/issues/352) in C++ chiapos doesn't
            // find as many proofs, and they are in different order due to compression, so we just
            // verify reference proofs with our verification function
            if let Some(original_proof) = maybe_original_proof {
                assert!(Tables::<K>::verify(chia_seed, &challenge, &original_proof).is_some());

                assert!(!found_proofs.is_empty());
            }

            // All the proofs we produce must be valid according to C++ chiapos as well, even those that
            // C++ chiapos can't find after compression
            for proof in &found_proofs {
                assert!(subspace_chiapos::is_proof_valid(&seed, challenge_index, proof).is_some());
            }
        }
    }
}
