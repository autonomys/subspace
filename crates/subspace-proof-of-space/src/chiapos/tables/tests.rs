use crate::chiapos::{Tables, TablesCache};
use std::mem;

const K: u8 = 17;

#[test]
fn self_verification() {
    let seed = [1; 32];
    let tables = Tables::<K>::create_simple(seed);
    let tables_parallel = Tables::<K>::create_parallel(seed, &mut TablesCache::default());

    for challenge_index in 0..1000_u32 {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());
        let qualities = tables.find_quality(&challenge).collect::<Vec<_>>();
        assert_eq!(
            qualities,
            tables_parallel.find_quality(&challenge).collect::<Vec<_>>()
        );
        let proofs = tables.find_proof(&challenge).collect::<Vec<_>>();
        assert_eq!(
            proofs,
            tables_parallel.find_proof(&challenge).collect::<Vec<_>>()
        );

        assert_eq!(qualities.len(), proofs.len());

        for (quality, proof) in qualities.into_iter().zip(&proofs) {
            assert_eq!(
                Some(quality),
                Tables::<K>::verify(seed, &challenge, proof),
                "challenge index {challenge_index}"
            );
            let mut bad_challenge = [0; 32];
            bad_challenge[..mem::size_of::<u32>()]
                .copy_from_slice(&(challenge_index + 1).to_le_bytes());
            assert!(
                Tables::<K>::verify(seed, &bad_challenge, proof).is_none(),
                "challenge index {challenge_index}"
            );
        }
    }
}
