use crate::chia::ChiaTable;
use crate::chia_v2::ChiaV2TableGenerator;
use crate::{Table, TableGenerator};
use subspace_core_primitives::pos::PosSeed;
use subspace_core_primitives::sectors::SBucket;

// Every abundance-backed proof must verify under ChiaTable::is_proof_valid.
#[test]
fn proofs_verify_under_consensus() {
    let generator = ChiaV2TableGenerator::default();

    for seed_byte in 0..3u8 {
        let seed = PosSeed::from([seed_byte; 32]);
        let table = generator.generate(&seed);

        let mut verified = 0u32;
        for s_bucket in u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX) {
            if let Some(proof) = table.find_proof(u32::from(s_bucket)) {
                assert!(
                    ChiaTable::is_proof_valid(&seed, u32::from(s_bucket), &proof),
                    "seed {seed_byte}: proof for s-bucket {s_bucket} rejected by the consensus \
                     verifier"
                );
                verified += 1;
            }
        }
        assert!(verified > 0, "seed {seed_byte}: no proofs produced");
    }
}
