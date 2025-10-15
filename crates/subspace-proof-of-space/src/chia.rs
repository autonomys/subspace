//! Chia proof of space implementation
#[cfg(feature = "alloc")]
use crate::TableGenerator;
use crate::chiapos::Tables;
#[cfg(feature = "alloc")]
use crate::chiapos::TablesCache;
use crate::{PosTableType, Table};
use ab_core_primitives::pos::{PosProof, PosSeed};

const K: u8 = PosProof::K;

/// Proof of space table generator.
///
/// Chia implementation.
#[derive(Debug, Default, Clone)]
#[cfg(feature = "alloc")]
pub struct ChiaTableGenerator {
    tables_cache: TablesCache,
}

#[cfg(feature = "alloc")]
impl TableGenerator<ChiaTable> for ChiaTableGenerator {
    fn generate(&self, seed: &PosSeed) -> ChiaTable {
        ChiaTable {
            tables: Tables::<K>::create((*seed).into(), &self.tables_cache),
        }
    }

    #[cfg(feature = "parallel")]
    fn generate_parallel(&self, seed: &PosSeed) -> ChiaTable {
        ChiaTable {
            tables: Tables::<K>::create_parallel((*seed).into(), &self.tables_cache),
        }
    }
}

/// Proof of space table.
///
/// Chia implementation.
#[derive(Debug)]
pub struct ChiaTable {
    #[cfg(feature = "alloc")]
    tables: Tables<K>,
}

impl ab_core_primitives::solutions::SolutionPotVerifier for ChiaTable {
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        Tables::<K>::verify_only(seed, challenge_index.to_le_bytes(), proof)
    }
}

impl Table for ChiaTable {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;
    #[cfg(feature = "alloc")]
    type Generator = ChiaTableGenerator;

    #[cfg(feature = "alloc")]
    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        let first_challenge_bytes = challenge_index.to_le_bytes();

        self.tables
            .find_proof(first_challenge_bytes)
            .next()
            .map(PosProof::from)
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <Self as ab_core_primitives::solutions::SolutionPotVerifier>::is_proof_valid(
            seed,
            challenge_index,
            proof,
        )
    }
}

#[cfg(all(feature = "alloc", test))]
#[cfg(not(miri))]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let seed = PosSeed::from([
            35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
            198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
        ]);

        let generator = ChiaTableGenerator::default();
        let table = generator.generate(&seed);
        #[cfg(feature = "parallel")]
        let table_parallel = generator.generate_parallel(&seed);

        assert!(table.find_proof(1232460437).is_none());
        #[cfg(feature = "parallel")]
        assert!(table_parallel.find_proof(1232460437).is_none());

        {
            let challenge_index = 600426542;
            let proof = table.find_proof(challenge_index).unwrap();
            #[cfg(feature = "parallel")]
            assert_eq!(proof, table_parallel.find_proof(challenge_index).unwrap());
            assert!(ChiaTable::is_proof_valid(&seed, challenge_index, &proof));
        }
    }
}
