//! Chia proof of space implementation
use crate::chiapos::{Tables, TablesCache};
use crate::{PosTableType, Table, TableGenerator};
use core::mem;
use subspace_core_primitives::pos::{PosProof, PosSeed};

const K: u8 = PosProof::K;

/// Subspace proof of space table generator.
///
/// Chia implementation.
#[derive(Debug, Default, Clone)]
pub struct ChiaTableGenerator {
    tables_cache: TablesCache<K>,
}

impl TableGenerator<ChiaTable> for ChiaTableGenerator {
    fn generate(&mut self, seed: &PosSeed) -> ChiaTable {
        ChiaTable {
            tables: Tables::<K>::create((*seed).into(), &mut self.tables_cache),
        }
    }

    #[cfg(any(feature = "parallel", test))]
    fn generate_parallel(&mut self, seed: &PosSeed) -> ChiaTable {
        ChiaTable {
            tables: Tables::<K>::create_parallel((*seed).into(), &mut self.tables_cache),
        }
    }
}

/// Subspace proof of space table.
///
/// Chia implementation.
#[derive(Debug)]
pub struct ChiaTable {
    tables: Tables<K>,
}

impl Table for ChiaTable {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;
    type Generator = ChiaTableGenerator;

    fn generate(seed: &PosSeed) -> ChiaTable {
        Self {
            tables: Tables::<K>::create_simple((*seed).into()),
        }
    }

    #[cfg(any(feature = "parallel", test))]
    fn generate_parallel(seed: &PosSeed) -> ChiaTable {
        Self {
            tables: Tables::<K>::create_parallel((*seed).into(), &mut TablesCache::default()),
        }
    }

    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());

        let proof = self
            .tables
            .find_proof(&challenge)
            .next()
            .map(PosProof::from);
        proof
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());
        Tables::<K>::verify(**seed, &challenge, proof).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let seed = PosSeed::from([
            35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
            198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
        ]);

        let table = ChiaTable::generate(&seed);
        let table_parallel = ChiaTable::generate_parallel(&seed);

        assert!(table.find_proof(1232460437).is_none());
        assert!(table_parallel.find_proof(1232460437).is_none());

        {
            let challenge_index = 600426542;
            let proof = table.find_proof(challenge_index).unwrap();
            assert_eq!(proof, table_parallel.find_proof(challenge_index).unwrap());
            assert!(ChiaTable::is_proof_valid(&seed, challenge_index, &proof));
        }
    }
}
