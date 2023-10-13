//! Chia proof of space implementation
use crate::chiapos::{Tables, TablesCache};
use crate::{PosTableType, Quality, Table, TableGenerator};
use core::mem;
use subspace_core_primitives::{PosProof, PosQualityBytes, PosSeed};

const K: u8 = 20;

/// Abstraction that represents quality of the solution in the table.
///
/// Chia implementation.
#[derive(Debug)]
#[must_use]
pub struct ChiaQuality<'a> {
    bytes: PosQualityBytes,
    challenge: [u8; 32],
    tables: &'a Tables<K>,
}

impl<'a> Quality for ChiaQuality<'a> {
    fn to_bytes(&self) -> PosQualityBytes {
        self.bytes
    }

    fn create_proof(&self) -> PosProof {
        self.tables
            .find_proof(&self.challenge)
            .next()
            .map(PosProof::from)
            .expect("Proof always exists if quality exists; qed")
    }
}

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

    type Quality<'a> = ChiaQuality<'a>;

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

    fn find_quality(&self, challenge_index: u32) -> Option<Self::Quality<'_>> {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());
        let maybe_quality = self.tables.find_quality(&challenge).next();
        maybe_quality.map(|quality| ChiaQuality {
            bytes: PosQualityBytes::from(quality),
            challenge,
            tables: &self.tables,
        })
    }

    fn is_proof_valid(
        seed: &PosSeed,
        challenge_index: u32,
        proof: &PosProof,
    ) -> Option<PosQualityBytes> {
        let mut challenge = [0; 32];
        challenge[..mem::size_of::<u32>()].copy_from_slice(&challenge_index.to_le_bytes());
        Tables::<K>::verify(**seed, &challenge, proof).map(PosQualityBytes::from)
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

        assert!(table.find_quality(1232460437).is_none());
        assert!(table_parallel.find_quality(1232460437).is_none());

        {
            let challenge_index = 600426542;
            let quality = table.find_quality(challenge_index).unwrap();
            assert_eq!(
                quality.to_bytes(),
                table_parallel
                    .find_quality(challenge_index)
                    .unwrap()
                    .to_bytes()
            );
            let proof = quality.create_proof();
            let maybe_quality = ChiaTable::is_proof_valid(&seed, challenge_index, &proof);
            assert_eq!(maybe_quality, Some(quality.to_bytes()));
        }
    }
}
