//! Chia proof of space backed by abundance's `ab-proof-of-space`.
//!
//! Proofs are looked up under Subspace's s-bucket convention, so they verify under the existing
//! [`ChiaTable`] verifier.

use crate::chia::ChiaTable;
use crate::{PosTableType, Table, TableGenerator};
use ab_proof_of_space::chiapos::{Tables, TablesCache};
use subspace_core_primitives::pos::{PosProof, PosSeed};
use subspace_core_primitives::solutions::SolutionPotVerifier;

const K: u8 = PosProof::K;

/// Proof of space table generator.
///
/// Chia implementation.
#[derive(Debug, Default, Clone)]
pub struct ChiaV2TableGenerator {
    tables_cache: TablesCache,
}

impl TableGenerator<ChiaV2Table> for ChiaV2TableGenerator {
    fn generate(&self, seed: &PosSeed) -> ChiaV2Table {
        ChiaV2Table {
            tables: Tables::<K>::create((*seed).into(), &self.tables_cache),
        }
    }

    #[cfg(feature = "parallel")]
    fn generate_parallel(&self, seed: &PosSeed) -> ChiaV2Table {
        ChiaV2Table {
            tables: Tables::<K>::create_parallel((*seed).into(), &self.tables_cache),
        }
    }
}

/// Proof of space table.
///
/// Chia implementation.
#[derive(Debug)]
pub struct ChiaV2Table {
    tables: Tables<K>,
}

impl SolutionPotVerifier for ChiaV2Table {
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <ChiaTable as SolutionPotVerifier>::is_proof_valid(seed, challenge_index, proof)
    }
}

impl Table for ChiaV2Table {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;
    type Generator = ChiaV2TableGenerator;

    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        self.tables
            .find_proof(challenge_index.to_le_bytes())
            .next()
            .map(PosProof::from)
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <Self as SolutionPotVerifier>::is_proof_valid(seed, challenge_index, proof)
    }
}
