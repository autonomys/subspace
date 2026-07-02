//! Proof of space that dispatches per sector between the old [`ChiaTable`] and the new
//! [`ChiaV2Table`], so one farm can mix them across the migration cutover.

use crate::chia::ChiaTable;
use crate::chia_v2::ChiaV2Table;
use crate::{PosTableType, Table, TableGenerator};
use subspace_core_primitives::pos::{PosProof, PosSeed};
use subspace_core_primitives::solutions::SolutionPotVerifier;

/// Proof of space table generator dispatching between the old and new Chia implementations.
#[derive(Debug, Clone)]
pub enum PosTableGenerator {
    /// Old (pre-cutover) implementation.
    V1(<ChiaTable as Table>::Generator),
    /// New (post-cutover) implementation.
    V2(<ChiaV2Table as Table>::Generator),
}

impl Default for PosTableGenerator {
    #[inline]
    fn default() -> Self {
        Self::V2(ChiaV2Table::generator())
    }
}

impl PosTableGenerator {
    /// Generator for a sector: the new implementation for post-cutover sectors, the old one
    /// otherwise.
    #[inline]
    pub fn new(is_post_cutover: bool) -> Self {
        if is_post_cutover {
            Self::V2(ChiaV2Table::generator())
        } else {
            Self::V1(ChiaTable::generator())
        }
    }
}

impl TableGenerator<PosTable> for PosTableGenerator {
    fn generate(&self, seed: &PosSeed) -> PosTable {
        match self {
            Self::V1(generator) => PosTable::V1(generator.generate(seed)),
            Self::V2(generator) => PosTable::V2(generator.generate(seed)),
        }
    }

    #[cfg(feature = "parallel")]
    fn generate_parallel(&self, seed: &PosSeed) -> PosTable {
        match self {
            Self::V1(generator) => PosTable::V1(generator.generate_parallel(seed)),
            Self::V2(generator) => PosTable::V2(generator.generate_parallel(seed)),
        }
    }
}

/// Proof of space table dispatching between the old and new Chia implementations.
#[derive(Debug)]
pub enum PosTable {
    /// Old (pre-cutover) implementation.
    V1(ChiaTable),
    /// New (post-cutover) implementation.
    V2(ChiaV2Table),
}

impl SolutionPotVerifier for PosTable {
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        // Both V1 and V2 proofs verify under ChiaTable.
        <ChiaTable as SolutionPotVerifier>::is_proof_valid(seed, challenge_index, proof)
    }
}

impl Table for PosTable {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;
    type Generator = PosTableGenerator;

    fn generator_for(is_post_cutover: bool) -> Self::Generator {
        PosTableGenerator::new(is_post_cutover)
    }

    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        match self {
            Self::V1(table) => table.find_proof(challenge_index),
            Self::V2(table) => table.find_proof(challenge_index),
        }
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <Self as SolutionPotVerifier>::is_proof_valid(seed, challenge_index, proof)
    }
}

#[cfg(test)]
mod tests;
