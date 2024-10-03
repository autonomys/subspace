//! Shim proof of space implementation that works much faster than Chia and can be used for testing
//! purposes to reduce memory and CPU usage

use crate::{PosTableType, Table, TableGenerator};
use core::iter;
use subspace_core_primitives::hashes::blake3_hash;
use subspace_core_primitives::pos::{PosProof, PosSeed};
use subspace_core_primitives::U256;

/// Subspace proof of space table generator.
///
/// Shim implementation.
#[derive(Debug, Default, Clone)]
pub struct ShimTableGenerator;

impl TableGenerator<ShimTable> for ShimTableGenerator {
    fn generate(&mut self, seed: &PosSeed) -> ShimTable {
        ShimTable::generate(seed)
    }
}

/// Subspace proof of space table.
///
/// Shim implementation.
#[derive(Debug)]
pub struct ShimTable {
    seed: PosSeed,
}

impl Table for ShimTable {
    const TABLE_TYPE: PosTableType = PosTableType::Shim;
    type Generator = ShimTableGenerator;
    fn generate(seed: &PosSeed) -> ShimTable {
        Self { seed: *seed }
    }

    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        find_proof(&self.seed, challenge_index)
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        let Some(correct_proof) = find_proof(seed, challenge_index) else {
            return false;
        };

        &correct_proof == proof
    }
}

fn find_proof(seed: &PosSeed, challenge_index: u32) -> Option<PosProof> {
    let quality = blake3_hash(&challenge_index.to_le_bytes());
    if U256::from_le_bytes(*quality) % U256::from(3u32) > U256::zero() {
        let mut proof = PosProof::default();
        proof
            .iter_mut()
            .zip(seed.iter().chain(iter::repeat(quality.iter()).flatten()))
            .for_each(|(output, input)| {
                *output = *input;
            });

        Some(proof)
    } else {
        None
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

        let table = ShimTable::generate(&seed);

        assert!(table.find_proof(0).is_none());

        {
            let challenge_index = 2;
            let proof = table.find_proof(challenge_index).unwrap();
            assert!(ShimTable::is_proof_valid(&seed, challenge_index, &proof));
        }
    }
}
