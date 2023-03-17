//! Subspace proof of space implementation based on Chia
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

use subspace_core_primitives::{PosProof, PosQualityBytes, PosSeed};

/// Abstraction that represents quality of the solution in the table
#[derive(Debug)]
#[must_use]
pub struct Quality<'a> {
    quality: subspace_chiapos::Quality<'a>,
}

impl<'a> Quality<'a> {
    /// Get underlying bytes representation of the quality
    pub fn to_bytes(&self) -> PosQualityBytes {
        PosQualityBytes(self.quality.to_bytes())
    }

    /// Create proof for this solution
    pub fn create_proof(&self) -> PosProof {
        PosProof(self.quality.create_proof())
    }
}

/// Subspace proof of space table
#[derive(Debug)]
pub struct Table {
    table: subspace_chiapos::Table,
}

impl Table {
    /// Generate new table with 32 bytes seed
    pub fn generate(seed: &PosSeed) -> Table {
        Self {
            table: subspace_chiapos::Table::generate(seed),
        }
    }

    /// Try to find quality of the proof at `challenge_index` if proof exists
    pub fn find_quality(&self, challenge_index: u32) -> Option<Quality<'_>> {
        self.table
            .find_quality(challenge_index)
            .map(|quality| Quality { quality })
    }
}

/// Check whether proof created earlier is valid
pub fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
    subspace_chiapos::is_proof_valid(seed, challenge_index, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: PosSeed = PosSeed([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);

    #[test]
    fn basic() {
        let table = Table::generate(&SEED);

        assert!(table.find_quality(0).is_none());

        {
            let challenge_index = 1;
            let quality = table.find_quality(challenge_index).unwrap();
            let proof = quality.create_proof();
            assert!(is_proof_valid(&SEED, challenge_index, &proof));
        }
    }
}
