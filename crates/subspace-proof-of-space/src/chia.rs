//! Chia proof of space implementation

use crate::{Quality, Table};
use subspace_core_primitives::{PosProof, PosQualityBytes, PosSeed};

/// Abstraction that represents quality of the solution in the table.
///
/// Chia implementation.
#[derive(Debug)]
#[must_use]
pub struct ChiaQuality<'a> {
    quality: subspace_chiapos::Quality<'a>,
}

impl<'a> Quality for ChiaQuality<'a> {
    fn to_bytes(&self) -> PosQualityBytes {
        PosQualityBytes::from(self.quality.to_bytes())
    }

    fn create_proof(&self) -> PosProof {
        PosProof::from(self.quality.create_proof())
    }
}

/// Subspace proof of space table
///
/// Chia implementation.
#[derive(Debug)]
pub struct ChiaTable {
    table: subspace_chiapos::Table,
}

impl Table for ChiaTable {
    type Quality<'a> = ChiaQuality<'a>;

    fn generate(seed: &PosSeed) -> ChiaTable {
        Self {
            table: subspace_chiapos::Table::generate(seed),
        }
    }

    fn find_quality(&self, challenge_index: u32) -> Option<Self::Quality<'_>> {
        self.table
            .find_quality(challenge_index)
            .map(|quality| ChiaQuality { quality })
    }

    fn is_proof_valid(
        seed: &PosSeed,
        challenge_index: u32,
        proof: &PosProof,
    ) -> Option<PosQualityBytes> {
        subspace_chiapos::is_proof_valid(seed, challenge_index, proof).map(PosQualityBytes::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: PosSeed = PosSeed::from([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);

    #[test]
    fn basic() {
        let table = ChiaTable::generate(&SEED);

        assert!(table.find_quality(0).is_none());

        {
            let challenge_index = 1;
            let quality = table.find_quality(challenge_index).unwrap();
            let proof = quality.create_proof();
            let maybe_quality = ChiaTable::is_proof_valid(&SEED, challenge_index, &proof);
            assert_eq!(maybe_quality, Some(quality.to_bytes()));
        }
    }
}
