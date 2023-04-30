//! Chia proof of space implementation
use crate::chiapos::Tables;
use crate::{PosTableType, Quality, Table};
use core::mem;
use subspace_core_primitives::{PosProof, PosQualityBytes, PosSeed};

const K: u8 = 17;

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

/// Subspace proof of space table
///
/// Chia implementation.
#[derive(Debug)]
pub struct ChiaTable {
    tables: Tables<K>,
}

impl Table for ChiaTable {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;

    type Quality<'a> = ChiaQuality<'a>;

    fn generate(seed: &PosSeed) -> ChiaTable {
        Self {
            tables: Tables::<K>::create_simple((*seed).into()),
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

    const SEED: PosSeed = PosSeed::from([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);

    #[test]
    fn basic() {
        let table = ChiaTable::generate(&SEED);

        assert!(table.find_quality(1232460437).is_none());

        {
            let challenge_index = 124537303;
            let quality = table.find_quality(challenge_index).unwrap();
            let proof = quality.create_proof();
            let maybe_quality = ChiaTable::is_proof_valid(&SEED, challenge_index, &proof);
            assert_eq!(maybe_quality, Some(quality.to_bytes()));
        }
    }
}
