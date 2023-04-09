//! Shim proof of space implementation

use crate::{Quality, Table};
use core::iter;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{Blake2b256Hash, PosProof, PosQualityBytes, PosSeed, U256};

/// Abstraction that represents quality of the solution in the table.
///
/// Shim implementation.
#[derive(Debug)]
#[must_use]
pub struct ShimQuality<'a> {
    seed: &'a PosSeed,
    quality: Blake2b256Hash,
}

impl<'a> Quality for ShimQuality<'a> {
    fn to_bytes(&self) -> PosQualityBytes {
        PosQualityBytes::from(self.quality)
    }

    fn create_proof(&self) -> PosProof {
        let mut proof = PosProof::default();
        proof
            .iter_mut()
            .zip(
                self.seed
                    .iter()
                    .chain(iter::repeat(self.quality.iter()).flatten()),
            )
            .for_each(|(output, input)| {
                *output = *input;
            });
        proof
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
    type Quality<'a> = ShimQuality<'a>;

    fn generate(seed: &PosSeed) -> ShimTable {
        Self { seed: *seed }
    }

    fn find_quality(&self, challenge_index: u32) -> Option<Self::Quality<'_>> {
        find_quality(&self.seed, challenge_index)
    }

    fn is_proof_valid(
        seed: &PosSeed,
        challenge_index: u32,
        proof: &PosProof,
    ) -> Option<PosQualityBytes> {
        let quality = find_quality(seed, challenge_index)?;

        proof[..seed.len()]
            .iter()
            .zip(
                seed.iter()
                    .chain(iter::repeat(quality.quality.iter()).flatten()),
            )
            .all(|(a, b)| a == b)
            .then_some(PosQualityBytes::from(quality.quality))
    }
}

fn find_quality(seed: &PosSeed, challenge_index: u32) -> Option<ShimQuality<'_>> {
    let quality = blake2b_256_hash(&challenge_index.to_le_bytes());
    (U256::from_le_bytes(quality) % U256::from(3u32) > U256::zero())
        .then_some(ShimQuality { seed, quality })
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
        let table = ShimTable::generate(&SEED);

        assert!(table.find_quality(0).is_none());

        {
            let challenge_index = 2;
            let quality = table.find_quality(challenge_index).unwrap();
            let proof = quality.create_proof();
            let maybe_quality = ShimTable::is_proof_valid(&SEED, challenge_index, &proof);
            assert_eq!(maybe_quality, Some(quality.to_bytes()));
        }
    }
}
