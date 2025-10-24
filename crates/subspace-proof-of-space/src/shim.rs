//! Shim proof of space implementation that works much faster than Chia and can be used for testing
//! purposes to reduce memory and CPU usage

#[cfg(feature = "alloc")]
use crate::TableGenerator;
use crate::{PosTableType, Table};
use core::iter;
use subspace_core_primitives::U256;
use subspace_core_primitives::hashes::blake3_hash;
use subspace_core_primitives::pos::{PosProof, PosSeed};

/// Proof of space table generator.
///
/// Shim implementation.
#[derive(Debug, Default, Clone)]
#[cfg(feature = "alloc")]
pub struct ShimTableGenerator;

#[cfg(feature = "alloc")]
impl TableGenerator<ShimTable> for ShimTableGenerator {
    fn generate(&self, seed: &PosSeed) -> ShimTable {
        ShimTable { seed: *seed }
    }
}

/// Proof of space table.
///
/// Shim implementation.
#[derive(Debug)]
pub struct ShimTable {
    #[cfg(feature = "alloc")]
    seed: PosSeed,
}

impl subspace_core_primitives::solutions::SolutionPotVerifier for ShimTable {
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        let Some(correct_proof) = find_proof(seed, challenge_index) else {
            return false;
        };

        &correct_proof == proof
    }
}

impl Table for ShimTable {
    const TABLE_TYPE: PosTableType = PosTableType::Shim;
    #[cfg(feature = "alloc")]
    type Generator = ShimTableGenerator;

    #[cfg(feature = "alloc")]
    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        find_proof(&self.seed, challenge_index)
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <Self as subspace_core_primitives::solutions::SolutionPotVerifier>::is_proof_valid(
            seed,
            challenge_index,
            proof,
        )
    }
}

fn find_proof(seed: &PosSeed, challenge_index: u32) -> Option<PosProof> {
    let quality = blake3_hash(&challenge_index.to_le_bytes());
    // Note: this is different to the ab-proof-of-space ShimTable implementation
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

#[cfg(all(feature = "alloc", test))]
mod tests {
    use super::*;
    use hex::FromHex;

    type RawProof = [u8; PosProof::SIZE];

    #[test]
    fn basic() {
        let seed = PosSeed::from([
            35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
            198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
        ]);

        let table = ShimTable::generator().generate(&seed);

        let expected_results = [
            (0, None),
            (
                1,
                Some(PosProof::from(
                    RawProof::from_hex(
                        "23023404333717545b0a6f0c0dde9710e4d3fe2d5cc6cc0a090a0b818bab0f17c610e85212d0697cb161d4ba431ba603f273feee7dcb7927c9ff5d74ae6cbfa3c610e85212d0697cb161d4ba431ba603f273feee7dcb7927c9ff5d74ae6cbfa3c610e85212d0697cb161d4ba431ba603f273feee7dcb7927c9ff5d74ae6cbfa3c610e85212d0697cb161d4ba431ba603f273feee7dcb7927c9ff5d74ae6cbfa3",
                    )
                    .unwrap(),
                )),
            ),
            (2, Some(PosProof::from(
                RawProof::from_hex(
                    "23023404333717545b0a6f0c0dde9710e4d3fe2d5cc6cc0a090a0b818bab0f17f03bf86f79d121cbfd774dec4a65912e99f5f17c33852bbc45e819160e62b53bf03bf86f79d121cbfd774dec4a65912e99f5f17c33852bbc45e819160e62b53bf03bf86f79d121cbfd774dec4a65912e99f5f17c33852bbc45e819160e62b53bf03bf86f79d121cbfd774dec4a65912e99f5f17c33852bbc45e819160e62b53b",
                )
                .unwrap(),
            ))),
            (3, None),
            (4, Some(PosProof::from(
                RawProof::from_hex(
                    "23023404333717545b0a6f0c0dde9710e4d3fe2d5cc6cc0a090a0b818bab0f17669c13550a3e727bb53d0d458f2e96e48571aa045dfabcfb4b7de16809484f11669c13550a3e727bb53d0d458f2e96e48571aa045dfabcfb4b7de16809484f11669c13550a3e727bb53d0d458f2e96e48571aa045dfabcfb4b7de16809484f11669c13550a3e727bb53d0d458f2e96e48571aa045dfabcfb4b7de16809484f11",
                )
                .unwrap(),
            ))),
            (5, Some(PosProof::from(
                RawProof::from_hex(
                    "23023404333717545b0a6f0c0dde9710e4d3fe2d5cc6cc0a090a0b818bab0f17e84248fb50d0833361d0417df114b0b3b34408fff97c39cd0de963b09a9aebb8e84248fb50d0833361d0417df114b0b3b34408fff97c39cd0de963b09a9aebb8e84248fb50d0833361d0417df114b0b3b34408fff97c39cd0de963b09a9aebb8e84248fb50d0833361d0417df114b0b3b34408fff97c39cd0de963b09a9aebb8",
                )
                .unwrap(),
            ))),
            (6, Some(PosProof::from(
                RawProof::from_hex(
                    "23023404333717545b0a6f0c0dde9710e4d3fe2d5cc6cc0a090a0b818bab0f17edaf1bd3d1c2ffcc44df55829c002f262426de2ffbea9be2cdf0075ec12c528dedaf1bd3d1c2ffcc44df55829c002f262426de2ffbea9be2cdf0075ec12c528dedaf1bd3d1c2ffcc44df55829c002f262426de2ffbea9be2cdf0075ec12c528dedaf1bd3d1c2ffcc44df55829c002f262426de2ffbea9be2cdf0075ec12c528d",
                )
                .unwrap(),
            ))),
            (7, None),
        ];

        for (challenge_index, expected_proof) in expected_results {
            let proof = table.find_proof(challenge_index);
            assert_eq!(
                proof, expected_proof,
                "proof mismatch for challenge_index: {challenge_index}",
            );

            if let Some(proof) = proof {
                assert!(
                    ShimTable::is_proof_valid(&seed, challenge_index, &proof),
                    "proof is not valid for challenge_index: {challenge_index}",
                );
            }
        }
    }
}
