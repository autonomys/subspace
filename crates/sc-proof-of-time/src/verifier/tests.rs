use crate::verifier::PotVerifier;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{PotNextSlotInput, PotParametersChange};
use std::mem;
use std::num::{NonZeroU32, NonZeroUsize};
use subspace_core_primitives::{Blake3Hash, PotSeed};

const SEED: [u8; 16] = [
    0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1, 0x3a,
];

#[tokio::test]
async fn test_basic() {
    let genesis_seed = PotSeed::from(SEED);
    let slot_iterations = NonZeroU32::new(512).unwrap();
    let checkpoints_1 = subspace_proof_of_time::prove(genesis_seed, slot_iterations).unwrap();

    let verifier = PotVerifier::new(genesis_seed, NonZeroUsize::new(1000).unwrap());

    // Expected to be valid
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: genesis_seed,
                },
                Slot::from(1),
                checkpoints_1.output(),
                None
            )
            .await
    );
    assert!(
        verifier
            .verify_checkpoints(genesis_seed, slot_iterations, &checkpoints_1)
            .await
    );

    // Invalid number of slots
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: genesis_seed,
                },
                Slot::from(2),
                checkpoints_1.output(),
                None
            )
            .await
    );
    // Invalid seed
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: checkpoints_1.output().seed(),
                },
                Slot::from(1),
                checkpoints_1.output(),
                None
            )
            .await
    );
    // Invalid number of iterations
    assert!(
        !verifier
            .verify_checkpoints(
                genesis_seed,
                slot_iterations
                    .checked_mul(NonZeroU32::new(2).unwrap())
                    .unwrap(),
                &checkpoints_1
            )
            .await
    );

    let seed_1 = checkpoints_1.output().seed();
    let checkpoints_2 = subspace_proof_of_time::prove(seed_1, slot_iterations).unwrap();

    // Expected to be valid
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(2),
                    slot_iterations,
                    seed: seed_1,
                },
                Slot::from(1),
                checkpoints_2.output(),
                None
            )
            .await
    );
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: genesis_seed,
                },
                Slot::from(2),
                checkpoints_2.output(),
                None
            )
            .await
    );
    assert!(
        verifier
            .verify_checkpoints(seed_1, slot_iterations, &checkpoints_2)
            .await
    );

    // Invalid number of slots
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: seed_1,
                },
                Slot::from(2),
                checkpoints_2.output(),
                None
            )
            .await
    );
    // Invalid seed
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations,
                    seed: seed_1,
                },
                Slot::from(2),
                checkpoints_2.output(),
                None
            )
            .await
    );
    // Invalid number of iterations
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations: slot_iterations
                        .checked_mul(NonZeroU32::new(2).unwrap())
                        .unwrap(),
                    seed: genesis_seed,
                },
                Slot::from(2),
                checkpoints_2.output(),
                None
            )
            .await
    );
}

#[tokio::test]
async fn parameters_change() {
    let genesis_seed = PotSeed::from(SEED);
    let slot_iterations_1 = NonZeroU32::new(512).unwrap();
    let entropy = [1; mem::size_of::<Blake3Hash>()];
    let checkpoints_1 = subspace_proof_of_time::prove(genesis_seed, slot_iterations_1).unwrap();
    let slot_iterations_2 = slot_iterations_1.saturating_mul(NonZeroU32::new(2).unwrap());
    let checkpoints_2 = subspace_proof_of_time::prove(
        checkpoints_1.output().seed_with_entropy(&entropy),
        slot_iterations_2,
    )
    .unwrap();
    let checkpoints_3 =
        subspace_proof_of_time::prove(checkpoints_2.output().seed(), slot_iterations_2).unwrap();

    let verifier = PotVerifier::new(genesis_seed, NonZeroUsize::new(1000).unwrap());

    // Changing parameters after first slot
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations: slot_iterations_1,
                    seed: genesis_seed,
                },
                Slot::from(1),
                checkpoints_1.output(),
                Some(PotParametersChange {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    entropy,
                })
            )
            .await
    );
    // Changing parameters in the middle
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations: slot_iterations_1,
                    seed: genesis_seed,
                },
                Slot::from(3),
                checkpoints_3.output(),
                Some(PotParametersChange {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    entropy,
                })
            )
            .await
    );
    // Changing parameters on last slot
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations: slot_iterations_1,
                    seed: genesis_seed,
                },
                Slot::from(2),
                checkpoints_2.output(),
                Some(PotParametersChange {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    entropy,
                })
            )
            .await
    );
    // Not changing parameters because changes apply to the very first slot that is verified
    assert!(
        verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    seed: checkpoints_1.output().seed_with_entropy(&entropy),
                },
                Slot::from(2),
                checkpoints_3.output(),
                Some(PotParametersChange {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    entropy,
                })
            )
            .await
    );

    // Missing parameters change
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(1),
                    slot_iterations: slot_iterations_1,
                    seed: genesis_seed,
                },
                Slot::from(3),
                checkpoints_3.output(),
                None
            )
            .await
    );
    // Invalid slot
    assert!(
        !verifier
            .is_output_valid(
                PotNextSlotInput {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_1,
                    seed: genesis_seed,
                },
                Slot::from(3),
                checkpoints_3.output(),
                Some(PotParametersChange {
                    slot: Slot::from(2),
                    slot_iterations: slot_iterations_2,
                    entropy,
                })
            )
            .await
    );
}
