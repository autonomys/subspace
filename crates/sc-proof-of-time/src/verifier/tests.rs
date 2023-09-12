use crate::verifier::PotVerifier;
use futures::executor::block_on;
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::PotParametersChange;
#[cfg(feature = "pot")]
use std::mem;
use std::num::{NonZeroU32, NonZeroUsize};
#[cfg(feature = "pot")]
use subspace_core_primitives::Blake3Hash;
use subspace_core_primitives::PotSeed;

const SEED: [u8; 16] = [
    0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1, 0x3a,
];

#[test]
fn test_basic() {
    let genesis_seed = PotSeed::from(SEED);
    let slot_iterations = NonZeroU32::new(512).unwrap();
    let checkpoints_1 = subspace_proof_of_time::prove(genesis_seed, slot_iterations).unwrap();

    let verifier = PotVerifier::new(genesis_seed, NonZeroUsize::new(1000).unwrap());

    // Expected to be valid
    assert!(block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        genesis_seed,
        slot_iterations,
        Slot::from(1),
        checkpoints_1.output(),
        #[cfg(feature = "pot")]
        None
    )));
    assert!(block_on(verifier.verify_checkpoints(
        genesis_seed,
        slot_iterations,
        &checkpoints_1
    )));

    // Invalid number of slots
    assert!(!block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        genesis_seed,
        slot_iterations,
        Slot::from(2),
        checkpoints_1.output(),
        #[cfg(feature = "pot")]
        None
    )));
    // Invalid seed
    assert!(!block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        checkpoints_1.output().seed(),
        slot_iterations,
        Slot::from(1),
        checkpoints_1.output(),
        #[cfg(feature = "pot")]
        None
    )));
    // Invalid number of iterations
    assert!(!block_on(
        verifier.verify_checkpoints(
            genesis_seed,
            slot_iterations
                .checked_mul(NonZeroU32::new(2).unwrap())
                .unwrap(),
            &checkpoints_1
        )
    ));

    let seed_1 = checkpoints_1.output().seed();
    let checkpoints_2 = subspace_proof_of_time::prove(seed_1, slot_iterations).unwrap();

    // Expected to be valid
    assert!(block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(2),
        seed_1,
        slot_iterations,
        Slot::from(1),
        checkpoints_2.output(),
        #[cfg(feature = "pot")]
        None
    )));
    assert!(block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        genesis_seed,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output(),
        #[cfg(feature = "pot")]
        None
    )));
    assert!(block_on(verifier.verify_checkpoints(
        seed_1,
        slot_iterations,
        &checkpoints_2
    )));

    // Invalid number of slots
    assert!(!block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        seed_1,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output(),
        #[cfg(feature = "pot")]
        None
    )));
    // Invalid seed
    assert!(!block_on(verifier.is_output_valid(
        #[cfg(feature = "pot")]
        Slot::from(1),
        seed_1,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output(),
        #[cfg(feature = "pot")]
        None
    )));
    // Invalid number of iterations
    assert!(!block_on(
        verifier.is_output_valid(
            #[cfg(feature = "pot")]
            Slot::from(1),
            genesis_seed,
            slot_iterations
                .checked_mul(NonZeroU32::new(2).unwrap())
                .unwrap(),
            Slot::from(2),
            checkpoints_2.output(),
            #[cfg(feature = "pot")]
            None
        )
    ));
}

#[cfg(feature = "pot")]
#[test]
fn parameters_change() {
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
    assert!(block_on(verifier.is_output_valid(
        Slot::from(1),
        genesis_seed,
        slot_iterations_1,
        Slot::from(1),
        checkpoints_1.output(),
        Some(PotParametersChange {
            slot: Slot::from(2),
            slot_iterations: slot_iterations_2,
            entropy,
        })
    )));
    // Changing parameters in the middle
    assert!(block_on(verifier.is_output_valid(
        Slot::from(1),
        genesis_seed,
        slot_iterations_1,
        Slot::from(3),
        checkpoints_3.output(),
        Some(PotParametersChange {
            slot: Slot::from(2),
            slot_iterations: slot_iterations_2,
            entropy,
        })
    )));
    // Changing parameters on last slot
    assert!(block_on(verifier.is_output_valid(
        Slot::from(1),
        genesis_seed,
        slot_iterations_1,
        Slot::from(2),
        checkpoints_2.output(),
        Some(PotParametersChange {
            slot: Slot::from(2),
            slot_iterations: slot_iterations_2,
            entropy,
        })
    )));
    // Not changing parameters because changes apply to the very first slot that is verified
    assert!(block_on(verifier.is_output_valid(
        Slot::from(2),
        checkpoints_1.output().seed_with_entropy(&entropy),
        slot_iterations_2,
        Slot::from(2),
        checkpoints_3.output(),
        Some(PotParametersChange {
            slot: Slot::from(2),
            slot_iterations: slot_iterations_2,
            entropy,
        })
    )));

    // Missing parameters change
    assert!(!block_on(verifier.is_output_valid(
        Slot::from(1),
        genesis_seed,
        slot_iterations_1,
        Slot::from(3),
        checkpoints_3.output(),
        None
    )));
    // Invalid slot
    assert!(!block_on(verifier.is_output_valid(
        Slot::from(2),
        genesis_seed,
        slot_iterations_1,
        Slot::from(3),
        checkpoints_3.output(),
        Some(PotParametersChange {
            slot: Slot::from(2),
            slot_iterations: slot_iterations_2,
            entropy,
        })
    )));
}
