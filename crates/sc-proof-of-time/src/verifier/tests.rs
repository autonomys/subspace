use crate::verifier::PotVerifier;
use futures::executor::block_on;
use sp_consensus_slots::Slot;
use std::num::{NonZeroU32, NonZeroUsize};
use subspace_core_primitives::PotSeed;
use subspace_proof_of_time::prove;

const SEED: [u8; 16] = [
    0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1, 0x3a,
];

#[test]
fn test_basic() {
    let genesis_seed = PotSeed::from(SEED);
    let slot_iterations = NonZeroU32::new(512).unwrap();
    let checkpoints_1 = prove(genesis_seed, slot_iterations).unwrap();

    let verifier = PotVerifier::new(genesis_seed, NonZeroUsize::new(1000).unwrap());

    // Expected to be valid
    assert!(block_on(verifier.is_proof_valid(
        genesis_seed,
        slot_iterations,
        Slot::from(1),
        checkpoints_1.output()
    )));
    assert!(block_on(verifier.verify_checkpoints(
        genesis_seed,
        slot_iterations,
        &checkpoints_1
    )));

    // Invalid number of slots
    assert!(!block_on(verifier.is_proof_valid(
        genesis_seed,
        slot_iterations,
        Slot::from(2),
        checkpoints_1.output()
    )));
    // Invalid seed
    assert!(!block_on(verifier.is_proof_valid(
        checkpoints_1.output().seed(),
        slot_iterations,
        Slot::from(1),
        checkpoints_1.output()
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
    let checkpoints_2 = prove(seed_1, slot_iterations).unwrap();

    // Expected to be valid
    assert!(block_on(verifier.is_proof_valid(
        seed_1,
        slot_iterations,
        Slot::from(1),
        checkpoints_2.output()
    )));
    assert!(block_on(verifier.is_proof_valid(
        genesis_seed,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output()
    )));
    assert!(block_on(verifier.verify_checkpoints(
        seed_1,
        slot_iterations,
        &checkpoints_2
    )));

    // Invalid number of slots
    assert!(!block_on(verifier.is_proof_valid(
        seed_1,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output()
    )));
    // Invalid seed
    assert!(!block_on(verifier.is_proof_valid(
        seed_1,
        slot_iterations,
        Slot::from(2),
        checkpoints_2.output()
    )));
    // Invalid number of iterations
    assert!(!block_on(
        verifier.is_proof_valid(
            genesis_seed,
            slot_iterations
                .checked_mul(NonZeroU32::new(2).unwrap())
                .unwrap(),
            Slot::from(2),
            checkpoints_2.output()
        )
    ));
}
