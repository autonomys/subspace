use crate::source::state::PotState;
use crate::verifier::PotVerifier;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{PotNextSlotInput, PotParametersChange};
use std::iter;
use std::num::NonZeroU32;
use subspace_core_primitives::hashes::Blake3Hash;
use subspace_core_primitives::pot::{PotCheckpoints, PotSeed};

const SEED: [u8; 16] = [
    0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1, 0x3a,
];
const SLOT_ITERATIONS: NonZeroU32 = NonZeroU32::new(16).unwrap();

/// Prove `num_slots` consecutive slots starting with `slot_input` and inject them into `verifier`,
/// returns input and checkpoints of each slot
fn prove_slots(
    verifier: &PotVerifier,
    mut slot_input: PotNextSlotInput,
    num_slots: usize,
) -> Vec<(PotNextSlotInput, PotCheckpoints)> {
    iter::repeat_with(|| {
        let checkpoints =
            subspace_proof_of_time::prove(slot_input.seed, slot_input.slot_iterations).unwrap();
        verifier.inject_verified_checkpoints(
            slot_input.seed,
            slot_input.slot_iterations,
            checkpoints,
        );
        let proof = (slot_input, checkpoints);
        slot_input = PotNextSlotInput::derive(
            slot_input.slot_iterations,
            slot_input.slot,
            checkpoints.output(),
            &None,
        );
        proof
    })
    .take(num_slots)
    .collect()
}

#[test]
fn is_on_current_chain() {
    // Slots 1..=3 of the chain and slots 2..=4 of the fork with entropy injected at slot 2
    let genesis_seed = PotSeed::from(SEED);
    let verifier = PotVerifier::new(genesis_seed, 100);
    let first_slot_input = PotNextSlotInput {
        slot: Slot::from(1),
        slot_iterations: SLOT_ITERATIONS,
        seed: genesis_seed,
    };
    let chain = prove_slots(&verifier, first_slot_input, 3);
    let parameters_change = PotParametersChange {
        slot: Slot::from(2),
        slot_iterations: SLOT_ITERATIONS,
        entropy: Blake3Hash::from([1; Blake3Hash::SIZE]),
    };
    let fork = prove_slots(
        &verifier,
        PotNextSlotInput::derive(
            SLOT_ITERATIONS,
            Slot::from(1),
            chain[0].1.output(),
            &Some(parameters_change),
        ),
        3,
    );

    let state = PotState::new(first_slot_input, None, verifier);
    // Other slots of the chain are already known, so the tip moves to slot 4
    let next_slot_input = state
        .try_extend(first_slot_input, Slot::from(1), chain[0].1.output(), None)
        .unwrap();
    assert_eq!(next_slot_input.slot, Slot::from(4));

    for (slot_input, checkpoints) in &chain {
        assert!(state.is_on_current_chain(*slot_input, checkpoints.output()));
    }
    for (slot_input, checkpoints) in &fork {
        assert!(!state.is_on_current_chain(*slot_input, checkpoints.output()));
    }
    // Any output is fine for the next slot as long as the input matches
    assert!(state.is_on_current_chain(next_slot_input, fork[2].1.output()));

    // Reorg to the fork, whose tip is at slot 5
    state.update(
        Slot::from(2),
        fork[0].1.output(),
        Some(Some(parameters_change)),
    );
    assert_eq!(state.next_slot_input().slot, Slot::from(5));

    assert!(state.is_on_current_chain(chain[0].0, chain[0].1.output()));
    for (slot_input, checkpoints) in &chain[1..] {
        assert!(!state.is_on_current_chain(*slot_input, checkpoints.output()));
    }
    for (slot_input, checkpoints) in &fork {
        assert!(state.is_on_current_chain(*slot_input, checkpoints.output()));
    }
}
