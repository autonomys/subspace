use crate::source::state::PotState;
use crate::verifier::PotVerifier;
use futures::SinkExt;
use futures::channel::mpsc;
use futures::executor::block_on;
use sp_consensus_slots::Slot;
use std::num::NonZeroU32;
use std::sync::Arc;
use subspace_core_primitives::pot::{PotCheckpoints, PotSeed};
use subspace_proof_of_time::PotError;
use tracing::{debug, trace};

/// Proof of time slot information
pub(super) struct TimekeeperProof {
    /// Slot number
    pub(super) slot: Slot,
    /// Proof of time seed
    pub(super) seed: PotSeed,
    /// Iterations per slot
    pub(super) slot_iterations: NonZeroU32,
    /// Proof of time checkpoints
    pub(super) checkpoints: PotCheckpoints,
}

/// Runs timekeeper, must be running on a fast dedicated CPU core
pub(super) fn run_timekeeper(
    state: Arc<PotState>,
    pot_verifier: PotVerifier,
    mut proofs_sender: mpsc::Sender<TimekeeperProof>,
) -> Result<(), PotError> {
    let mut next_slot_input = state.next_slot_input();

    loop {
        trace!(
            "Proving for slot {} with {} iterations",
            next_slot_input.slot, next_slot_input.slot_iterations
        );
        let checkpoints =
            subspace_proof_of_time::prove(next_slot_input.seed, next_slot_input.slot_iterations)?;

        let proof = TimekeeperProof {
            seed: next_slot_input.seed,
            slot_iterations: next_slot_input.slot_iterations,
            slot: next_slot_input.slot,
            checkpoints,
        };

        pot_verifier.inject_verified_checkpoints(
            next_slot_input.seed,
            next_slot_input.slot_iterations,
            checkpoints,
        );

        match state.try_extend(
            next_slot_input,
            next_slot_input.slot,
            checkpoints.output(),
            None,
        ) {
            Ok(new_next_slot_input) => {
                next_slot_input = new_next_slot_input;

                if let Err(error) = proofs_sender.try_send(proof)
                    && let Err(error) = block_on(proofs_sender.send(error.into_inner()))
                {
                    debug!(%error, "Couldn't send checkpoints, channel is closed");
                    return Ok(());
                }
            }
            Err(existing_next_slot_input) => {
                // PoT chain was changed while proving, the proof is either known already or not on
                // the chain that is followed anymore
                trace!(
                    slot = %next_slot_input.slot,
                    "Proof of time chain was changed while proving, not sending the proof",
                );

                next_slot_input = existing_next_slot_input;
            }
        }
    }
}
