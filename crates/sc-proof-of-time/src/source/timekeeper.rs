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

        next_slot_input = state
            .try_extend(
                next_slot_input,
                next_slot_input.slot,
                checkpoints.output(),
                None,
            )
            .unwrap_or_else(|next_slot_input| next_slot_input);

        if let Err(error) = proofs_sender.try_send(proof)
            && let Err(error) = block_on(proofs_sender.send(error.into_inner()))
        {
            debug!(%error, "Couldn't send checkpoints, channel is closed");
            return Ok(());
        }
    }
}
