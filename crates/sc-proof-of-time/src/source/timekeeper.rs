use crate::source::state::PotState;
use crate::source::TimekeeperCheckpoints;
use crate::verifier::PotVerifier;
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::SinkExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use subspace_proof_of_time::PotError;
use tracing::debug;

/// Runs timekeeper, must be running on a fast dedicated CPU core
pub(super) fn run_timekeeper(
    state: Arc<PotState>,
    pot_verifier: PotVerifier,
    mut proofs_sender: mpsc::Sender<TimekeeperCheckpoints>,
) -> Result<(), PotError> {
    let mut next_slot_input = state.next_slot_input(Ordering::Acquire);

    loop {
        let checkpoints =
            subspace_proof_of_time::prove(next_slot_input.seed, next_slot_input.slot_iterations)?;

        let slot_info = TimekeeperCheckpoints {
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
                #[cfg(feature = "pot")]
                None,
            )
            .unwrap_or_else(|next_slot_input| next_slot_input);

        if let Err(error) = proofs_sender.try_send(slot_info) {
            if let Err(error) = block_on(proofs_sender.send(error.into_inner())) {
                debug!(%error, "Couldn't send checkpoints, channel is closed");
                return Ok(());
            }
        }
    }
}
