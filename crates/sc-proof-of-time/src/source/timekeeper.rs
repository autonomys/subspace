use crate::source::TimekeeperCheckpoints;
use crate::verifier::PotVerifier;
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::SinkExt;
use sp_consensus_slots::Slot;
use std::num::NonZeroU32;
use subspace_core_primitives::{PotSeed, SlotNumber};
use subspace_proof_of_time::PotError;
use tracing::debug;

/// Runs timekeeper, must be running on a fast dedicated CPU core
pub(super) fn run_timekeeper(
    mut seed: PotSeed,
    slot: Slot,
    slot_iterations: NonZeroU32,
    pot_verifier: PotVerifier,
    mut proofs_sender: mpsc::Sender<TimekeeperCheckpoints>,
) -> Result<(), PotError> {
    let mut slot = SlotNumber::from(slot);
    loop {
        let checkpoints = subspace_proof_of_time::prove(seed, slot_iterations)?;

        pot_verifier.inject_verified_checkpoints(seed, slot_iterations, checkpoints);

        let slot_info = TimekeeperCheckpoints {
            seed,
            slot_iterations,
            slot: Slot::from(slot),
            checkpoints,
        };

        seed = checkpoints.output().seed();

        if let Err(error) = proofs_sender.try_send(slot_info) {
            if let Err(error) = block_on(proofs_sender.send(error.into_inner())) {
                debug!(%error, "Couldn't send checkpoints, channel is closed");
                return Ok(());
            }
        }

        slot += 1;
    }
}
