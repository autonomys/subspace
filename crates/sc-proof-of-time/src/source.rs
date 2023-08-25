use derive_more::{Deref, DerefMut, From};
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::SinkExt;
use sp_consensus_slots::Slot;
use std::num::NonZeroU32;
use std::thread;
use subspace_core_primitives::{PotBytes, PotCheckpoints, PotKey, PotSeed, SlotNumber};
use subspace_proof_of_time::PotError;
use tracing::{debug, error};

/// Proof of time slot information
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut, From)]
pub struct PotSlotInfoStream(mpsc::Receiver<PotSlotInfo>);

/// Configuration for proof of time source
#[derive(Debug, Copy, Clone)]
pub struct PotSourceConfig {
    /// Is this node a Timekeeper
    pub is_timekeeper: bool,
    /// PoT key used initially when PoT chain starts
    pub initial_key: PotKey,
}

/// Source of proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
pub struct PotSource {
    // TODO
}

impl PotSource {
    pub fn new(config: PotSourceConfig) -> (Self, PotSlotInfoStream) {
        // TODO: All 3 are incorrect and should be able to continue after node restart
        let start_slot = SlotNumber::MIN;
        let start_seed = PotSeed::default();
        let start_key = config.initial_key;
        // TODO: Change to correct values taken from blockchain
        let iterations = NonZeroU32::new(1024).expect("Not zero; qed");

        // TODO: Correct capacity
        let (slot_sender, slot_receiver) = mpsc::channel(10);
        thread::Builder::new()
            .name("timekeeper".to_string())
            .spawn(move || {
                if let Err(error) =
                    run_timekeeper(start_seed, start_key, start_slot, iterations, slot_sender)
                {
                    error!(%error, "Timekeeper exited with an error");
                }
            })
            .expect("Thread creation must not panic");

        (
            Self {
                // TODO
            },
            PotSlotInfoStream(slot_receiver),
        )
    }

    /// Run proof of time source
    pub async fn run(self) {
        // TODO: Aggregate multiple sources of proofs of time (multiple timekeepers, gossip,
        //  blockchain itself)
        std::future::pending().await
    }
}

/// Runs timekeeper, must be running on a fast dedicated CPU core
fn run_timekeeper(
    mut seed: PotSeed,
    mut key: PotKey,
    mut slot: SlotNumber,
    iterations: NonZeroU32,
    mut slot_sender: mpsc::Sender<PotSlotInfo>,
) -> Result<(), PotError> {
    // TODO
    loop {
        let checkpoints = subspace_proof_of_time::prove(seed, key, iterations)?;

        // TODO: Store checkpoints somewhere

        // TODO: These two are wrong and need to be updated
        seed = PotSeed::from(PotBytes::from(checkpoints.output()));
        key = PotKey::from(PotBytes::from(checkpoints.output()));

        let slot_info = PotSlotInfo {
            slot: Slot::from(slot),
            checkpoints,
        };

        if let Err(error) = slot_sender.try_send(slot_info) {
            if let Err(error) = block_on(slot_sender.send(error.into_inner())) {
                debug!(%error, "Couldn't send checkpoints, channel is closed");
                return Ok(());
            }
        }

        slot += 1;
    }
}
