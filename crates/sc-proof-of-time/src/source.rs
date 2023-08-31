use crate::verifier::PotVerifier;
use derive_more::{Deref, DerefMut, From};
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::{SinkExt, StreamExt};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi as SubspaceRuntimeApi};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::thread;
use subspace_core_primitives::{PotCheckpoints, PotSeed, SlotNumber};
use subspace_proof_of_time::PotError;
use tracing::{debug, error};

/// Proof of time slot information
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Proof of time slot information
struct NewCheckpoints {
    /// Proof of time seed
    seed: PotSeed,
    /// Iterations per slot
    slot_iterations: NonZeroU32,
    /// Slot number
    slot: Slot,
    /// Proof of time checkpoints
    checkpoints: PotCheckpoints,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut, From)]
pub struct PotSlotInfoStream(mpsc::Receiver<PotSlotInfo>);

/// Source of proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
pub struct PotSource<Block, Client> {
    // TODO: Use this in `fn run`
    #[allow(dead_code)]
    client: Arc<Client>,
    pot_verifier: PotVerifier,
    local_proofs_receiver: mpsc::Receiver<NewCheckpoints>,
    slot_sender: mpsc::Sender<PotSlotInfo>,
    _block: PhantomData<Block>,
}

impl<Block, Client> PotSource<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    pub fn new(
        // TODO: Respect this boolean flag
        _is_timekeeper: bool,
        client: Arc<Client>,
        pot_verifier: PotVerifier,
    ) -> Result<(Self, PotSlotInfoStream), ApiError> {
        // TODO: Both of following are incorrect and should be able to continue after node restart
        let start_slot = 1;
        let start_seed = pot_verifier.genesis_seed();
        #[cfg(feature = "pot")]
        let best_hash = client.info().best_hash;
        #[cfg(feature = "pot")]
        let slot_iterations = client
            .runtime_api()
            .pot_parameters(best_hash)?
            .slot_iterations(Slot::from(start_slot));
        #[cfg(not(feature = "pot"))]
        let slot_iterations = NonZeroU32::new(100_000_000).expect("Not zero; qed");

        // TODO: Correct capacity
        let (local_proofs_sender, local_proofs_receiver) = mpsc::channel(10);
        let (slot_sender, slot_receiver) = mpsc::channel(10);
        thread::Builder::new()
            .name("timekeeper".to_string())
            .spawn(move || {
                if let Err(error) =
                    run_timekeeper(start_seed, start_slot, slot_iterations, local_proofs_sender)
                {
                    error!(%error, "Timekeeper exited with an error");
                }
            })
            .expect("Thread creation must not panic");

        Ok((
            Self {
                client,
                pot_verifier,
                local_proofs_receiver,
                slot_sender,
                _block: PhantomData,
            },
            PotSlotInfoStream(slot_receiver),
        ))
    }

    /// Run proof of time source
    pub async fn run(mut self) {
        // TODO: More sources of checkpoints (block import, gossip)
        while let Some(new_checkpoints) = self.local_proofs_receiver.next().await {
            let NewCheckpoints {
                seed,
                slot_iterations,
                slot,
                checkpoints,
            } = new_checkpoints;

            self.pot_verifier
                .inject_verified_checkpoints(seed, slot_iterations, checkpoints);

            // It doesn't matter if receiver is dropped
            let _ = self
                .slot_sender
                .send(PotSlotInfo { slot, checkpoints })
                .await;
        }
    }
}

/// Runs timekeeper, must be running on a fast dedicated CPU core
fn run_timekeeper(
    mut seed: PotSeed,
    mut slot: SlotNumber,
    slot_iterations: NonZeroU32,
    mut proofs_sender: mpsc::Sender<NewCheckpoints>,
) -> Result<(), PotError> {
    loop {
        let checkpoints = subspace_proof_of_time::prove(seed, slot_iterations)?;

        let slot_info = NewCheckpoints {
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
