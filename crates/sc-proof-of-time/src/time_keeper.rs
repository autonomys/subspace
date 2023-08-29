//! Time keeper implementation.

use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use futures::channel::mpsc;
use futures::SinkExt;
use sc_client_api::BlockBackend;
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use subspace_core_primitives::{NonEmptyVec, PotKey, PotProof, PotSeed};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, trace, warn};

/// Channel size to send the produced proofs.
/// The proof producer thread will block if the receiver is behind and
/// the channel fills up.
const PROOFS_CHANNEL_SIZE: usize = 12; // 2 * reveal lag.

/// The time keeper manages the protocol: periodic proof generation/verification, gossip.
pub struct TimeKeeper<Block, Client> {
    // TODO: Remove this from here, shouldn't be necessary eventually
    initial_seed: PotSeed,
    // TODO: Remove this from here, shouldn't be necessary eventually
    initial_key: PotKey,
    iterations: NonZeroU32,
    // TODO: Make stateless and remove this
    pot_state: Arc<dyn PotProtocolState>,
    // TODO: Make stateless and remove this
    client: Arc<Client>,
    // Expected time to produce a proof.
    // TODO: this will be removed after the pot_iterations is set to produce a proof/sec.
    target_proof_time: Duration,
    gossip_sender: mpsc::Sender<PotProof>,
    _block: PhantomData<Block>,
}

impl<Block, Client> TimeKeeper<Block, Client>
where
    Block: BlockT<Hash = H256>,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    /// Creates the time keeper instance.
    pub fn new(
        components: &PotComponents,
        client: Arc<Client>,
        target_proof_time: Duration,
        gossip_sender: mpsc::Sender<PotProof>,
    ) -> Self {
        Self {
            initial_seed: components.initial_seed,
            initial_key: components.initial_key,
            iterations: components.iterations,
            pot_state: Arc::clone(&components.protocol_state),
            client,
            target_proof_time,
            gossip_sender,
            _block: PhantomData,
        }
    }

    /// Runs the time keeper processing loop.
    pub async fn run(mut self) {
        self.initialize().await;

        let mut local_proof_receiver = self.spawn_producer_thread();
        while let Some(proof) = local_proof_receiver.recv().await {
            trace!(%proof, "Got local proof");
            if let Err(error) = self.gossip_sender.send(proof).await {
                error!(%error, "Failed to send proof to gossip");
                return;
            }
        }
    }

    /// Initializes the chain state from the consensus tip info.
    async fn initialize(&self) {
        debug!("Initializing timekeeper");

        let best_hash = self.client.info().best_hash;
        let best_block = match self.client.block(best_hash) {
            Ok(maybe_best_header) => maybe_best_header.expect("Best block must exist; qed").block,
            Err(error) => {
                // TODO: This is very bad, initialization must become fallible
                error!(
                    %error,
                    %best_hash,
                    "Failed to get best block",
                );
                return;
            }
        };

        let pre_digest = match extract_pre_digest(best_block.header()) {
            Ok(pre_digest) => pre_digest,
            Err(error) => {
                // TODO: This is very bad, initialization must become fallible
                error!(
                    %error,
                    %best_hash,
                    "Failed to get pre_digest",
                );
                return;
            }
        };

        let maybe_pot_pre_digest = pre_digest.pot_pre_digest();

        let proofs = match maybe_pot_pre_digest {
            Some(pot_pre_digest) => pot_pre_digest.proofs().clone(),
            None => {
                // TODO: We shouldn't need to generate proofs here, but current state expects parent
                //  proofs to exist
                // No proof of time means genesis block, produce the very first proof
                let checkpoints = match subspace_proof_of_time::prove(
                    self.initial_seed,
                    self.initial_key,
                    self.iterations,
                ) {
                    Ok(next_checkpoints) => next_checkpoints,
                    Err(error) => {
                        // TODO: This is very bad, initialization must become fallible
                        error!(%error, "Failed to produce proof, exiting timekeeper");
                        return;
                    }
                };
                let proof = PotProof::new(
                    0,
                    self.initial_seed,
                    self.initial_key,
                    checkpoints,
                    best_hash.into(),
                );
                debug!(%proof, "Created the first proof");
                NonEmptyVec::new_with_entry(proof)
            }
        };

        self.pot_state.reset(proofs);

        debug!(
            %best_hash,
            ?maybe_pot_pre_digest,
            "Initialization complete",
        );
    }

    /// Starts the thread to produce the proofs.
    fn spawn_producer_thread(&self) -> Receiver<PotProof> {
        let (sender, receiver) = channel(PROOFS_CHANNEL_SIZE);
        let pot_state = self.pot_state.clone();
        let iterations = self.iterations;
        let target_proof_time = self.target_proof_time;

        thread::Builder::new()
            .name("pot-proof-producer".to_string())
            .spawn(move || {
                Self::produce_proofs(iterations, pot_state, sender, target_proof_time);
            })
            // TODO: Proper error handling or proof
            .expect("Failed to spawn PoT proof producer thread");
        receiver
    }

    /// Long running loop to produce the proofs.
    fn produce_proofs(
        iterations: NonZeroU32,
        state: Arc<dyn PotProtocolState>,
        proof_sender: Sender<PotProof>,
        target_proof_time: Duration,
    ) {
        let target_proof_time_msec = target_proof_time.as_millis();
        loop {
            // Build the next proof on top of the latest tip.
            // TODO: Proper error handling or proof
            let last_proof = state.tip().expect("Time keeper chain cannot be empty");

            // TODO: injected block hash from consensus
            let start_ts = Instant::now();
            let next_slot_number = last_proof.slot_number + 1;
            let next_seed = last_proof.next_seed(None);
            let next_key = last_proof.next_key();
            let next_checkpoints =
                match subspace_proof_of_time::prove(next_seed, next_key, iterations) {
                    Ok(next_checkpoints) => next_checkpoints,
                    Err(error) => {
                        error!(%error, "Failed to produce proof, exiting timekeeper");
                        return;
                    }
                };
            let next_proof = PotProof::new(
                next_slot_number,
                next_seed,
                next_key,
                next_checkpoints,
                last_proof.injected_block_hash,
            );

            let elapsed = start_ts.elapsed();
            trace!(
                %next_proof,
                ?elapsed,
                "Produce proofs",
            );

            // Store the new proof back into the chain and gossip to other time keepers.
            if let Err(error) = state.on_proof(&next_proof) {
                error!(%error, "Produce proofs: failed to extend chain");
                continue;
            } else if let Err(error) = proof_sender.blocking_send(next_proof.clone()) {
                warn!(%error, "Produce proofs: send failed");
                return;
            }

            // TODO: temporary hack for initial testing.
            // The pot_iterations is set to take less than 1 sec. Pad the
            // remaining time so that we produce approximately 1 proof/sec.
            let elapsed_msec = elapsed.as_millis();
            if elapsed_msec < target_proof_time_msec {
                if let Ok(pad) = u64::try_from(target_proof_time_msec - elapsed_msec) {
                    thread::sleep(Duration::from_millis(pad))
                }
            }
        }
    }
}
