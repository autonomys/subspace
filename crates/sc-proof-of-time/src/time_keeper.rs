//! Time keeper implementation.

use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use sc_client_api::BlockchainEvents;
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use subspace_core_primitives::{NonEmptyVec, PotProof, PotSeed};
use subspace_proof_of_time::ProofOfTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, trace, warn};

/// Channel size to send the produced proofs.
/// The proof producer thread will block if the receiver is behind and
/// the channel fills up.
const PROOFS_CHANNEL_SIZE: usize = 12; // 2 * reveal lag.

/// The time keeper manages the protocol: periodic proof generation/verification, gossip.
pub struct TimeKeeper<Block, Client> {
    proof_of_time: ProofOfTime,
    pot_state: Arc<dyn PotProtocolState>,
    client: Arc<Client>,
    // Expected time to produce a proof.
    // TODO: this will be removed after the pot_iterations is set
    // to produce a proof/sec.
    target_proof_time: Duration,
    gossip_sender: mpsc::Sender<PotProof>,
    _block: PhantomData<Block>,
}

impl<Block, Client> TimeKeeper<Block, Client>
where
    Block: BlockT<Hash = H256>,
    Client: HeaderBackend<Block> + BlockchainEvents<Block>,
{
    /// Creates the time keeper instance.
    pub fn new(
        components: &PotComponents,
        client: Arc<Client>,
        target_proof_time: Duration,
        gossip_sender: mpsc::Sender<PotProof>,
    ) -> Self {
        Self {
            proof_of_time: components.proof_of_time,
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
        debug!("Waiting for initialization");

        // Wait for the first block import.
        let mut block_import = self.client.import_notification_stream();
        while let Some(incoming_block) = block_import.next().await {
            let pre_digest = match extract_pre_digest(&incoming_block.header) {
                Ok(pre_digest) => pre_digest,
                Err(error) => {
                    warn!(
                        %error,
                        block_hash = %incoming_block.hash,
                        origin = ?incoming_block.origin,
                        "Failed to get pre_digest",
                    );
                    continue;
                }
            };

            let pot_pre_digest = match pre_digest.pot_pre_digest() {
                Some(pot_pre_digest) => pot_pre_digest,
                None => {
                    warn!(
                        block_hash = %incoming_block.hash,
                        origin = ?incoming_block.origin,
                        "Failed to get pot_pre_digest",
                    );
                    continue;
                }
            };

            debug!(
                block_hash = %incoming_block.hash,
                origin = ?incoming_block.origin,
                ?pot_pre_digest,
                "Initialization complete",
            );
            let proofs = pot_pre_digest.proofs().cloned().unwrap_or_else(|| {
                // Producing proofs starting from (genesis_slot + 1).
                // TODO: Proper error handling or proof
                let block_hash = incoming_block.hash.into();
                let proof = self.proof_of_time.create(
                    PotSeed::from_block_hash(block_hash),
                    Default::default(), // TODO: key from cmd line or BTC
                    pot_pre_digest
                        .next_block_initial_slot()
                        .expect("Initial slot number should be available for block_number >= 1"),
                    block_hash,
                );
                debug!(%proof, "Creating first proof");
                NonEmptyVec::new_with_entry(proof)
            });

            self.pot_state.reset(proofs);
            return;
        }
    }

    /// Starts the thread to produce the proofs.
    fn spawn_producer_thread(&self) -> Receiver<PotProof> {
        let (sender, receiver) = channel(PROOFS_CHANNEL_SIZE);
        let proof_of_time = self.proof_of_time;
        let pot_state = self.pot_state.clone();
        let target_proof_time = self.target_proof_time;
        thread::Builder::new()
            .name("pot-proof-producer".to_string())
            .spawn(move || {
                Self::produce_proofs(proof_of_time, pot_state, sender, target_proof_time);
            })
            // TODO: Proper error handling or proof
            .expect("Failed to spawn PoT proof producer thread");
        receiver
    }

    /// Long running loop to produce the proofs.
    fn produce_proofs(
        proof_of_time: ProofOfTime,
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
            let next_proof = proof_of_time.create(
                next_seed,
                next_key,
                next_slot_number,
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
