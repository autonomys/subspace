//! Time keeper implementation.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::{PotComponents, INITIAL_SLOT_NUMBER};
use futures::FutureExt;
use parity_scale_codec::Encode;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use subspace_core_primitives::{BlockHash, NonEmptyVec, PotKey, PotProof, PotSeed};
use subspace_proof_of_time::ProofOfTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{error, info, trace, warn};

/// Channel size to send the produced proofs.
/// The proof producer thread will block if the receiver is behind and
/// the channel fills up.
const PROOFS_CHANNEL_SIZE: usize = 12; // 2 * reveal lag.

/// The time keeper manages the protocol: periodic proof generation/verification, gossip.
pub struct TimeKeeper<Block: BlockT<Hash = H256>> {
    proof_of_time: ProofOfTime,
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
    // Expected time to produce a proof.
    // TODO: this will be removed after the pot_iterations is set
    // to produce a proof/sec.
    target_proof_time: Duration,
}

impl<Block> TimeKeeper<Block>
where
    Block: BlockT<Hash = H256>,
{
    /// Creates the time keeper instance.
    pub fn new<Network, GossipSync>(
        components: PotComponents,
        network: Network,
        sync: Arc<GossipSync>,
        target_proof_time: Duration,
    ) -> Self
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let PotComponents {
            proof_of_time,
            protocol_state: pot_state,
            ..
        } = components;

        Self {
            proof_of_time: proof_of_time.clone(),
            pot_state: pot_state.clone(),
            gossip: PotGossip::new(network, sync, pot_state, proof_of_time),
            target_proof_time,
        }
    }

    /// Runs the time keeper processing loop.
    pub async fn run(self, initial_hash: BlockHash, initial_key: PotKey) {
        self.initialize(initial_hash, initial_key).await;

        let mut local_proof_receiver = self.spawn_producer_thread();
        let handle_gossip_message: Arc<dyn Fn(PeerId, PotProof) + Send + Sync> =
            Arc::new(|sender, proof| {
                self.handle_gossip_message(sender, proof);
            });
        loop {
            futures::select! {
                local_proof = local_proof_receiver.recv().fuse() => {
                    if let Some(proof) = local_proof {
                        trace!(%proof, "Got local proof");
                        self.handle_local_proof(proof);
                    }
                },
                _ = self.gossip.process_incoming_messages(
                    handle_gossip_message.clone()
                ).fuse() => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
    }

    /// Initializes the chain state with the first proof.
    async fn initialize(&self, initial_hash: BlockHash, initial_key: PotKey) {
        let proof = self.proof_of_time.create(
            PotSeed::from_block_hash(initial_hash),
            initial_key,
            INITIAL_SLOT_NUMBER,
            initial_hash,
        );
        info!(?initial_hash, ?initial_key, ?proof, "Creating first proof");
        self.pot_state.reset(NonEmptyVec::new_with_entry(proof));
    }

    /// Starts the thread to produce the proofs.
    fn spawn_producer_thread(&self) -> Receiver<PotProof> {
        let (sender, receiver) = channel(PROOFS_CHANNEL_SIZE);
        let proof_of_time = self.proof_of_time.clone();
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

    /// Gossips the locally generated proof.
    fn handle_local_proof(&self, proof: PotProof) {
        self.gossip.gossip_message(proof.encode());
    }

    /// Handles the incoming gossip message.
    fn handle_gossip_message(&self, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = self.pot_state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(error) = ret {
            trace!(%error, %sender, "On gossip");
        } else {
            trace!(%proof, ?elapsed, %sender, "On gossip");
        }
    }
}
