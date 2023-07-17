//! Clock master implementation.

use crate::pot_state::{pot_state, PotStateInterface};
use crate::utils::{topic, PotGossip, LOG_TARGET};
use crate::{InitialPotProofInputs, PotConfig};
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use sc_network::PeerId;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_consensus::SyncOracle;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::thread;
use std::time::{self, Instant};
use subspace_core_primitives::{PotProof, PotSeed};
use subspace_proof_of_time::ProofOfTime;
use tracing::{debug, error, info, warn};

/// The clock master manages the protocol: periodic proof generation/verification, gossip.
pub struct ClockMaster<Block: BlockT, SO: SyncOracle + Send + Sync + Clone + 'static> {
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
    gossip: PotGossip<Block>,
    sync_oracle: Arc<SO>,
}

impl<Block, SO> ClockMaster<Block, SO>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    /// Creates the clock master instance.
    pub fn new(config: PotConfig, gossip: PotGossip<Block>, sync_oracle: Arc<SO>) -> Self {
        let proof_of_time = Arc::new(ProofOfTime::new(
            config.num_checkpoints,
            config.checkpoint_iterations,
        ));

        Self {
            config,
            proof_of_time,
            gossip,
            sync_oracle,
        }
    }

    /// Starts the workers.
    pub async fn run(
        mut self,
        init_fn: Box<dyn Fn() -> Option<InitialPotProofInputs> + Send>,
        sender_clock_master: TracingUnboundedSender<PotProof>,
        mut receiver_clock_master: TracingUnboundedReceiver<PotProof>,
        sender_pot_client: TracingUnboundedSender<PotProof>,
    ) {
        let state = pot_state(self.config.clone(), self.proof_of_time.clone());
        state
            .on_proof(&self.create_initial_proof(init_fn).await)
            .expect("Adding initial proof cannot fail");

        let mut incoming_messages = Box::pin(
            self.gossip
                .engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    notification
                        .sender
                        .map(|sender| (sender, notification.message))
                })
                .filter_map(|(sender, message)| async move {
                    PotProof::decode(&mut &message[..])
                        .ok()
                        .map(|msg| (sender, msg))
                }),
        );

        let proof_of_time = self.proof_of_time.clone();
        let sync_oracle = self.sync_oracle.clone();
        let state_cl = state.clone();
        thread::Builder::new()
            .name("pot-proof-producer".to_string())
            .spawn(move || {
                Self::produce_proofs(
                    proof_of_time,
                    sync_oracle,
                    state_cl,
                    vec![sender_clock_master, sender_pot_client],
                );
            })
            .expect("Failed to spawn PoT proof producer thread");

        loop {
            let engine = self.gossip.engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                local_proof = receiver_clock_master.next().fuse() => {
                    if let Some(proof) = local_proof {
                        debug!(target: LOG_TARGET, "clock_master: got local proof: {proof}");
                        self.on_local_proof(proof);
                    }
                },
                gossiped = incoming_messages.next().fuse() => {
                    if let Some((sender, proof)) = gossiped {
                        debug!(target: LOG_TARGET, "clock_master: got gossiped proof: {sender} => {proof}");
                        self.on_gossip_message(state.as_ref(), sender, proof);
                    }
                },
                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "clock_master: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Long running loop to produce the proofs.
    fn produce_proofs(
        proof_of_time: Arc<ProofOfTime>,
        sync_oracle: Arc<SO>,
        state: Arc<dyn PotStateInterface>,
        proof_senders: Vec<TracingUnboundedSender<PotProof>>,
    ) {
        let sync_delay = time::Duration::from_secs(1);
        loop {
            // Wait for syncing to complete before producing proofs.
            if sync_oracle.is_major_syncing() {
                error!(target: LOG_TARGET, "clock_master::produce proofs: waiting for sync");
                thread::sleep(sync_delay);
                continue;
            }

            // Build the next proof on top of the latest tip.
            let last_proof = state.tip().expect("Clock master chain cannot be empty");

            // TODO: injected block hash from consensus
            let start_ts = Instant::now();
            let next_slot_number = last_proof.slot_number + 1;
            let next_seed = last_proof.next_seed(None);
            let next_key = last_proof.next_key();
            let next_proof = proof_of_time
                .create(
                    next_seed,
                    next_key,
                    next_slot_number,
                    last_proof.injected_block_hash,
                )
                .expect("Proof creation cannot fail");
            let elapsed = start_ts.elapsed();
            info!(target: LOG_TARGET, "clock_master::produce proofs: {next_proof}, time=[{elapsed:?}]");

            // Store the new proof back into the chain and gossip to other clock masters.
            if let Err(e) = state.on_proof(&next_proof) {
                info!(target: LOG_TARGET, "clock_master::produce proofs: failed to extend chain: {e:?}");
                continue;
            }

            proof_senders.iter().for_each(|sender| {
                if let Err(e) = sender.unbounded_send(next_proof.clone()) {
                    warn!(target: LOG_TARGET, "clock_master::produce proofs: send failed: {e:?}");
                }
            })
        }
    }

    /// Gossips the locally generated proof.
    fn on_local_proof(&mut self, proof: PotProof) {
        let encoded_msg = proof.encode();
        self.gossip.validator.on_broadcast(&encoded_msg);
        self.gossip
            .engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_msg, false);
    }

    /// Handles the incoming gossip message.
    fn on_gossip_message(
        &mut self,
        state: &dyn PotStateInterface,
        sender: PeerId,
        proof: PotProof,
    ) {
        let start_ts = Instant::now();
        let ret = state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            warn!(target: LOG_TARGET, "clock_master::on gossip: {err:?}, {sender}");
        } else {
            info!(target: LOG_TARGET, "clock_master::on gossip: {proof}, time=[{elapsed:?}], {sender}");
            let encoded_msg = proof.encode();
            self.gossip.validator.on_broadcast(&encoded_msg);
            self.gossip
                .engine
                .lock()
                .gossip_message(topic::<Block>(), encoded_msg, false);
        }
    }

    /// Creates the initial proof from genesis block.
    async fn create_initial_proof(
        &self,
        init_fn: Box<dyn Fn() -> Option<InitialPotProofInputs> + Send>,
    ) -> PotProof {
        // Wait for the genesis block and create the state.
        // TODO: this would be changed when the state is persisted in AuxStorage.
        // With storage, wait for genesis block would only be needed during
        // initial bootstrap.
        let genesis_delay = tokio::time::Duration::from_secs(10);
        let initial_input = loop {
            if let Some(input) = (init_fn)() {
                break input;
            }
            info!(target: LOG_TARGET, "clock_master::initial proof: waiting for genesis slot");
            tokio::time::sleep(genesis_delay).await;
        };

        let proof = self
            .proof_of_time
            .create(
                PotSeed::from_block_hash(initial_input.genesis_hash),
                initial_input.key,
                initial_input.genesis_slot,
                initial_input.genesis_hash,
            )
            .expect("Initial proof creation cannot fail");
        info!(target: LOG_TARGET, "clock_master::initial proof: {proof}");
        proof
    }
}
