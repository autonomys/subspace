//! Clock master implementation.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::utils::get_consensus_tip;
use crate::PotComponents;
use futures::FutureExt;
use parity_scale_codec::Encode;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, Zero};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use subspace_core_primitives::{NonEmptyVec, PotProof, PotSeed};
use subspace_proof_of_time::ProofOfTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{error, info, trace, warn};

/// Channel size to send the produced proofs.
/// The proof producer thread will block if the receiver is behind and
/// the channel fills up.
const PROOFS_CHANNEL_SIZE: usize = 12; // 2 * reveal lag.

/// Expected time to produce a proof.
const TARGET_PROOF_TIME_MSEC: u128 = 1000;

/// The clock master manages the protocol: periodic proof generation/verification, gossip.
pub struct ClockMaster<Block: BlockT<Hash = H256>, Client, SO> {
    proof_of_time: ProofOfTime,
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
}

impl<Block, Client, SO> ClockMaster<Block, Client, SO>
where
    Block: BlockT<Hash = H256>,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    /// Creates the clock master instance.
    /// TODO: chain_info() is not a trait method, but part of the
    /// client::Client struct itself. Passing it in brings in lot
    /// of unnecessary generics/dependencies. chain_info_fn() tries
    /// to avoid that by using a Fn instead. Follow up with upstream
    /// to include this in the trait.
    pub fn new<Network, GossipSync>(
        components: PotComponents,
        client: Arc<Client>,
        sync_oracle: Arc<SO>,
        network: Network,
        sync: Arc<GossipSync>,
        chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
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
            client,
            sync_oracle,
            chain_info_fn,
        }
    }

    /// Runs the clock master processing loop.
    pub async fn run(self) {
        self.initialize().await;

        let mut local_proof_receiver = self.spawn_producer_thread();
        let handle_gossip_message: Arc<dyn Fn(PeerId, PotProof) + Send + Sync> =
            Arc::new(|sender, proof| {
                self.handle_gossip_message(sender, proof);
            });
        loop {
            futures::select! {
                local_proof = local_proof_receiver.recv().fuse() => {
                    if let Some(proof) = local_proof {
                        trace!("clock_master: got local proof: {proof}");
                        self.handle_local_proof(proof);
                    }
                },
                _ = self.gossip.process_incoming_messages(
                    handle_gossip_message.clone()
                ).fuse() => {
                    error!("clock_master: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Initializes the chain state from the consensus tip info.
    async fn initialize(&self) {
        info!("clock_master::initialize: waiting for initialization ...");
        let delay = tokio::time::Duration::from_secs(1);
        let proofs = loop {
            let tip = get_consensus_tip(
                self.client.clone(),
                self.sync_oracle.clone(),
                self.chain_info_fn.clone(),
            )
            .await
            .expect("Consensus tip info should be available");

            if tip.block_number.is_zero() {
                trace!("clock_master::initialize: {tip:?}, to wait ...",);
                tokio::time::sleep(delay).await;
                continue;
            }

            info!(
                "clock_master::initialization done: block_hash={:?}, block_number={}, slot_number={}, {:?}",
                tip.block_hash, tip.block_number, tip.slot_number, tip.pot_pre_digest
            );

            let proofs = tip.pot_pre_digest.proofs().cloned().unwrap_or_else(|| {
                // Producing proofs starting from (genesis_slot + 1).
                let proof = self.proof_of_time.create(
                    PotSeed::from_block_hash(tip.block_hash),
                    Default::default(), // TODO: key from cmd line or BTC
                    tip.pot_pre_digest
                        .next_block_initial_slot()
                        .expect("Initial slot number should be available for block_number >= 1"),
                    tip.block_hash,
                );
                info!("clock_master::initialize: creating first proof: {proof}");
                NonEmptyVec::new_with_entry(proof)
            });
            break proofs;
        };
        self.pot_state.reset(proofs);
    }

    /// Starts the thread to produce the proofs.
    fn spawn_producer_thread(&self) -> Receiver<PotProof> {
        let (sender, receiver) = channel(PROOFS_CHANNEL_SIZE);
        let proof_of_time = self.proof_of_time.clone();
        let pot_state = self.pot_state.clone();
        thread::Builder::new()
            .name("pot-proof-producer".to_string())
            .spawn(move || {
                Self::produce_proofs(proof_of_time, pot_state, sender);
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
    ) {
        loop {
            // Build the next proof on top of the latest tip.
            // TODO: Proper error handling or proof
            let last_proof = state.tip().expect("Clock master chain cannot be empty");

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
            trace!("clock_master::produce proofs: {next_proof}, time=[{elapsed:?}]");

            // Store the new proof back into the chain and gossip to other clock masters.
            if let Err(e) = state.on_proof(&next_proof) {
                info!("clock_master::produce proofs: failed to extend chain: {e:?}");
                continue;
            } else if let Err(e) = proof_sender.blocking_send(next_proof.clone()) {
                warn!("clock_master::produce proofs: send failed: {e:?}");
                return;
            }

            // TODO: temporary hack for initial testing.
            // The pot_iterations is set to take less than 1 sec. Pad the
            // remaining time so that we produce approximately 1 proof/sec.
            if elapsed.as_millis() < TARGET_PROOF_TIME_MSEC {
                let pad = TARGET_PROOF_TIME_MSEC - elapsed.as_millis();
                // Cast should be fine if TARGET_PROOF_TIME_MSEC is small
                thread::sleep(Duration::from_millis(pad as u64))
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

        if let Err(err) = ret {
            trace!("clock_master::on gossip: {err:?}, {sender}");
        } else {
            trace!("clock_master::on gossip: {proof}, time=[{elapsed:?}], {sender}");
            self.gossip.gossip_message(proof.encode());
        }
    }
}
