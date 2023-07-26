//! Clock master implementation.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::utils::get_consensus_tip_proofs;
use crate::PotComponents;
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use sc_network::PeerId;
use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use subspace_core_primitives::{BlockHash, NonEmptyVec, PotKey, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::ProofOfTime;
use tokio::sync::mpsc::{channel, Sender};
use tracing::{error, trace, warn};

/// Channel size to send the produced proofs.
/// The proof producer thread will block if the receiver is behind and
/// the channel fills up.
const PROOFS_CHANNEL_SIZE: usize = 12; // 2 * reveal lag.

/// Inputs for bootstrapping.
#[derive(Debug, Clone)]
pub struct BootstrapParams {
    /// Genesis block hash.
    pub genesis_hash: BlockHash,

    /// The initial key to be used.
    pub key: PotKey,

    /// Initial slot number.
    pub slot: SlotNumber,
}

impl BootstrapParams {
    pub fn new(genesis_hash: BlockHash, key: PotKey, slot: SlotNumber) -> Self {
        Self {
            genesis_hash,
            key,
            slot,
        }
    }
}

/// The clock master manages the protocol: periodic proof generation/verification, gossip.
pub struct ClockMaster<Block: BlockT, Client, SO> {
    proof_of_time: ProofOfTime,
    gossip: PotGossip<Block>,
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    pot_state: Arc<dyn PotProtocolState>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
}

impl<Block, Client, SO> ClockMaster<Block, Client, SO>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    /// Creates the clock master instance.
    /// TODO: chain_info() is not a trait method, but part of the
    /// client::Client struct itself. Passing it in brings in lot
    /// of unnecessary generics/dependencies. chain_info_fn() tries
    /// to avoid that by using a Fn instead. Follow up with upstream
    /// to include this in the trait.
    pub fn new(
        components: PotComponents,
        gossip: PotGossip<Block>,
        client: Arc<Client>,
        sync_oracle: Arc<SO>,
        chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
    ) -> Self {
        let PotComponents {
            proof_of_time,
            protocol_state: pot_state,
            ..
        } = components;

        Self {
            proof_of_time,
            pot_state,
            gossip,
            client,
            sync_oracle,
            chain_info_fn,
        }
    }

    /// Starts the workers.
    pub async fn run(self, bootstrap_params: Option<BootstrapParams>) {
        if let Some(params) = bootstrap_params.as_ref() {
            // The clock master is responsible for bootstrapping, build/add the
            // initial proof to the state and start the proof producer.
            self.add_bootstrap_proof(params);
        } else {
            // Wait for sync to complete, get the proof from the tip.
            let proofs = match get_consensus_tip_proofs(
                self.client.clone(),
                self.sync_oracle.clone(),
                self.chain_info_fn.clone(),
            )
            .await
            {
                Ok(proofs) => proofs,
                Err(err) => {
                    error!("clock master: Failed to get initial proofs: {err:?}");
                    return;
                }
            };
            self.pot_state.reset(proofs);
        }

        let (local_proof_sender, mut local_proof_receiver) = channel(PROOFS_CHANNEL_SIZE);

        // Filter out incoming messages without sender_id or that fail to decode.
        let mut incoming_messages = Box::pin(self.gossip.incoming_messages().filter_map(
            |notification| async move {
                let mut ret = None;
                if let Some(sender) = notification.sender {
                    if let Ok(msg) = PotProof::decode(&mut &notification.message[..]) {
                        ret = Some((sender, msg))
                    }
                }
                ret
            },
        ));

        let proof_of_time = self.proof_of_time.clone();
        let pot_state = self.pot_state.clone();
        thread::Builder::new()
            .name("pot-proof-producer".to_string())
            .spawn(move || {
                Self::produce_proofs(proof_of_time, pot_state, local_proof_sender);
            })
            .expect("Failed to spawn PoT proof producer thread");

        loop {
            //let engine = self.gossip.engine.clone();
            //let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                local_proof = local_proof_receiver.recv().fuse() => {
                    if let Some(proof) = local_proof {
                        trace!("clock_master: got local proof: {proof}");
                        self.handle_local_proof(proof);
                    }
                },
                gossiped = incoming_messages.next().fuse() => {
                    if let Some((sender, proof)) = gossiped {
                        trace!("clock_master: got gossiped proof: {sender} => {proof}");
                        self.handle_gossip_message(self.pot_state.as_ref(), sender, proof);
                    }
                },
                _ = self.gossip.is_terminated().fuse() => {
                    error!("clock_master: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Long running loop to produce the proofs.
    fn produce_proofs(
        proof_of_time: ProofOfTime,
        state: Arc<dyn PotProtocolState>,
        proof_sender: Sender<PotProof>,
    ) {
        loop {
            // Build the next proof on top of the latest tip.
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
                trace!("clock_master::produce proofs: failed to extend chain: {e:?}");
                continue;
            } else if let Err(e) = proof_sender.blocking_send(next_proof.clone()) {
                warn!("clock_master::produce proofs: send failed: {e:?}");
                return;
            }
        }
    }

    /// Gossips the locally generated proof.
    fn handle_local_proof(&self, proof: PotProof) {
        self.gossip.gossip_message(proof.encode());
    }

    /// Handles the incoming gossip message.
    fn handle_gossip_message(&self, state: &dyn PotProtocolState, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            trace!("clock_master::on gossip: {err:?}, {sender}");
        } else {
            trace!("clock_master::on gossip: {proof}, time=[{elapsed:?}], {sender}");
            self.gossip.gossip_message(proof.encode());
        }
    }

    /// Builds/adds the bootstrap proof to the state.
    fn add_bootstrap_proof(&self, params: &BootstrapParams) {
        let proof = self.proof_of_time.create(
            PotSeed::from_block_hash(params.genesis_hash),
            params.key,
            params.slot,
            params.genesis_hash,
        );
        let proofs = NonEmptyVec::new(vec![proof]).expect("Vec is non empty");
        self.pot_state.reset(proofs);
    }
}
