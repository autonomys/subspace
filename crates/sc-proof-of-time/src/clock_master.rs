//! Clock master implementation.

use crate::{clock_master_state, ClockMasterState, InitialPotProofInputs, PotConfig, LOG_TARGET};
use futures::{FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::config::NonDefaultSetConfig;
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Syncing as GossipSyncing, ValidationResult, Validator,
    ValidatorContext,
};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
use sp_consensus::SyncOracle;
use sp_core::twox_256;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::{self, Instant};
use subspace_core_primitives::{PotProof, PotSeed};
use subspace_proof_of_time::ProofOfTime;
use tracing::{debug, error, info, warn};

const PROTOCOL_NAME: &str = "/subspace/pot-clock-master";

type MessageHash = [u8; 32];

/// The clock master manages the protocol: periodic proof generation/verification, gossip.
pub struct ClockMaster<Block: BlockT, SO: SyncOracle + Send + Sync + Clone + 'static> {
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    gossip_validator: Arc<ClockMasterGossipValidator>,
    sync_oracle: Arc<SO>,
}

impl<Block, SO> ClockMaster<Block, SO>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    /// Creates the clock master instance.
    pub fn new<Network, GossipSync>(
        config: PotConfig,
        network: Network,
        sync: Arc<GossipSync>,
        sync_oracle: Arc<SO>,
    ) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let gossip_validator = Arc::new(ClockMasterGossipValidator {
            pending: RwLock::new(HashSet::new()),
        });
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            PROTOCOL_NAME,
            gossip_validator.clone(),
            None,
        )));
        let proof_of_time = Arc::new(ProofOfTime::new(
            config.num_checkpoints,
            config.checkpoint_iterations,
        ));

        Self {
            config,
            proof_of_time,
            gossip_engine,
            gossip_validator,
            sync_oracle,
        }
    }

    /// Starts the workers.
    pub async fn run(mut self, init_fn: Box<dyn Fn() -> Option<InitialPotProofInputs> + Send>) {
        let (proof_sender, mut proof_receiver) = tracing_unbounded("pot-local-proofs-channel", 100);
        let state = clock_master_state(
            self.config.clone(),
            self.proof_of_time.clone(),
            self.create_initial_proof(init_fn).await,
        );

        let mut incoming_messages = Box::pin(
            self.gossip_engine
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
                Self::produce_proofs(proof_of_time, sync_oracle, state_cl, proof_sender);
            })
            .expect("Failed to spawn PoT proof producer thread");

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                local_proof = proof_receiver.next().fuse() => {
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
        state: Arc<dyn ClockMasterState>,
        proof_sender: TracingUnboundedSender<PotProof>,
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
            let last_proof = state.tip();

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
                .expect("Proof creation  cannot fail");
            let elapsed = start_ts.elapsed();
            info!(target: LOG_TARGET, "clock_master::produce proofs: {next_proof}, time=[{elapsed:?}]");

            // Store the new proof back into the chain and gossip to other clock masters.
            if let Err(err) = state.on_proof(&next_proof) {
                info!(target: LOG_TARGET, "clock_master::produce proofs: failed to extend chain: {err:?}");
            } else if let Err(e) = proof_sender.unbounded_send(next_proof) {
                warn!(target: LOG_TARGET, "clock_master::produce proofs: failed to gossip: {e:?}");
            }
        }
    }

    /// Gossips the locally generated proof.
    fn on_local_proof(&mut self, proof: PotProof) {
        let encoded_msg = proof.encode();
        self.gossip_validator.on_broadcast(&encoded_msg);
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_msg, false);
    }

    /// Handles the incoming gossip message.
    fn on_gossip_message(&mut self, state: &dyn ClockMasterState, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            warn!(target: LOG_TARGET, "clock_master::on gossip: {err:?}");
        } else {
            info!(target: LOG_TARGET, "clock_master::on gossip: {proof}, time=[{elapsed:?}]");
            let encoded_msg = proof.encode();
            self.gossip_validator.on_broadcast(&encoded_msg);
            self.gossip_engine
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

/// Validator for gossiped messages
#[derive(Debug)]
struct ClockMasterGossipValidator {
    pending: RwLock<HashSet<MessageHash>>,
}

impl ClockMasterGossipValidator {
    /// Called when the message is broadcast.
    fn on_broadcast(&self, msg: &[u8]) {
        let hash = twox_256(msg);
        let mut pending = self.pending.write();
        pending.insert(hash);
    }
}

impl<Block: BlockT> Validator<Block> for ClockMasterGossipValidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match PotProof::decode(&mut data) {
            Ok(_) => ValidationResult::ProcessAndKeep(topic::<Block>()),
            Err(_) => ValidationResult::Discard,
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let hash = twox_256(data);
            let pending = self.pending.read();
            !pending.contains(&hash)
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, data| {
            let hash = twox_256(data);
            let mut pending = self.pending.write();
            if pending.contains(&hash) {
                pending.remove(&hash);
                true
            } else {
                false
            }
        })
    }
}

/// PoT message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"subspace-pot-gossip-messages")
}

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(PROTOCOL_NAME.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}
