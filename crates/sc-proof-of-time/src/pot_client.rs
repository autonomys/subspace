//! subspace-node consumes the proofs produced by the clock
//! master network. The Pot client is the interface to the
//! clock masters from the subspace-node side.

use crate::pot_state::{pot_state, PotStateInterface};
use crate::utils::{topic, PotGossip, LOG_TARGET};
use crate::PotConfig;
use futures::{FutureExt, StreamExt};
use parity_scale_codec::Decode;
use sc_network::PeerId;
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::PotProof;
use subspace_proof_of_time::ProofOfTime;
use tracing::{debug, error, info, warn};

/// The PoT client implementation
pub struct PotClient<Block: BlockT> {
    config: PotConfig,
    proof_of_time: Arc<ProofOfTime>,
    gossip: PotGossip<Block>,
}

impl<Block: BlockT> PotClient<Block> {
    /// Creates the PoT client instance.
    pub fn new(config: PotConfig, gossip: PotGossip<Block>) -> Self {
        let proof_of_time = Arc::new(ProofOfTime::new(
            config.num_checkpoints,
            config.checkpoint_iterations,
        ));

        Self {
            config,
            proof_of_time,
            gossip,
        }
    }

    /// Starts the workers.
    pub async fn run(
        mut self,
        mut local_proof_receiver: Option<TracingUnboundedReceiver<PotProof>>,
    ) {
        let state = pot_state(self.config.clone(), self.proof_of_time.clone());
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

        loop {
            let engine = self.gossip.engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                local_proof = Self::next_local_proof(local_proof_receiver.as_mut()).fuse() => {
                    if let Some(proof) = local_proof {
                        debug!(target: LOG_TARGET, "clock_master: got local proof: {proof}");
                        self.on_local_proof(state.as_ref(), proof);
                    }
                },
                gossiped = incoming_messages.next().fuse() => {
                    if let Some((sender, proof)) = gossiped {
                        debug!(target: LOG_TARGET, "pot_client: got gossiped proof: {sender} => {proof}");
                        self.on_gossip_message(state.as_ref(), sender, proof);
                    }
                },
                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "pot_client: gossip engine has terminated.");
                    return;
                }
            }
        }
    }

    /// Handles the locally generated proof from clock master.
    fn on_local_proof(&mut self, state: &dyn PotStateInterface, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = state.on_proof(&proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            warn!(target: LOG_TARGET, "pot_client::local proof: {err:?}");
        } else {
            info!(target: LOG_TARGET, "pot_client::local proof: {proof}, time=[{elapsed:?}]");
        }
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
            warn!(target: LOG_TARGET, "pot_client::on gossip: {err:?}, {sender}");
        } else {
            info!(target: LOG_TARGET, "pot_client::on gossip: {proof}, time=[{elapsed:?}], {sender}");
        }
    }

    /// Helper to receive the next local proof, if local clock master is
    /// enabled.
    async fn next_local_proof(
        local_proof_receiver: Option<&mut TracingUnboundedReceiver<PotProof>>,
    ) -> Option<PotProof> {
        match local_proof_receiver {
            Some(receiver) => receiver.next().await,
            None => {
                futures::future::pending::<PotProof>().await;
                None
            }
        }
    }
}
