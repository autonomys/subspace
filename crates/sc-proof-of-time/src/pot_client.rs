//! subspace-node consumes the proofs produced by the clock
//! master network. The Pot client is the interface to the
//! clock masters from the subspace-node side.

use crate::pot_state::{pot_client_state, PotClientState};
use crate::utils::{topic, PotGossipVaidator, GOSSIP_PROTOCOL, LOG_TARGET};
use crate::PotConfig;
use futures::{FutureExt, StreamExt};
use parity_scale_codec::Decode;
use parking_lot::Mutex;
use sc_network::PeerId;
use sc_network_gossip::{GossipEngine, Syncing as GossipSyncing};
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
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
}

impl<Block: BlockT> PotClient<Block> {
    /// Creates the PoT client instance.
    pub fn new<Network, GossipSync>(
        config: PotConfig,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let gossip_validator = Arc::new(PotGossipVaidator::new());
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            GOSSIP_PROTOCOL,
            gossip_validator,
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
        }
    }

    /// Starts the workers.
    pub async fn run(mut self) {
        let state = pot_client_state(self.config.clone(), self.proof_of_time.clone());
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

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
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

    /// Handles the incoming gossip message.
    fn on_gossip_message(&mut self, state: &dyn PotClientState, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            warn!(target: LOG_TARGET, "pot_client::on gossip: {err:?}, {sender}");
        } else {
            info!(target: LOG_TARGET, "pot_client::on gossip: {proof}, time=[{elapsed:?}], {sender}");
        }
    }
}
