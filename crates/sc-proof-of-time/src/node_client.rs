//! Consensus node interface to the time keeper network.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::PotProof;
use tracing::{error, trace};

/// The PoT client implementation
pub struct PotClient<Block: BlockT<Hash = H256>> {
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
}

impl<Block> PotClient<Block>
where
    Block: BlockT<Hash = H256>,
{
    /// Creates the PoT client instance.
    pub fn new<Network, GossipSync>(
        components: PotComponents,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> Self
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        Self {
            pot_state: components.protocol_state.clone(),
            gossip: PotGossip::new(
                network,
                sync,
                components.protocol_state,
                components.proof_of_time,
            ),
        }
    }

    /// Runs the node client processing loop.
    pub async fn run(self) {
        let handle_gossip_message: Arc<dyn Fn(PeerId, PotProof) + Send + Sync> =
            Arc::new(|sender, proof| {
                self.handle_gossip_message(sender, proof);
            });
        self.gossip
            .process_incoming_messages(handle_gossip_message)
            .await;
        error!("Gossip engine has terminated");
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
