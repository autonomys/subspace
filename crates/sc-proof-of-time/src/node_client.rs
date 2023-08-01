//! Consensus node interface to the clock master network.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::utils::get_consensus_tip_proofs;
use crate::PotComponents;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::PotProof;
use tracing::{error, trace};

/// The PoT client implementation
pub struct PotClient<Block: BlockT, Client, SO> {
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
}

impl<Block, Client, SO> PotClient<Block, Client, SO>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    /// Creates the PoT client instance.
    pub fn new<Network, GossipSync>(
        components: PotComponents<Block>,
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
        Self {
            pot_state: components.protocol_state.clone(),
            gossip: PotGossip::new(network, sync, components.protocol_state),
            client,
            sync_oracle,
            chain_info_fn,
        }
    }

    /// Runs the node client processing loop.
    pub async fn run(self) {
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
                error!("PoT client: Failed to get initial proofs: {err:?}");
                return;
            }
        };
        self.pot_state.reset(proofs);

        let handle_gossip_message: Arc<dyn Fn(PeerId, PotProof)> = Arc::new(|sender, proof| {
            self.handle_gossip_message(sender, proof);
        });
        self.gossip
            .process_incoming_messages(handle_gossip_message)
            .await;
        error!("pot_client: gossip engine has terminated.");
    }

    /// Handles the incoming gossip message.
    fn handle_gossip_message(&self, sender: PeerId, proof: PotProof) {
        let start_ts = Instant::now();
        let ret = self.pot_state.on_proof_from_peer(sender, &proof);
        let elapsed = start_ts.elapsed();

        if let Err(err) = ret {
            trace!("pot_client::on gossip: {err:?}, {sender}");
        } else {
            trace!("pot_client::on gossip: {proof}, time=[{elapsed:?}], {sender}");
        }
    }
}
