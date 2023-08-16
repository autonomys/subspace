//! Consensus node interface to the time keeper network.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use futures::StreamExt;
use sc_client_api::BlockchainEvents;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::PotProof;
use tracing::{error, info, trace, warn};

/// The PoT client implementation
pub struct PotClient<Block: BlockT<Hash = H256>, Client> {
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
    client: Arc<Client>,
}

impl<Block, Client> PotClient<Block, Client>
where
    Block: BlockT<Hash = H256>,
    Client: HeaderBackend<Block> + BlockchainEvents<Block>,
{
    /// Creates the PoT client instance.
    pub fn new<Network, GossipSync>(
        components: PotComponents,
        client: Arc<Client>,
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
            client,
        }
    }

    /// Runs the node client processing loop.
    pub async fn run(self) {
        self.initialize().await;
        let handle_gossip_message: Arc<dyn Fn(PeerId, PotProof) + Send + Sync> =
            Arc::new(|sender, proof| {
                self.handle_gossip_message(sender, proof);
            });
        self.gossip
            .process_incoming_messages(handle_gossip_message)
            .await;
        error!("pot_client: gossip engine has terminated.");
    }

    /// Initializes the chain state from the consensus tip info.
    async fn initialize(&self) {
        info!("pot_client::initialize: waiting for initialization ...");

        // Wait for a block with proofs.
        let mut block_import = self.client.import_notification_stream();
        while let Some(incoming_block) = block_import.next().await {
            let pre_digest = match extract_pre_digest(&incoming_block.header) {
                Ok(pre_digest) => pre_digest,
                Err(err) => {
                    warn!(
                        "pot_client::initialize: failed to get pre_digest: {}/{:?}/{err:?}",
                        incoming_block.hash, incoming_block.origin
                    );
                    continue;
                }
            };

            let pot_pre_digest = match pre_digest.pot_pre_digest() {
                Some(pot_pre_digest) => pot_pre_digest,
                None => {
                    warn!(
                        "pot_client::initialize: failed to get pot_pre_digest: {}/{:?}",
                        incoming_block.hash, incoming_block.origin
                    );
                    continue;
                }
            };

            if pot_pre_digest.proofs().is_some() {
                info!(
                    "pot_client::initialize: initialization complete: {}/{:?}, pot_pre_digest = {:?}",
                    incoming_block.hash, incoming_block.origin, pot_pre_digest
                );
                return;
            }
        }
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
