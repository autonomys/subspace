//! Consensus node interface to the time keeper network.

use crate::gossip::PotGossip;
use crate::PotComponents;
use futures::StreamExt;
use sc_client_api::BlockchainEvents;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use tracing::{debug, error, trace, warn};

/// The PoT client implementation
pub struct PotClient<Block: BlockT<Hash = H256>, Client> {
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
        self.gossip.process_incoming_messages().await;
        error!("Gossip engine has terminated");
    }

    /// Initializes the chain state from the consensus tip info.
    async fn initialize(&self) {
        debug!("Waiting for initialization");

        // Wait for a block with proofs.
        let mut block_import = self.client.import_notification_stream();
        while let Some(incoming_block) = block_import.next().await {
            let pre_digest = match extract_pre_digest(&incoming_block.header) {
                Ok(pre_digest) => pre_digest,
                Err(error) => {
                    warn!(
                        %error,
                        block_hash = %incoming_block.hash,
                        origin = ?incoming_block.origin,
                        "Failed to get pre_digest",
                    );
                    continue;
                }
            };

            let pot_pre_digest = match pre_digest.pot_pre_digest() {
                Some(pot_pre_digest) => pot_pre_digest,
                None => {
                    warn!(
                        block_hash = %incoming_block.hash,
                        origin = ?incoming_block.origin,
                        "Failed to get pot_pre_digest",
                    );
                    continue;
                }
            };

            if pot_pre_digest.proofs().is_some() {
                trace!(
                    block_hash = %incoming_block.hash,
                    origin = ?incoming_block.origin,
                    ?pot_pre_digest,
                    "Initialization complete",
                );
                return;
            }
        }
    }
}
