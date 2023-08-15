//! Consensus node interface to the time keeper network.

use crate::gossip::PotGossip;
use crate::state_manager::PotProtocolState;
use crate::PotComponents;
use futures::{FutureExt, StreamExt};
use sc_client_api::{BlockImportNotification, BlockchainEvents};
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::sync::Arc;
use std::time::Instant;
use subspace_core_primitives::{BlockNumber, PotProof};
use tracing::{debug, error, trace, warn};

/// The PoT client implementation
pub struct PotClient<Block: BlockT<Hash = H256>, Client> {
    pot_state: Arc<dyn PotProtocolState>,
    gossip: PotGossip<Block>,
    client: Arc<Client>,
}

impl<Block, Client> PotClient<Block, Client>
where
    Block: BlockT<Hash = H256>,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
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
        let mut block_import = self.client.import_notification_stream();
        loop {
            futures::select! {
                incoming_block = block_import.next().fuse() => {
                    if let Some(incoming_block) = incoming_block {
                        self.handle_block_import(incoming_block);
                    }
                }
                _ = self.gossip.process_incoming_messages(
                    handle_gossip_message.clone()
                ).fuse() => {
                    error!("Gossip engine has terminated");
                    return;
                }
            }
        }
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

    /// Handles the block import notification.
    fn handle_block_import(&self, incoming_block: BlockImportNotification<Block>) {
        match extract_pre_digest(&incoming_block.header) {
            Ok(pre_digest) => {
                self.pot_state.on_block_import(
                    (*incoming_block.header.number()).into(),
                    incoming_block.hash.into(),
                    *pre_digest.slot,
                );
            }
            Err(err) => {
                warn!(
                    "pot_client::block_import: failed to get pre_digest: {}/{:?}/{err:?}",
                    incoming_block.hash, incoming_block.origin
                );
            }
        }
    }
}
