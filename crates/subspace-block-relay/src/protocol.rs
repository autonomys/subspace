/// Common define for the block relay.

use async_trait::async_trait;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network_gossip::TopicNotification;
use sc_service::config::IncomingRequest;
use sp_runtime::traits::{Block as BlockT};

pub use crate::worker::{init_block_relay_config, BlockRelayWorker};

#[async_trait]
pub trait BlockRelayProtocol<Block: BlockT> : Send + Sync {
    /// The gossip topic to be used for announcements.
    fn block_announcement_topic(&self) -> Block::Hash;

    /// Handles the block import notifications.
    async fn on_block_import(&self, notification: ImportedBlockNotification<Block>);

    /// Handles the block announcements from peers.
    async fn on_block_announcement(&self, message: TopicNotification);

    /// Handles the protocol handshake messages from peers.
    async fn on_protocol_message(&self, request: IncomingRequest);
}
