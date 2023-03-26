/// Common define for the block relay.
use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network::{PeerId, RequestFailure};
use sc_network_gossip::TopicNotification;
use sc_service::config::IncomingRequest;
use sc_service::Configuration;
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Instant;

mod full_block;

use crate::protocol::full_block::{init_full_block_config, FullBlockRelay};
use crate::runner::BlockRelayRunner;

pub(crate) type GossipNetworkService<Block> =
    sc_network::NetworkService<Block, <Block as BlockT>::Hash>;

#[async_trait]
pub trait BlockRelayProtocol<Block: BlockT>: Send {
    /// The gossip topic to be used for announcements.
    fn block_announcement_topic(&self) -> Block::Hash;

    /// Handles the block import notifications.
    async fn on_block_import(&mut self, notification: ImportedBlockNotification<Block>);

    /// Handles the block announcements from peers.
    async fn on_block_announcement(&mut self, message: TopicNotification);

    /// Handles the protocol handshake messages from peers.
    async fn on_protocol_message(&mut self, request: IncomingRequest);

    /// Interface to drive any protocol specific polling.
    async fn poll(&mut self);
}

/// Async response to start_request().
pub(crate) struct ProtocolResponse<ReqId> {
    /// Peer to which the request was sent.
    peer_id: PeerId,

    /// Protocol specific request identifier.
    request_id: ReqId,

    /// The response. Set to None if the oneshot receiver returned Canceled.
    response: Option<Result<Vec<u8>, RequestFailure>>,

    /// When the request was sent.
    request_ts: Instant,
}

/// Block identifier.
#[derive(Clone, Encode, Decode, Eq, PartialEq)]
pub(crate) struct BlockInfo<Block: BlockT> {
    /// Block number
    pub block_number: NumberFor<Block>,

    /// Block hash
    pub block_hash: Block::Hash,

    /// Parent block hash
    pub parent_hash: Block::Hash,
}

impl<Block: BlockT> From<&ImportedBlockNotification<Block>> for BlockInfo<Block> {
    fn from(notification: &ImportedBlockNotification<Block>) -> Self {
        Self {
            block_number: notification.block_number,
            block_hash: notification.block_hash,
            parent_hash: notification.parent_hash,
        }
    }
}

impl<Block: BlockT> Hash for BlockInfo<Block> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_number.hash(state);
        self.block_hash.hash(state);
        self.parent_hash.hash(state);
    }
}

impl<Block: BlockT> fmt::Display for BlockInfo<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Block[number = {}, hash = {}, parent = {}]",
            self.block_number, self.block_hash, self.parent_hash
        )
    }
}

/// Initializes the block relay specific parts in the network config.
pub fn init_block_relay_config(config: &mut Configuration) -> Receiver<IncomingRequest> {
    init_full_block_config(config)
}

/// Creates the protocol implementation and the runner to drive the protocol.
/// Takes the receive endpoint previously created by init_block_relay_config() as
/// input.
pub fn build_block_relay<Block, Client>(
    network: Arc<GossipNetworkService<Block>>,
    client: Arc<Client>,
    import_queue: Box<dyn ImportQueueService<Block>>,
    import_notifications: TracingUnboundedReceiver<ImportedBlockNotification<Block>>,
    receiver: Receiver<IncomingRequest>,
) -> BlockRelayRunner<Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
{
    let (protocol, gossip_engine) = FullBlockRelay::new(network, client, import_queue);
    BlockRelayRunner::new(
        Box::new(protocol),
        gossip_engine,
        import_notifications,
        receiver,
    )
}
