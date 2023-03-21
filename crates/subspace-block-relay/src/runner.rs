//! Block relay protocol runner.

use crate::protocol::BlockRelayProtocol;
use crate::LOG_TARGET;
use futures::channel::mpsc::Receiver;
use futures::{FutureExt, StreamExt};
use parking_lot::Mutex;
use sc_consensus_subspace::ImportedBlockNotification;
use sc_network_gossip::GossipEngine;
use sc_service::config::IncomingRequest;
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use tracing::{error, info};

/// The block relay runner acts as an interface between the event sources and the protocol implementation.
pub struct BlockRelayRunner<Block: BlockT> {
    /// The backend protocol.
    protocol: Box<dyn BlockRelayProtocol<Block>>,

    /// Block announcement stream.
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,

    /// Block import notification stream.
    import_notifications: TracingUnboundedReceiver<ImportedBlockNotification<Block>>,

    /// Protocol message stream.
    protocol_messages: Receiver<IncomingRequest>,
}

impl<Block: BlockT> BlockRelayRunner<Block> {
    pub fn new(
        protocol: Box<dyn BlockRelayProtocol<Block>>,
        gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
        import_notifications: TracingUnboundedReceiver<ImportedBlockNotification<Block>>,
        protocol_messages: Receiver<IncomingRequest>,
    ) -> Self {
        Self {
            protocol,
            gossip_engine,
            import_notifications,
            protocol_messages,
        }
    }

    /// The event loop.
    pub async fn run(mut self) {
        info!(target: LOG_TARGET, "BlockRelayRunner: started");
        let mut block_announcements = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(self.protocol.block_announcement_topic()),
        );

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = futures::future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                block_import = self.import_notifications.next().fuse() => {
                    if let Some(block_import) = block_import {
                        self.protocol.on_block_import(block_import).await;
                    }
                }
                block_announcement = block_announcements.next().fuse() => {
                    if let Some(block_announcement) = block_announcement {
                        self.protocol.on_block_announcement(block_announcement).await;
                    }
                }
                protocol_message = self.protocol_messages.next().fuse() => {
                    if let Some(protocol_message) = protocol_message {
                        self.protocol.on_protocol_message(protocol_message).await;
                    }
                },

                _ = gossip_engine.fuse() => {
                    error!(target: LOG_TARGET, "BlockRelayRunner(): gossip engine has terminated.");
                    return;
                }
            }
        }
    }
}
