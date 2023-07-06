use crate::{
    topic, BundleFor, BundleReceiver, GossipMessage, GossipMessageHandler, GossipValidator,
    LOG_TARGET,
};
use futures::{future, FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network_gossip::GossipEngine;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// A worker plays the executor gossip protocol.
pub struct GossipWorker<CBlock, Block, Executor>
where
    CBlock: BlockT,
    Block: BlockT,
    Executor: GossipMessageHandler<CBlock, Block>,
{
    gossip_validator: Arc<GossipValidator<CBlock, Block, Executor>>,
    gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
    bundle_receiver: BundleReceiver<Block, CBlock>,
}

impl<CBlock, Block, Executor> GossipWorker<CBlock, Block, Executor>
where
    CBlock: BlockT,
    Block: BlockT,
    Executor: GossipMessageHandler<CBlock, Block>,
{
    pub(super) fn new(
        gossip_validator: Arc<GossipValidator<CBlock, Block, Executor>>,
        gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
        bundle_receiver: BundleReceiver<Block, CBlock>,
    ) -> Self {
        Self {
            gossip_validator,
            gossip_engine,
            bundle_receiver,
        }
    }

    fn gossip_bundle(&self, bundle: BundleFor<Block, CBlock>) {
        let outgoing_message: GossipMessage<CBlock, Block> = bundle.into();
        let encoded_message = outgoing_message.encode();
        self.gossip_validator.note_rebroadcasted(&encoded_message);
        self.gossip_engine
            .lock()
            .gossip_message(topic::<Block>(), encoded_message, false);
    }

    pub(super) async fn run(mut self) {
        let mut incoming = Box::pin(
            self.gossip_engine
                .lock()
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    GossipMessage::<CBlock, Block>::decode(&mut &notification.message[..]).ok()
                }),
        );

        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine = future::poll_fn(|cx| engine.lock().poll_unpin(cx));

            futures::select! {
                gossip_message = incoming.next().fuse() => {
                    if let Some(message) = gossip_message {
                        tracing::debug!(target: LOG_TARGET, ?message, "Rebroadcasting an executor gossip message");
                        match message {
                            GossipMessage::Bundle(bundle) => self.gossip_bundle(bundle),
                        }
                    } else {
                        return
                    }
                }
                bundle = self.bundle_receiver.next().fuse() => {
                    if let Some(bundle) = bundle {
                        self.gossip_bundle(bundle);
                    }
                }
                _ = gossip_engine.fuse() => {
                    tracing::error!(target: LOG_TARGET, "Gossip engine has terminated.");
                    return;
                }
            }
        }
    }
}
