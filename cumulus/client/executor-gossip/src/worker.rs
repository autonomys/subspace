use crate::{topic, GossipMessage, GossipMessageHandler, GossipValidator, LOG_TARGET};
use futures::{future, FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network_gossip::GossipEngine;
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_executor::{SignedBundle, SignedExecutionReceipt};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;

/// A worker plays the executor gossip protocol.
pub struct GossipWorker<PBlock, Block, Executor>
where
	PBlock: BlockT,
	Block: BlockT,
	Executor: GossipMessageHandler<PBlock, Block>,
{
	gossip_validator: Arc<GossipValidator<PBlock, Block, Executor>>,
	gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
	bundle_receiver: TracingUnboundedReceiver<SignedBundle<Block::Extrinsic>>,
	execution_receipt_receiver: TracingUnboundedReceiver<
		SignedExecutionReceipt<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
	>,
}

impl<PBlock, Block, Executor> GossipWorker<PBlock, Block, Executor>
where
	PBlock: BlockT,
	Block: BlockT,
	Executor: GossipMessageHandler<PBlock, Block>,
{
	pub(super) fn new(
		gossip_validator: Arc<GossipValidator<PBlock, Block, Executor>>,
		gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
		bundle_receiver: TracingUnboundedReceiver<SignedBundle<Block::Extrinsic>>,
		execution_receipt_receiver: TracingUnboundedReceiver<
			SignedExecutionReceipt<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
		>,
	) -> Self {
		Self { gossip_validator, gossip_engine, bundle_receiver, execution_receipt_receiver }
	}

	fn gossip_bundle(&self, bundle: SignedBundle<Block::Extrinsic>) {
		let outgoing_message: GossipMessage<PBlock, Block> = bundle.into();
		let encoded_message = outgoing_message.encode();
		self.gossip_validator.note_rebroadcasted(&encoded_message);
		self.gossip_engine
			.lock()
			.gossip_message(topic::<Block>(), encoded_message, false);
	}

	fn gossip_execution_receipt(
		&self,
		execution_receipt: SignedExecutionReceipt<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
	) {
		let outgoing_message: GossipMessage<PBlock, Block> = execution_receipt.into();
		let encoded_message = outgoing_message.encode();
		self.gossip_validator.note_rebroadcasted(&encoded_message);
		self.gossip_engine
			.lock()
			.gossip_message(topic::<Block>(), encoded_message, false);
	}

	pub(super) async fn run(mut self) {
		let mut incoming =
			Box::pin(self.gossip_engine.lock().messages_for(topic::<Block>()).filter_map(
				|notification| async move {
					GossipMessage::<PBlock, Block>::decode(&mut &notification.message[..]).ok()
				},
			));

		loop {
			let engine = self.gossip_engine.clone();
			let gossip_engine = future::poll_fn(|cx| engine.lock().poll_unpin(cx));

			futures::select! {
				gossip_message = incoming.next().fuse() => {
					if let Some(message) = gossip_message {
						tracing::debug!(target: LOG_TARGET, ?message, "Rebroadcasting an executor gossip message");
						match message {
							GossipMessage::Bundle(bundle) => self.gossip_bundle(bundle),
							GossipMessage::ExecutionReceipt(execution_receipt) => self.gossip_execution_receipt(execution_receipt)
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
				execution_receipt = self.execution_receipt_receiver.next().fuse() => {
					if let Some(execution_receipt) = execution_receipt {
						self.gossip_execution_receipt(execution_receipt);
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
