use crate::{topic, GossipMessage, GossipMessageHandler, GossipValidator, LOG_TARGET};
use futures::{future, FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network_gossip::GossipEngine;
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_executor::{Bundle, ExecutionReceipt};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// A worker plays the executor gossip protocol.
pub struct GossipWorker<Block: BlockT, E> {
	executor: E,
	gossip_validator: Arc<GossipValidator<Block>>,
	gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
	bundle_receiver: TracingUnboundedReceiver<Bundle<Block::Extrinsic>>,
	execution_receipt_receiver: TracingUnboundedReceiver<ExecutionReceipt<Block::Hash>>,
}

impl<Block: BlockT, E: GossipMessageHandler<Block>> GossipWorker<Block, E> {
	pub(super) fn new(
		executor: E,
		gossip_validator: Arc<GossipValidator<Block>>,
		gossip_engine: Arc<Mutex<GossipEngine<Block>>>,
		bundle_receiver: TracingUnboundedReceiver<Bundle<Block::Extrinsic>>,
		execution_receipt_receiver: TracingUnboundedReceiver<ExecutionReceipt<Block::Hash>>,
	) -> Self {
		Self {
			executor,
			gossip_validator,
			gossip_engine,
			bundle_receiver,
			execution_receipt_receiver,
		}
	}

	pub(super) async fn run(mut self) {
		let mut incoming =
			Box::pin(self.gossip_engine.lock().messages_for(topic::<Block>()).filter_map(
				|notification| async move {
					GossipMessage::<Block>::decode(&mut &notification.message[..]).ok()
				},
			));

		loop {
			let engine = self.gossip_engine.clone();
			let gossip_engine = future::poll_fn(|cx| engine.lock().poll_unpin(cx));

			futures::select! {
				gossip_message = incoming.next().fuse() => {
					if let Some(message) = gossip_message {
						tracing::debug!(target: LOG_TARGET, ?message, "Received a new executor gossip message");
						match message {
							GossipMessage::Bundle(bundle) => {
								let outcome = self.executor.on_bundle(&bundle).await;
								if outcome.rebroadcast_bundle() {
									let outgoing_message: GossipMessage<Block> = bundle.into();
									let encoded_message = outgoing_message.encode();
									self.gossip_engine.lock().gossip_message(topic::<Block>(), encoded_message, false);
								}
							}
							GossipMessage::ExecutionReceipt(execution_receipt) => {
								let outcome = self.executor.on_execution_receipt(&execution_receipt).await;
								if outcome.rebroadcast_execution_receipt() {
									let outgoing_message: GossipMessage<Block> = execution_receipt.into();
									let encoded_message = outgoing_message.encode();
									self.gossip_engine.lock().gossip_message(topic::<Block>(), encoded_message, false);
								}
							}
						}
					} else {
						return
					}
				}
				bundle = self.bundle_receiver.next().fuse() => {
					if let Some(bundle) = bundle {
						let outgoing_message: GossipMessage<Block> = bundle.into();
						let encoded_message = outgoing_message.encode();
						self.gossip_engine.lock().gossip_message(topic::<Block>(), encoded_message, false);
					}
				}
				execution_receipt = self.execution_receipt_receiver.next().fuse() => {
					if let Some(execution_receipt) = execution_receipt {
						let outgoing_message: GossipMessage<Block> = execution_receipt.into();
						let encoded_message = outgoing_message.encode();
						self.gossip_engine.lock().gossip_message(topic::<Block>(), encoded_message, false);
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
