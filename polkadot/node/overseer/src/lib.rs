// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! TODO
#![warn(missing_docs)]

use std::{
	collections::{hash_map::Entry, HashMap},
	fmt::Debug,
	sync::Arc,
};

use futures::{select, stream::FusedStream, StreamExt};

use sc_client_api::{BlockBackend, BlockImportNotification, BlockchainEvents};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_runtime::generic::DigestItem;

use cirrus_node_primitives::{CollationGenerationConfig, ExecutorSlotInfo};
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use subspace_runtime_primitives::{
	opaque::{Block, BlockId},
	BlockNumber, Hash,
};

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
enum CollationGenerationMessage {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig),
	/// Fraud proof needs to be submitted to primary chain.
	FraudProof(FraudProof),
	/// Bundle equivocation proof needs to be submitted to primary chain.
	BundleEquivocationProof(BundleEquivocationProof),
	/// Invalid transaction proof needs to be submitted to primary chain.
	InvalidTransactionProof(InvalidTransactionProof),
}

const LOG_TARGET: &str = "overseer";

/// Apply the transaction bundles for given primary block as follows:
///
/// 1. Extract the transaction bundles from the block.
/// 2. Pass the bundles to secondary node and do the computation there.
async fn process_primary_block<Client>(
	client: Arc<Client>,
	config: &CollationGenerationConfig,
	block_hash: Hash,
) -> Result<(), ApiError>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	let block_id = BlockId::Hash(block_hash);
	let extrinsics = match client.block_body(&block_id) {
		Err(err) => {
			tracing::error!(
				target: LOG_TARGET,
				?err,
				"Failed to get block body from primary chain"
			);
			return Ok(())
		},
		Ok(None) => {
			tracing::error!(target: LOG_TARGET, ?block_hash, "BlockBody unavailable");
			return Ok(())
		},
		Ok(Some(body)) => body,
	};

	let bundles = client.runtime_api().extract_bundles(&block_id, extrinsics)?;

	let header = match client.header(block_id) {
		Err(err) => {
			tracing::error!(target: LOG_TARGET, ?err, "Failed to get block from primary chain");
			return Ok(())
		},
		Ok(None) => {
			tracing::error!(target: LOG_TARGET, ?block_hash, "BlockHeader unavailable");
			return Ok(())
		},
		Ok(Some(header)) => header,
	};

	let maybe_new_runtime = if header
		.digest
		.logs
		.iter()
		.any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
	{
		Some(client.runtime_api().execution_wasm_bundle(&block_id)?)
	} else {
		None
	};

	let shuffling_seed = client.runtime_api().extrinsics_shuffling_seed(&block_id, header)?;

	let opaque_execution_receipt =
		match (config.processor)(block_hash, bundles, shuffling_seed, maybe_new_runtime).await {
			Some(processor_result) => processor_result.to_opaque_execution_receipt(),
			None => {
				tracing::debug!(
					target: LOG_TARGET,
					"Skip sending the execution receipt because executor is not elected",
				);
				return Ok(())
			},
		};

	let best_hash = client.info().best_hash;

	// TODO: Handle returned result?
	client
		.runtime_api()
		.submit_execution_receipt_unsigned(&BlockId::Hash(best_hash), opaque_execution_receipt)?;

	Ok(())
}

/// Activated leaf.
#[derive(Debug, Clone)]
pub struct ActivatedLeaf {
	/// The block hash.
	pub hash: Hash,
	/// The block number.
	pub number: BlockNumber,
}

/// A handle used to communicate with the [`Overseer`].
///
/// [`Overseer`]: struct.Overseer.html
#[derive(Clone)]
pub struct Handle(OverseerHandle);

impl Handle {
	/// Create a new [`Handle`].
	fn new(raw: OverseerHandle) -> Self {
		Self(raw)
	}

	/// Inform the `Overseer` that that some block was imported.
	async fn block_imported(&mut self, block: BlockInfo) {
		self.send_and_log_error(Event::BlockImported(block)).await
	}

	/// Send some message to one of the `Subsystem`s.
	async fn send_msg(&mut self, msg: CollationGenerationMessage) {
		self.send_and_log_error(Event::MsgToSubsystem(msg)).await
	}

	/// Inform the `Overseer` that a new slot was triggered.
	async fn slot_arrived(&mut self, slot_info: ExecutorSlotInfo) {
		self.send_and_log_error(Event::NewSlot(slot_info)).await
	}

	/// Most basic operation, to stop a server.
	async fn send_and_log_error(&mut self, event: Event) {
		if self.0.send(event).await.is_err() {
			tracing::info!(target: LOG_TARGET, "Failed to send an event to Overseer");
		}
	}

	/// TODO
	pub async fn initialize(&mut self, config: CollationGenerationConfig) {
		self.send_msg(CollationGenerationMessage::Initialize(config)).await;
	}

	/// TODO
	pub async fn submit_bundle_equivocation_proof(
		&mut self,
		bundle_equivocation_proof: BundleEquivocationProof,
	) {
		self.send_msg(CollationGenerationMessage::BundleEquivocationProof(
			bundle_equivocation_proof,
		))
		.await
	}

	/// TODO
	pub async fn submit_fraud_proof(&mut self, fraud_proof: FraudProof) {
		self.send_msg(CollationGenerationMessage::FraudProof(fraud_proof)).await;
	}

	/// TODO
	pub async fn submit_invalid_transaction_proof(
		&mut self,
		invalid_transaction_proof: InvalidTransactionProof,
	) {
		self.send_msg(CollationGenerationMessage::InvalidTransactionProof(
			invalid_transaction_proof,
		))
		.await;
	}
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo {
	/// hash of the block.
	pub hash: Hash,
	/// hash of the parent block.
	pub parent_hash: Hash,
	/// block's number.
	pub number: BlockNumber,
}

impl From<BlockImportNotification<Block>> for BlockInfo {
	fn from(n: BlockImportNotification<Block>) -> Self {
		BlockInfo { hash: n.hash, parent_hash: n.header.parent_hash, number: n.header.number }
	}
}

/// An event from outside the overseer scope, such
/// as the substrate framework or user interaction.
enum Event {
	/// A new block was imported.
	BlockImported(BlockInfo),
	/// A new slot arrived.
	NewSlot(ExecutorSlotInfo),
	/// Message as sent to a subsystem.
	MsgToSubsystem(CollationGenerationMessage),
}

/// Glues together the [`Overseer`] and `BlockchainEvents` by forwarding
/// import and finality notifications into the [`OverseerHandle`].
pub async fn forward_events<P: BlockchainEvents<Block>>(
	client: Arc<P>,
	mut slots: impl FusedStream<Item = ExecutorSlotInfo> + Unpin,
	mut handle: Handle,
) {
	let mut imports = client.import_notification_stream();

	loop {
		select! {
			i = imports.next() => {
				match i {
					Some(block) => {
						handle.block_imported(block.into()).await;
					}
					None => break,
				}
			},
			s = slots.next() => {
				match s {
					Some(executor_slot_info) => {
						handle.slot_arrived(executor_slot_info).await;
					}
					None => break,
				}
			}
			complete => break,
		}
	}
}

/// Capacity of a signal channel between a subsystem and the overseer.
const SIGNAL_CHANNEL_CAPACITY: usize = 64usize;
/// The overseer.
pub struct Overseer<Client> {
	primary_chain_client: Arc<Client>,
	config: Option<Arc<CollationGenerationConfig>>,
	/// A user specified addendum field.
	leaves: Vec<(Hash, BlockNumber)>,
	/// A user specified addendum field.
	active_leaves: HashMap<Hash, BlockNumber>,
	/// Events that are sent to the overseer from the outside world.
	events_rx: metered::MeteredReceiver<Event>,
}
/// Handle for an overseer.
type OverseerHandle = metered::MeteredSender<Event>;

impl<Client> Overseer<Client>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	/// Create a new overseer.
	pub fn new(
		primary_chain_client: Arc<Client>,
		leaves: Vec<(Hash, BlockNumber)>,
		active_leaves: HashMap<Hash, BlockNumber>,
	) -> (Self, Handle) {
		let (handle, events_rx) = metered::channel(SIGNAL_CHANNEL_CAPACITY);
		let overseer =
			Overseer { primary_chain_client, config: None, leaves, active_leaves, events_rx };
		(overseer, Handle::new(handle))
	}

	/// Run the `Overseer`.
	pub async fn run(mut self) -> Result<(), ApiError> {
		// Notify about active leaves on startup before starting the loop
		for (hash, number) in std::mem::take(&mut self.leaves) {
			let _ = self.active_leaves.insert(hash, number);
			let update = ActivatedLeaf { hash, number };
			if let Err(error) = self.update_activated_leave(update).await {
				tracing::error!(
					target: LOG_TARGET,
					"Collation generation processing error: {error}"
				);
			}
		}

		while let Some(msg) = self.events_rx.next().await {
			match msg {
				Event::MsgToSubsystem(message) => {
					if let Err(error) = self.handle_message(message).await {
						tracing::error!(
							target: LOG_TARGET,
							"Collation generation processing error: {error}"
						);
					}
				},
				Event::BlockImported(block) => {
					self.block_imported(block).await?;
				},
				Event::NewSlot(slot_info) => {
					if let Err(error) = self.update_new_slot(slot_info).await {
						tracing::error!(
							target: LOG_TARGET,
							"Collation generation processing error: {error}"
						);
					}
				},
			}
		}

		Ok(())
	}

	async fn update_activated_leave(&self, activated_leaf: ActivatedLeaf) -> Result<(), ApiError> {
		// follow the procedure from the guide
		if let Some(config) = &self.config {
			// TODO: invoke this on finalized block?
			process_primary_block(
				Arc::clone(&self.primary_chain_client),
				config,
				activated_leaf.hash,
			)
			.await?;
		}

		Ok(())
	}

	async fn update_new_slot(&self, slot_info: ExecutorSlotInfo) -> Result<(), ApiError> {
		if let Some(config) = &self.config {
			let client = &self.primary_chain_client;
			let best_hash = client.info().best_hash;

			let opaque_bundle = match (config.bundler)(best_hash, slot_info).await {
				Some(bundle_result) => bundle_result.to_opaque_bundle(),
				None => {
					tracing::debug!(target: LOG_TARGET, "executor returned no bundle on bundling",);
					return Ok(())
				},
			};

			// TODO: Handle returned result?
			let _ = client
				.runtime_api()
				.submit_transaction_bundle_unsigned(&BlockId::Hash(best_hash), opaque_bundle)?;
		}

		Ok(())
	}

	async fn handle_message(
		&mut self,
		message: CollationGenerationMessage,
	) -> Result<(), ApiError> {
		let client = &self.primary_chain_client;

		match message {
			CollationGenerationMessage::Initialize(config) =>
				if self.config.is_some() {
					tracing::error!(target: LOG_TARGET, "double initialization");
				} else {
					self.config = Some(Arc::new(config));
				},
			CollationGenerationMessage::FraudProof(fraud_proof) => {
				// TODO: Handle returned result?
				let _ = client.runtime_api().submit_fraud_proof_unsigned(
					&BlockId::Hash(client.info().best_hash),
					fraud_proof,
				)?;
			},
			CollationGenerationMessage::BundleEquivocationProof(bundle_equivocation_proof) => {
				// TODO: Handle returned result?
				let _ = client.runtime_api().submit_bundle_equivocation_proof_unsigned(
					&BlockId::Hash(client.info().best_hash),
					bundle_equivocation_proof,
				)?;
			},
			CollationGenerationMessage::InvalidTransactionProof(invalid_transaction_proof) => {
				// TODO: Handle returned result?
				let _ = self
					.primary_chain_client
					.runtime_api()
					.submit_invalid_transaction_proof_unsigned(
						&BlockId::Hash(client.info().best_hash),
						invalid_transaction_proof,
					)?;
			},
		}

		Ok(())
	}

	async fn block_imported(&mut self, block: BlockInfo) -> Result<(), ApiError> {
		match self.active_leaves.entry(block.hash) {
			Entry::Vacant(entry) => entry.insert(block.number),
			Entry::Occupied(entry) => {
				debug_assert_eq!(*entry.get(), block.number);
				return Ok(())
			},
		};

		let update = ActivatedLeaf { hash: block.hash, number: block.number };

		if let Some(number) = self.active_leaves.remove(&block.parent_hash) {
			debug_assert_eq!(block.number.saturating_sub(1), number);
		}

		if let Err(error) = self.update_activated_leave(update).await {
			tracing::error!(target: LOG_TARGET, "Collation generation processing error: {error}");
		}

		Ok(())
	}
}
