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

use codec::{Decode, Encode};
use futures::{channel::mpsc, select, stream::FusedStream, SinkExt, StreamExt};
use sc_client_api::{BlockBackend, BlockImportNotification};
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_executor::{
	BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof, OpaqueBundle,
	SignedExecutionReceipt, SignedOpaqueBundle,
};
use sp_runtime::{
	generic::{BlockId, DigestItem},
	traits::{Header as HeaderT, NumberFor, One, Saturating},
	OpaqueExtrinsic,
};
use std::{
	borrow::Cow,
	collections::{hash_map::Entry, HashMap},
	fmt::Debug,
	future::Future,
	pin::Pin,
	sync::Arc,
};
use subspace_core_primitives::{Randomness, Tag};
use subspace_runtime_primitives::Hash as PHash;

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub struct ExecutorSlotInfo {
	/// Slot
	pub slot: Slot,
	/// Global slot challenge
	pub global_challenge: Tag,
}

/// Bundle function.
///
/// Will be called with each slot of the primary chain.
///
/// Returns an optional [`SignedOpaqueBundle`].
pub type BundlerFn = Box<
	dyn Fn(
			PHash,
			ExecutorSlotInfo,
		) -> Pin<Box<dyn Future<Output = Option<SignedOpaqueBundle>> + Send>>
		+ Send
		+ Sync,
>;

/// Process function.
///
/// Will be called with the hash of the primary chain block.
///
/// Returns an optional [`OpaqueExecutionReceipt`].
pub type ProcessorFn<Hash> = Box<
	dyn Fn(
			PHash,
			Vec<OpaqueBundle>,
			Randomness,
			Option<Cow<'static, [u8]>>,
		) -> Pin<Box<dyn Future<Output = Option<SignedExecutionReceipt<Hash>>> + Send>>
		+ Send
		+ Sync,
>;

/// Configuration for the collation generator
pub struct CollationGenerationConfig<Hash> {
	/// Transaction bundle function. See [`BundlerFn`] for more details.
	pub bundler: BundlerFn,
	/// State processor function. See [`ProcessorFn`] for more details.
	pub processor: ProcessorFn<Hash>,
}

impl<Hash> std::fmt::Debug for CollationGenerationConfig<Hash> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "CollationGenerationConfig {{ ... }}")
	}
}

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
enum CollationGenerationMessage<Hash> {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig<Hash>),
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
async fn process_primary_block<PBlock, PClient, Hash>(
	client: Arc<PClient>,
	config: &CollationGenerationConfig<Hash>,
	block_hash: PBlock::Hash,
) -> Result<(), ApiError>
where
	PBlock: BlockT,
	PClient: HeaderBackend<PBlock>
		+ BlockBackend<PBlock>
		+ ProvideRuntimeApi<PBlock>
		+ Send
		+ 'static
		+ Sync,
	PClient::Api: ExecutorApi<PBlock, Hash>,
	Hash: Encode + Decode,
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

	let bundles = client.runtime_api().extract_bundles(
		&block_id,
		extrinsics
			.into_iter()
			.map(|xt| {
				OpaqueExtrinsic::from_bytes(&xt.encode()).expect("Certainly a correct extrinsic")
			})
			.collect(),
	)?;

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
		.digest()
		.logs
		.iter()
		.any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
	{
		Some(client.runtime_api().execution_wasm_bundle(&block_id)?)
	} else {
		None
	};

	let shuffling_seed = client.runtime_api().extrinsics_shuffling_seed(&block_id, header)?;

	let non_generic_block_hash =
		PHash::decode(&mut block_hash.encode().as_slice()).expect("Hash type must be correct");

	let execution_receipt = match (config.processor)(
		non_generic_block_hash,
		bundles,
		shuffling_seed,
		maybe_new_runtime,
	)
	.await
	{
		Some(execution_receipt) => execution_receipt,
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
		.submit_execution_receipt_unsigned(&BlockId::Hash(best_hash), execution_receipt)?;

	Ok(())
}

/// Activated leaf.
#[derive(Debug, Clone)]
pub struct ActivatedLeaf<Block>
where
	Block: BlockT,
{
	/// The block hash.
	pub hash: Block::Hash,
	/// The block number.
	pub number: NumberFor<Block>,
}

/// A handle used to communicate with the [`Overseer`].
///
/// [`Overseer`]: struct.Overseer.html
#[derive(Clone)]
pub struct OverseerHandle<PBlock: BlockT, Hash>(mpsc::Sender<Event<PBlock, Hash>>);

impl<PBlock, Hash> OverseerHandle<PBlock, Hash>
where
	PBlock: BlockT,
{
	/// Create a new [`Handle`].
	fn new(raw: mpsc::Sender<Event<PBlock, Hash>>) -> Self {
		Self(raw)
	}

	/// Inform the `Overseer` that that some block was imported.
	async fn block_imported(&mut self, block: BlockInfo<PBlock>) {
		self.send_and_log_error(Event::BlockImported(block)).await
	}

	/// Send some message to one of the `Subsystem`s.
	async fn send_msg(&mut self, msg: CollationGenerationMessage<Hash>) {
		self.send_and_log_error(Event::MsgToSubsystem(msg)).await
	}

	/// Inform the `Overseer` that a new slot was triggered.
	async fn slot_arrived(&mut self, slot_info: ExecutorSlotInfo) {
		self.send_and_log_error(Event::NewSlot(slot_info)).await
	}

	/// Most basic operation, to stop a server.
	async fn send_and_log_error(&mut self, event: Event<PBlock, Hash>) {
		if self.0.send(event).await.is_err() {
			tracing::info!(target: LOG_TARGET, "Failed to send an event to Overseer");
		}
	}

	/// TODO
	pub async fn initialize(&mut self, config: CollationGenerationConfig<Hash>) {
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
pub struct BlockInfo<Block>
where
	Block: BlockT,
{
	/// hash of the block.
	pub hash: Block::Hash,
	/// hash of the parent block.
	pub parent_hash: Block::Hash,
	/// block's number.
	pub number: NumberFor<Block>,
}

impl<Block> From<BlockImportNotification<Block>> for BlockInfo<Block>
where
	Block: BlockT,
{
	fn from(n: BlockImportNotification<Block>) -> Self {
		BlockInfo { hash: n.hash, parent_hash: *n.header.parent_hash(), number: *n.header.number() }
	}
}

/// An event from outside the overseer scope, such
/// as the substrate framework or user interaction.
enum Event<PBlock, Hash>
where
	PBlock: BlockT,
{
	/// A new block was imported.
	BlockImported(BlockInfo<PBlock>),
	/// A new slot arrived.
	NewSlot(ExecutorSlotInfo),
	/// Message as sent to a subsystem.
	MsgToSubsystem(CollationGenerationMessage<Hash>),
}

/// Glues together the [`Overseer`] and `BlockchainEvents` by forwarding
/// import and finality notifications to it.
pub async fn forward_events<PBlock, Client, Hash>(
	client: Arc<Client>,
	mut imports: impl FusedStream<Item = NumberFor<PBlock>> + Unpin,
	mut slots: impl FusedStream<Item = ExecutorSlotInfo> + Unpin,
	mut handle: OverseerHandle<PBlock, Hash>,
) where
	PBlock: BlockT,
	Client: HeaderBackend<PBlock>,
{
	loop {
		select! {
			i = imports.next() => {
				match i {
					Some(block_number) => {
						let header = client
							.header(BlockId::Number(block_number))
							.expect("Header of imported block must exist; qed")
							.expect("Header of imported block must exist; qed");
						let block = BlockInfo {
							hash: header.hash(),
							parent_hash: *header.parent_hash(),
							number: *header.number(),
						};
						handle.block_imported(block).await;
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
pub struct Overseer<PBlock, PClient, Hash>
where
	PBlock: BlockT,
{
	primary_chain_client: Arc<PClient>,
	config: Option<Arc<CollationGenerationConfig<Hash>>>,
	/// A user specified addendum field.
	leaves: Vec<(PBlock::Hash, NumberFor<PBlock>)>,
	/// A user specified addendum field.
	active_leaves: HashMap<PBlock::Hash, NumberFor<PBlock>>,
	/// Events that are sent to the overseer from the outside world.
	events_rx: mpsc::Receiver<Event<PBlock, Hash>>,
}

impl<PBlock, PClient, Hash> Overseer<PBlock, PClient, Hash>
where
	PBlock: BlockT,
	PClient: HeaderBackend<PBlock>
		+ BlockBackend<PBlock>
		+ ProvideRuntimeApi<PBlock>
		+ Send
		+ 'static
		+ Sync,
	PClient::Api: ExecutorApi<PBlock, Hash>,
	Hash: Encode + Decode,
{
	/// Create a new overseer.
	pub fn new(
		primary_chain_client: Arc<PClient>,
		leaves: Vec<(PBlock::Hash, NumberFor<PBlock>)>,
		active_leaves: HashMap<PBlock::Hash, NumberFor<PBlock>>,
	) -> (Self, OverseerHandle<PBlock, Hash>) {
		let (handle, events_rx) = mpsc::channel(SIGNAL_CHANNEL_CAPACITY);
		let overseer =
			Overseer { primary_chain_client, config: None, leaves, active_leaves, events_rx };
		(overseer, OverseerHandle::new(handle))
	}

	/// Run the `Overseer`.
	pub async fn run(mut self) -> Result<(), ApiError> {
		// Notify about active leaves on startup before starting the loop
		for (hash, number) in std::mem::take(&mut self.leaves) {
			let _ = self.active_leaves.insert(hash, number);
			let updated_leaf = ActivatedLeaf { hash, number };
			if let Err(error) = self.on_activated_leaf(updated_leaf).await {
				tracing::error!(
					target: LOG_TARGET,
					"Collation generation processing error: {error}"
				);
			}
		}

		// TODO: remove this once the config can be initialized in [`Self::new`].
		let mut config_initialized = false;
		// Only a few dozens of backlog blocks.
		let mut imports_backlog = Vec::new();

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
				// TODO: we still need the context of block, e.g., executor gossips no message
				// to the primary node during the major sync.
				Event::BlockImported(block) => {
					if !config_initialized {
						if self.config.is_some() {
							// Process the backlog first once the config has been initialized.
							if !imports_backlog.is_empty() {
								for b in imports_backlog.drain(..) {
									self.block_imported(b).await?;
								}
							}
							config_initialized = true;
							self.block_imported(block).await?;
						} else {
							imports_backlog.push(block);
						}
					} else {
						self.block_imported(block).await?;
					}
				},
				Event::NewSlot(slot_info) =>
					if let Err(error) = self.on_new_slot(slot_info).await {
						tracing::error!(
							target: LOG_TARGET,
							"Collation generation processing error: {error}"
						);
					},
			}
		}

		Ok(())
	}

	async fn on_activated_leaf(
		&self,
		activated_leaf: ActivatedLeaf<PBlock>,
	) -> Result<(), ApiError> {
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

	async fn on_new_slot(&self, slot_info: ExecutorSlotInfo) -> Result<(), ApiError> {
		if let Some(config) = &self.config {
			let client = &self.primary_chain_client;
			let best_hash = client.info().best_hash;

			let non_generic_best_hash = PHash::decode(&mut best_hash.encode().as_slice())
				.expect("Hash type must be correct");

			let opaque_bundle = match (config.bundler)(non_generic_best_hash, slot_info).await {
				Some(opaque_bundle) => opaque_bundle,
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
		message: CollationGenerationMessage<Hash>,
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

	async fn block_imported(&mut self, block: BlockInfo<PBlock>) -> Result<(), ApiError> {
		match self.active_leaves.entry(block.hash) {
			Entry::Vacant(entry) => entry.insert(block.number),
			Entry::Occupied(entry) => {
				debug_assert_eq!(*entry.get(), block.number);
				return Ok(())
			},
		};

		let updated_leaf = ActivatedLeaf { hash: block.hash, number: block.number };

		if let Some(number) = self.active_leaves.remove(&block.parent_hash) {
			debug_assert_eq!(block.number.saturating_sub(One::one()), number);
		}

		if let Err(error) = self.on_activated_leaf(updated_leaf).await {
			tracing::error!(target: LOG_TARGET, "Collation generation processing error: {error}");
		}

		Ok(())
	}
}
