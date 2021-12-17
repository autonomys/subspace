// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Cirrus Executor implementation for Subspace.
#![allow(clippy::all)]

use sc_client_api::BlockBackend;
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockStatus;
use sp_core::traits::SpawnNamed;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, Zero},
	SaturatedConversion,
};
use sp_trie::StorageProof;

use cumulus_client_consensus_common::ParachainConsensus;

use polkadot_node_subsystem::messages::CollationGenerationMessage;
use polkadot_overseer::Handle as OverseerHandle;

use cirrus_node_primitives::{
	BundleResult, Collation, CollationGenerationConfig, CollationResult, CollatorPair,
	ExecutorSlotInfo, HeadData, PersistedValidationData, ProcessorResult,
};
use sp_executor::{Bundle, BundleHeader, ExecutionReceipt, FraudProof, OpaqueBundle};
use subspace_runtime_primitives::Hash as PHash;

use codec::{Decode, Encode};
use futures::{select, FutureExt};
use std::{sync::Arc, time};
use tracing::Instrument;

/// The logging target.
const LOG_TARGET: &str = "cirrus::executor";

/// The implementation of the Cirrus `Executor`.
pub struct Executor<Block: BlockT, BS, RA, Client, TransactionPool> {
	block_status: Arc<BS>,
	parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	runtime_api: Arc<RA>,
	client: Arc<Client>,
	overseer_handle: OverseerHandle,
	transaction_pool: Arc<TransactionPool>,
}

impl<Block: BlockT, BS, RA, Client, TransactionPool> Clone
	for Executor<Block, BS, RA, Client, TransactionPool>
{
	fn clone(&self) -> Self {
		Self {
			block_status: self.block_status.clone(),
			parachain_consensus: self.parachain_consensus.clone(),
			runtime_api: self.runtime_api.clone(),
			client: self.client.clone(),
			overseer_handle: self.overseer_handle.clone(),
			transaction_pool: self.transaction_pool.clone(),
		}
	}
}

impl<Block, BS, RA, Client, TransactionPool> Executor<Block, BS, RA, Client, TransactionPool>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	BS: BlockBackend<Block>,
	RA: ProvideRuntimeApi<Block>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
	/// Create a new instance.
	fn new(
		block_status: Arc<BS>,
		runtime_api: Arc<RA>,
		parachain_consensus: Box<dyn ParachainConsensus<Block>>,
		client: Arc<Client>,
		overseer_handle: OverseerHandle,
		transaction_pool: Arc<TransactionPool>,
	) -> Self {
		Self {
			block_status,
			runtime_api,
			parachain_consensus,
			client,
			overseer_handle,
			transaction_pool,
		}
	}

	/// Checks the status of the given block hash in the Parachain.
	///
	/// Returns `true` if the block could be found and is good to be build on.
	fn check_block_status(
		&self,
		hash: Block::Hash,
		number: <Block::Header as HeaderT>::Number,
	) -> bool {
		match self.block_status.block_status(&BlockId::Hash(hash)) {
			Ok(BlockStatus::Queued) => {
				tracing::debug!(
					target: LOG_TARGET,
					block_hash = ?hash,
					"Skipping candidate production, because block is still queued for import.",
				);
				false
			},
			Ok(BlockStatus::InChainWithState) => true,
			Ok(BlockStatus::InChainPruned) => {
				tracing::error!(
					target: LOG_TARGET,
					"Skipping candidate production, because block `{:?}` is already pruned!",
					hash,
				);
				false
			},
			Ok(BlockStatus::KnownBad) => {
				tracing::error!(
					target: LOG_TARGET,
					block_hash = ?hash,
					"Block is tagged as known bad and is included in the relay chain! Skipping candidate production!",
				);
				false
			},
			Ok(BlockStatus::Unknown) => {
				if number.is_zero() {
					tracing::error!(
						target: LOG_TARGET,
						block_hash = ?hash,
						"Could not find the header of the genesis block in the database!",
					);
				} else {
					tracing::debug!(
						target: LOG_TARGET,
						block_hash = ?hash,
						"Skipping candidate production, because block is unknown.",
					);
				}
				false
			},
			Err(e) => {
				tracing::error!(
					target: LOG_TARGET,
					block_hash = ?hash,
					error = ?e,
					"Failed to get block status.",
				);
				false
			},
		}
	}

	/// Checks the execution receipt from the executor peers.
	///
	/// TODO: invoke this once the external ER is received.
	#[allow(unused)]
	async fn on_execution_receipt_received(
		&mut self,
		_execution_receipt: ExecutionReceipt<<Block as BlockT>::Hash>,
	) {
		// TODO: validate the Proof-of-Election

		// TODO: check if the received ER is same with the one produced locally.
		let same_with_produced_locally = true;

		if same_with_produced_locally {
			// TODO: rebroadcast ER
		} else {
			// TODO: generate a fraud proof
			let fraud_proof = FraudProof { proof: StorageProof::empty() };

			// TODO: gossip the fraud proof to farmers
			self.overseer_handle
				.send_msg(CollationGenerationMessage::FraudProof(fraud_proof), "SubmitFraudProof")
				.await;
		}
	}

	async fn produce_candidate(
		mut self,
		relay_parent: PHash,
		validation_data: PersistedValidationData,
	) -> Option<CollationResult> {
		tracing::trace!(
			target: LOG_TARGET,
			relay_parent = ?relay_parent,
			validation_data = ?validation_data,
			"Producing candidate",
		);

		// Try retrieving the latest pending head from primary chain,otherwise fall
		// back to the local best hash which should definitely be the genesis hash.
		let maybe_pending_head = match <Option<<Block::Header as HeaderT>::Hash>>::decode(
			&mut &validation_data.parent_head[..],
		) {
			Ok(h) => h,
			Err(e) => {
				tracing::error!(
					target: LOG_TARGET,
					error = ?e,
					"Could not decode the pending head hash."
				);
				return None
			},
		};

		let best_number = self.client.info().best_number;

		let last_head_hash = if let Some(pending_head) = maybe_pending_head {
			pending_head
		} else {
			assert_eq!(best_number.saturated_into::<u32>(), 0u32);
			self.client.info().best_hash
		};

		if !self.check_block_status(last_head_hash, best_number) {
			return None
		}

		tracing::info!(
			target: LOG_TARGET,
			relay_parent = ?relay_parent,
			client_info = ?self.client.info(),
			"Starting collation.",
		);

		let last_head = self
			.client
			.header(BlockId::Hash(last_head_hash))
			.ok()?
			.expect("Failed to fetch the best header");

		// FIXME: handle PersistedValidationData
		let validation_data = Default::default();
		let candidate = self
			.parachain_consensus
			.produce_candidate(&last_head, relay_parent, &validation_data)
			.await?;

		let (header, _extrinsics) = candidate.block.deconstruct();

		let head_data = HeadData(header.encode());
		let number = best_number.saturated_into::<u32>() + 1u32;

		Some(CollationResult { collation: Collation { head_data, number }, result_sender: None })
	}

	// TODO:
	// - gossip the bundle to the executor peers
	//     - OnBundleReceivedBySecondaryNode
	//         - OnBundleEquivocationProof(farmer only)
	//         - OnInvalidBundleProof(farmer only)
	async fn produce_bundle(self, slot_info: ExecutorSlotInfo) -> Option<BundleResult> {
		println!("TODO: solve some puzzle based on `slot_info` to be allowed to produce a bundle");

		// TODO: ready at the best number of primary block?
		let parent_number = self.client.info().best_number;
		let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
		// TODO: proper timeout
		let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

		let mut pending_iterator = select! {
			res = t1 => res,
			_ = t2 => {
				tracing::warn!(
					"Timeout fired waiting for transaction pool at {}, proceeding with production.",
					parent_number,
				);
				self.transaction_pool.ready()
			}
		};

		// TODO: proper deadline
		let pushing_duration = time::Duration::from_micros(500);

		let start = time::Instant::now();

		// TODO: Select transactions properly from the transaction pool
		//
		// Selection policy:
		// - minimize the transaction equivocation.
		// - maximize the executor computation power.
		let mut extrinsics = Vec::new();
		while let Some(pending_tx) = pending_iterator.next() {
			if start.elapsed() >= pushing_duration {
				break
			}
			let pending_tx_data = pending_tx.data().clone();
			extrinsics.push(pending_tx_data);
		}

		let extrinsics_root =
			BlakeTwo256::ordered_trie_root(extrinsics.iter().map(|xt| xt.encode()).collect());

		let best_hash = self.client.info().best_hash;
		let _state_root = self.client.expect_header(BlockId::Hash(best_hash)).ok()?.state_root();

		let bundle = Bundle {
			header: BundleHeader { slot_number: slot_info.slot.into(), extrinsics_root },
			extrinsics,
		};

		Some(BundleResult { opaque_bundle: bundle.into() })
	}

	async fn process_bundles(
		self,
		primary_hash: PHash,
		_bundles: Vec<OpaqueBundle>,
	) -> Option<ProcessorResult> {
		// TODO:
		// 1. convert the bundles to a full tx list
		// 2. duplicate the full tx list
		// 3. shuffle the full tx list by sender account

		// TODO: now we have the final transaction list:
		// - apply each tx one by one.
		// - compute the incremental state root and add to the execution trace
		// - produce ExecutionReceipt

		// The applied txs can be full removed from the transaction pool

		// TODO: win the executor election to broadcast ER.
		let is_elected = true;

		if is_elected {
			// TODO: broadcast ER to all executors.

			// Return `Some(_)` to broadcast ER to all farmers via unsigned extrinsic.
			Some(ProcessorResult {
				execution_receipt: ExecutionReceipt {
					primary_hash,
					secondary_hash: Default::default(),
					state_root: Default::default(),
					state_transition_root: Default::default(),
				},
			})
		} else {
			None
		}
	}
}

/// Parameters for [`start_executor`].
pub struct StartExecutorParams<Block: BlockT, RA, BS, Spawner, Client, TransactionPool> {
	pub client: Arc<Client>,
	pub runtime_api: Arc<RA>,
	pub block_status: Arc<BS>,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
	pub overseer_handle: OverseerHandle,
	pub spawner: Spawner,
	pub key: CollatorPair,
	pub parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	pub transaction_pool: Arc<TransactionPool>,
}

/// Start the executor.
pub async fn start_executor<Block, RA, BS, Spawner, Client, TransactionPool>(
	StartExecutorParams {
		client,
		block_status,
		announce_block: _,
		mut overseer_handle,
		spawner: _,
		key,
		parachain_consensus,
		runtime_api,
		transaction_pool,
	}: StartExecutorParams<Block, RA, BS, Spawner, Client, TransactionPool>,
) where
	Block: BlockT,
	BS: BlockBackend<Block> + Send + Sync + 'static,
	Spawner: SpawnNamed + Clone + Send + Sync + 'static,
	Client: HeaderBackend<Block> + Send + Sync + 'static,
	RA: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	TransactionPool:
		sc_transaction_pool_api::TransactionPool<Block = Block> + Send + Sync + 'static,
{
	let executor = Executor::new(
		block_status,
		runtime_api,
		parachain_consensus,
		client,
		overseer_handle.clone(),
		transaction_pool,
	);

	let span = tracing::Span::current();
	let collator_clone = executor.clone();
	let bundler_clone = executor.clone();
	let collator_span_clone = span.clone();
	let bundler_span_clone = span.clone();
	let config = CollationGenerationConfig {
		key,
		collator: Box::new(move |relay_parent, validation_data| {
			let collator = collator_clone.clone();

			collator
				.produce_candidate(relay_parent, validation_data.clone())
				.instrument(collator_span_clone.clone())
				.boxed()
		}),
		bundler: Box::new(move |slot_info| {
			let bundler = bundler_clone.clone();

			bundler.produce_bundle(slot_info).instrument(bundler_span_clone.clone()).boxed()
		}),
		processor: Box::new(move |primary_hash, bundles| {
			let processor = executor.clone();

			processor
				.process_bundles(primary_hash, bundles)
				.instrument(span.clone())
				.boxed()
		}),
	};

	overseer_handle
		.send_msg(CollationGenerationMessage::Initialize(config), "StartCollator")
		.await;
}
