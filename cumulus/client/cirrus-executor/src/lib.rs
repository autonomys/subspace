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

mod processor;

use sc_client_api::BlockBackend;
use sc_transaction_pool_api::InPoolTransaction;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockStatus;
use sp_core::traits::SpawnNamed;
use sp_inherents::{CreateInherentDataProviders, InherentData, InherentDataProvider};
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, Zero},
	SaturatedConversion,
};
use sp_trie::StorageProof;

use cumulus_client_consensus_common::ParachainConsensus;

use polkadot_node_subsystem::messages::CollationGenerationMessage;
use polkadot_overseer::Handle as OverseerHandle;

use cirrus_block_builder::{BlockBuilder, RecordProof};
use cirrus_client_executor_gossip::{Action, GossipMessageHandler};
use cirrus_node_primitives::{
	BundleResult, Collation, CollationGenerationConfig, CollationResult, CollatorPair,
	ExecutorSlotInfo, HeadData, PersistedValidationData, ProcessorResult,
};
use cirrus_primitives::{AccountId, Hash, SecondaryApi};
use sp_executor::{
	Bundle, BundleEquivocationProof, BundleHeader, ExecutionReceipt, FraudProof,
	InvalidTransactionProof, OpaqueBundle,
};
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::Hash as PHash;

use codec::{Decode, Encode};
use futures::{select, FutureExt};
use std::{sync::Arc, time};
use tracing::Instrument;

/// The logging target.
const LOG_TARGET: &str = "cirrus::executor";

/// The implementation of the Cirrus `Executor`.
pub struct Executor<Block: BlockT, BS, RA, Client, TransactionPool, Backend, CIDP> {
	block_status: Arc<BS>,
	parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	runtime_api: Arc<RA>,
	client: Arc<Client>,
	spawner: Arc<dyn SpawnNamed + Send + Sync>,
	overseer_handle: OverseerHandle,
	transaction_pool: Arc<TransactionPool>,
	bundle_sender: Arc<TracingUnboundedSender<Bundle<Block::Extrinsic>>>,
	execution_receipt_sender: Arc<TracingUnboundedSender<ExecutionReceipt<Block::Hash>>>,
	backend: Arc<Backend>,
	create_inherent_data_providers: Arc<CIDP>,
}

impl<Block: BlockT, BS, RA, Client, TransactionPool, Backend, CIDP> Clone
	for Executor<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
{
	fn clone(&self) -> Self {
		Self {
			block_status: self.block_status.clone(),
			parachain_consensus: self.parachain_consensus.clone(),
			runtime_api: self.runtime_api.clone(),
			client: self.client.clone(),
			spawner: self.spawner.clone(),
			overseer_handle: self.overseer_handle.clone(),
			transaction_pool: self.transaction_pool.clone(),
			bundle_sender: self.bundle_sender.clone(),
			execution_receipt_sender: self.execution_receipt_sender.clone(),
			backend: self.backend.clone(),
			create_inherent_data_providers: self.create_inherent_data_providers.clone(),
		}
	}
}

impl<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
	Executor<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	BS: BlockBackend<Block>,
	Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
	RA: ProvideRuntimeApi<Block>,
	RA::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
	CIDP: CreateInherentDataProviders<Block, Hash>,
{
	/// Create a new instance.
	fn new(
		block_status: Arc<BS>,
		runtime_api: Arc<RA>,
		parachain_consensus: Box<dyn ParachainConsensus<Block>>,
		client: Arc<Client>,
		spawner: Arc<dyn SpawnNamed + Send + Sync>,
		overseer_handle: OverseerHandle,
		transaction_pool: Arc<TransactionPool>,
		bundle_sender: Arc<TracingUnboundedSender<Bundle<Block::Extrinsic>>>,
		execution_receipt_sender: Arc<TracingUnboundedSender<ExecutionReceipt<Block::Hash>>>,
		backend: Arc<Backend>,
		create_inherent_data_providers: Arc<CIDP>,
	) -> Self {
		Self {
			block_status,
			runtime_api,
			parachain_consensus,
			client,
			spawner,
			overseer_handle,
			transaction_pool,
			bundle_sender,
			execution_receipt_sender,
			backend,
			create_inherent_data_providers,
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

	fn submit_bundle_equivocation_proof(&self, bundle_equivocation_proof: BundleEquivocationProof) {
		let mut overseer_handle = self.overseer_handle.clone();
		self.spawner.spawn(
			"cirrus-submit-bundle-equivocation-proof",
			None,
			async move {
				tracing::debug!(
					target: LOG_TARGET,
					"Submitting bundle equivocation proof in a background task..."
				);
				overseer_handle
					.send_msg(
						CollationGenerationMessage::BundleEquivocationProof(
							bundle_equivocation_proof,
						),
						"SubmitBundleEquivocationProof",
					)
					.await;
				tracing::debug!(
					target: LOG_TARGET,
					"Bundle equivocation proof submission finished"
				);
			}
			.boxed(),
		);
	}

	fn submit_fraud_proof(&self, fraud_proof: FraudProof) {
		let mut overseer_handle = self.overseer_handle.clone();
		self.spawner.spawn(
			"cirrus-submit-fraud-proof",
			None,
			async move {
				tracing::debug!(
					target: LOG_TARGET,
					"Submitting fraud proof in a background task..."
				);
				overseer_handle
					.send_msg(
						CollationGenerationMessage::FraudProof(fraud_proof),
						"SubmitFraudProof",
					)
					.await;
				tracing::debug!(target: LOG_TARGET, "Fraud proof submission finished");
			}
			.boxed(),
		);
	}

	fn submit_invalid_transaction_proof(&self, invalid_transaction_proof: InvalidTransactionProof) {
		let mut overseer_handle = self.overseer_handle.clone();
		self.spawner.spawn(
			"cirrus-submit-invalid-transaction-proof",
			None,
			async move {
				tracing::debug!(
					target: LOG_TARGET,
					"Submitting invalid transaction proof in a background task..."
				);
				overseer_handle
					.send_msg(
						CollationGenerationMessage::InvalidTransactionProof(
							invalid_transaction_proof,
						),
						"SubmitInvalidTransactionProof",
					)
					.await;
				tracing::debug!(
					target: LOG_TARGET,
					"Invalid transaction proof submission finished"
				);
			}
			.boxed(),
		);
	}

	/// Get the inherent data.
	async fn inherent_data(
		&self,
		parent: Block::Hash,
		relay_parent: PHash,
	) -> Option<InherentData> {
		let inherent_data_providers = self
			.create_inherent_data_providers
			.create_inherent_data_providers(parent, relay_parent)
			.await
			.map_err(|e| {
				tracing::error!(
					target: LOG_TARGET,
					error = ?e,
					"Failed to create inherent data providers.",
				)
			})
			.ok()?;

		inherent_data_providers
			.create_inherent_data()
			.map_err(|e| {
				tracing::error!(
					target: LOG_TARGET,
					error = ?e,
					"Failed to create inherent data.",
				)
			})
			.ok()
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

	async fn produce_bundle(
		self,
		_primary_hash: PHash,
		slot_info: ExecutorSlotInfo,
	) -> Option<BundleResult> {
		println!("TODO: solve some puzzle based on `slot_info` to be allowed to produce a bundle");

		let parent_hash = self.client.info().best_hash;
		let parent_number =
			self.client.expect_block_number_from_id(&BlockId::Hash(parent_hash)).ok()?;

		let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
		// TODO: proper timeout
		let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

		let mut pending_iterator = select! {
			res = t1 => res,
			_ = t2 => {
				tracing::warn!(
					target: LOG_TARGET,
					"Timeout fired waiting for transaction pool at #{}, proceeding with production.",
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
		let mut extrinsics = {
			let inherent_data = self.inherent_data(parent_hash, primary_hash).await?;

			let mut block_builder = BlockBuilder::new(
				&*self.runtime_api,
				parent_hash,
				parent_number,
				RecordProof::No,
				Default::default(),
				&*self.backend,
			)
			.ok()?;

			// TODO: is creating inherents fallible?
			block_builder.create_inherents(inherent_data).ok().unwrap_or_default()
		};

		while let Some(pending_tx) = pending_iterator.next() {
			if start.elapsed() >= pushing_duration {
				break
			}
			let pending_tx_data = pending_tx.data().clone();
			extrinsics.push(pending_tx_data);
		}

		let extrinsics_root = BlakeTwo256::ordered_trie_root(
			extrinsics.iter().map(|xt| xt.encode()).collect(),
			sp_core::storage::StateVersion::V1,
		);

		let _state_root =
			self.client.expect_header(BlockId::Number(parent_number)).ok()?.state_root();

		let bundle = Bundle {
			header: BundleHeader { slot_number: slot_info.slot.into(), extrinsics_root },
			extrinsics,
		};

		if let Err(e) = self.bundle_sender.unbounded_send(bundle.clone()) {
			tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
		}

		Some(BundleResult { opaque_bundle: bundle.into() })
	}

	async fn process_bundles(
		self,
		primary_hash: PHash,
		bundles: Vec<OpaqueBundle>,
		shuffling_seed: Randomness,
	) -> Option<ProcessorResult> {
		self.process_bundles_impl(primary_hash, bundles, shuffling_seed)
			.await
			.ok()
			.flatten()
	}
}

// TODO: proper error type
#[derive(Debug)]
pub enum GossipMessageError {
	BundleEquivocation,
}

impl<Block, BS, RA, Client, TransactionPool, Backend, CIDP> GossipMessageHandler<Block>
	for Executor<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	BS: BlockBackend<Block> + Send + Sync,
	Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
	RA: ProvideRuntimeApi<Block> + Send + Sync,
	RA::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
	CIDP: CreateInherentDataProviders<Block, Hash>,
{
	type Error = GossipMessageError;

	fn on_bundle(&self, bundle: &Bundle<Block::Extrinsic>) -> Result<Action, Self::Error> {
		let check_equivocation = |_bundle: &Bundle<Block::Extrinsic>| {
			// TODO: check bundle equivocation
			let bundle_is_an_equivocation = false;
			if bundle_is_an_equivocation {
				Some(BundleEquivocationProof::dummy_at(bundle.header.slot_number))
			} else {
				None
			}
		};

		// A bundle equivocation occurs.
		if let Some(equivocation_proof) = check_equivocation(bundle) {
			self.submit_bundle_equivocation_proof(equivocation_proof);
			return Err(GossipMessageError::BundleEquivocation)
		}

		let bundle_exists = false;

		if bundle_exists {
			Ok(Action::Empty)
		} else {
			// TODO: validate the PoE

			for extrinsic in bundle.extrinsics.iter() {
				let tx_hash = self.transaction_pool.hash_of(extrinsic);

				if self.transaction_pool.ready_transaction(&tx_hash).is_some() {
					// TODO: Set the status of each tx in the bundle to seen
				} else {
					// TODO: check the legality
					//
					// if illegal => illegal tx proof
					let invalid_transaction_proof = InvalidTransactionProof;

					self.submit_invalid_transaction_proof(invalid_transaction_proof);
				}
			}

			// TODO: all checks pass, add to the bundle pool

			Ok(Action::RebroadcastBundle)
		}
	}

	/// Checks the execution receipt from the executor peers.
	fn on_execution_receipt(
		&self,
		_execution_receipt: &ExecutionReceipt<<Block as BlockT>::Hash>,
	) -> Result<Action, Self::Error> {
		// TODO: validate the Proof-of-Election

		// TODO: check if the received ER is same with the one produced locally.
		let same_with_produced_locally = true;

		if same_with_produced_locally {
			Ok(Action::RebroadcastExecutionReceipt)
		} else {
			// TODO: generate a fraud proof
			let fraud_proof = FraudProof { proof: StorageProof::empty() };

			self.submit_fraud_proof(fraud_proof);

			Ok(Action::Empty)
		}
	}
}

/// Parameters for [`start_executor`].
pub struct StartExecutorParams<
	Block: BlockT,
	RA,
	BS,
	Spawner,
	Client,
	TransactionPool,
	Backend,
	CIDP,
> {
	pub client: Arc<Client>,
	pub runtime_api: Arc<RA>,
	pub block_status: Arc<BS>,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
	pub overseer_handle: OverseerHandle,
	pub spawner: Spawner,
	pub key: CollatorPair,
	pub parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	pub transaction_pool: Arc<TransactionPool>,
	pub bundle_sender: TracingUnboundedSender<Bundle<Block::Extrinsic>>,
	pub execution_receipt_sender: TracingUnboundedSender<ExecutionReceipt<Block::Hash>>,
	pub backend: Arc<Backend>,
	pub create_inherent_data_providers: Arc<CIDP>,
}

/// Start the executor.
pub async fn start_executor<Block, RA, BS, Spawner, Client, TransactionPool, Backend, CIDP>(
	StartExecutorParams {
		client,
		block_status,
		announce_block: _,
		mut overseer_handle,
		spawner,
		key,
		parachain_consensus,
		runtime_api,
		transaction_pool,
		bundle_sender,
		execution_receipt_sender,
		backend,
		create_inherent_data_providers,
	}: StartExecutorParams<Block, RA, BS, Spawner, Client, TransactionPool, Backend, CIDP>,
) -> Executor<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
where
	Block: BlockT,
	BS: BlockBackend<Block> + Send + Sync + 'static,
	Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
	Spawner: SpawnNamed + Clone + Send + Sync + 'static,
	Client: HeaderBackend<Block> + Send + Sync + 'static,
	RA: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	RA::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	TransactionPool:
		sc_transaction_pool_api::TransactionPool<Block = Block> + Send + Sync + 'static,
	CIDP: CreateInherentDataProviders<Block, Hash> + 'static,
{
	let executor = Executor::new(
		block_status,
		runtime_api,
		parachain_consensus,
		client,
		Arc::new(spawner),
		overseer_handle.clone(),
		transaction_pool,
		Arc::new(bundle_sender),
		Arc::new(execution_receipt_sender),
		backend,
		create_inherent_data_providers,
	);

	let span = tracing::Span::current();
	let config = CollationGenerationConfig {
		key,
		collator: {
			let executor = executor.clone();
			let span = span.clone();

			Box::new(move |relay_parent, validation_data| {
				let executor = executor.clone();
				executor
					.produce_candidate(relay_parent, validation_data.clone())
					.instrument(span.clone())
					.boxed()
			})
		},
		bundler: {
			let executor = executor.clone();
			let span = span.clone();

			Box::new(move |primary_hash, slot_info| {
				let executor = executor.clone();
				executor
					.produce_bundle(primary_hash, slot_info)
					.instrument(span.clone())
					.boxed()
			})
		},
		processor: {
			let executor = executor.clone();

			Box::new(move |primary_hash, bundles, shuffling_seed| {
				let executor = executor.clone();
				executor
					.process_bundles(primary_hash, bundles, shuffling_seed)
					.instrument(span.clone())
					.boxed()
			})
		},
	};

	overseer_handle
		.send_msg(CollationGenerationMessage::Initialize(config), "StartCollator")
		.await;

	executor
}
