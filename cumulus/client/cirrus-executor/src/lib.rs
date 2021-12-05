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

//! Cirrus Executor implementation for Substrate.

use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockStatus;
use sp_core::traits::SpawnNamed;
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, HashFor, Header as HeaderT, Zero},
	SaturatedConversion,
};

use cumulus_client_consensus_common::ParachainConsensus;

// FIXME
use polkadot_overseer::Handle as OverseerHandle;

use subspace_node_primitives::{Collation, CollationResult};
use subspace_runtime_primitives::{CollatorPair, Hash as PHash, HeadData, PersistedValidationData};

use codec::{Decode, Encode};
use futures::{channel::oneshot, FutureExt};
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::Instrument;

/// The logging target.
const LOG_TARGET: &str = "cirrus::executor";

/// The implementation of the Cirrus `Executor`.
pub struct Executor<Block: BlockT, BS, RA, Client> {
	block_status: Arc<BS>,
	parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	runtime_api: Arc<RA>,
	client: Arc<Client>,
}

impl<Block: BlockT, BS, RA, Client> Clone for Executor<Block, BS, RA, Client> {
	fn clone(&self) -> Self {
		Self {
			block_status: self.block_status.clone(),
			parachain_consensus: self.parachain_consensus.clone(),
			runtime_api: self.runtime_api.clone(),
			client: self.client.clone(),
		}
	}
}

impl<Block, BS, RA, Client> Executor<Block, BS, RA, Client>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	BS: BlockBackend<Block>,
	RA: ProvideRuntimeApi<Block>,
{
	/// Create a new instance.
	fn new(
		block_status: Arc<BS>,
		spawner: Arc<dyn SpawnNamed + Send + Sync>,
		announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
		runtime_api: Arc<RA>,
		parachain_consensus: Box<dyn ParachainConsensus<Block>>,
		client: Arc<Client>,
	) -> Self {
		Self { block_status, runtime_api, parachain_consensus, client }
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

	async fn produce_candidate(
		mut self,
		relay_parent: PHash,
		validation_data: PersistedValidationData,
	) -> Option<CollationResult> {
		tracing::trace!(
			target: LOG_TARGET,
			relay_parent = ?relay_parent,
			"Producing candidate",
		);

		// FIXME: We only sync the primary chain and does not attempt to produce candidate at the
		// very first step.
		tracing::trace!(
			target: LOG_TARGET,
			relay_parent = ?relay_parent,
			validation_data = ?validation_data,
			"Should be producing candidate...",
		);

		let best_number = self.client.info().best_number;

		// The last block we're building on is from the primary chain if the best local block is not
		// genesis block.
		let maybe_pending_head = match <Option<<Block::Header as HeaderT>::Hash>>::decode(&mut &validation_data.parent_head[..]) {
			Ok(x) => x,
			Err(e) => {
				tracing::error!(
					target: LOG_TARGET,
					error = ?e,
					"Could not decode the pending head hash."
				);
				return None
			},
		};

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

		tracing::info!(
			target: LOG_TARGET,
			last_head = ?last_head,
			?last_head_hash,
			"=========== Producing candidate.",
		);

		// FIXME: replace cumulus_primitives_core::PersistedValidationData
		let validation_data = Default::default();
		let candidate = self
			.parachain_consensus
			.produce_candidate(&last_head, relay_parent, &validation_data)
			.await?;

		let (header, extrinsics) = candidate.block.deconstruct();

		let head_data = HeadData(header.encode());

		Some(CollationResult {
			collation: Collation {
				head_data,
				number: self.client.info().best_number.saturated_into::<u32>() + 1u32,
			},
			result_sender: None,
		})
	}
}

/// Parameters for [`start_executor`].
pub struct StartExecutorParams<Block: BlockT, RA, BS, Spawner, Client> {
	pub client: Arc<Client>,
	pub runtime_api: Arc<RA>,
	pub block_status: Arc<BS>,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
	pub overseer_handle: OverseerHandle,
	pub spawner: Spawner,
	pub key: CollatorPair,
	pub parachain_consensus: Box<dyn ParachainConsensus<Block>>,
}

/// Start the executor.
pub async fn start_executor<Block, RA, BS, Spawner, Client>(
	StartExecutorParams {
		client,
		block_status,
		announce_block,
		mut overseer_handle,
		spawner,
		key,
		parachain_consensus,
		runtime_api,
	}: StartExecutorParams<Block, RA, BS, Spawner, Client>,
) where
	Block: BlockT,
	BS: BlockBackend<Block> + Send + Sync + 'static,
	Spawner: SpawnNamed + Clone + Send + Sync + 'static,
	Client: HeaderBackend<Block> + Send + Sync + 'static,
	RA: ProvideRuntimeApi<Block> + Send + Sync + 'static,
{
	use polkadot_node_subsystem::messages::{CollationGenerationMessage, CollatorProtocolMessage};
	use subspace_node_primitives::CollationGenerationConfig;

	let executor = Executor::new(
		block_status,
		Arc::new(spawner),
		announce_block,
		runtime_api,
		parachain_consensus,
		client,
	);

	let span = tracing::Span::current();
	let config = CollationGenerationConfig {
		key,
		collator: Box::new(move |relay_parent, validation_data| {
			let collator = executor.clone();

			collator
				.produce_candidate(relay_parent, validation_data.clone())
				.instrument(span.clone())
				.boxed()
		}),
	};

	overseer_handle
		.send_msg(CollationGenerationMessage::Initialize(config), "StartCollator")
		.await;
}

#[cfg(test)]
mod tests {
	use super::*;
	use cumulus_client_consensus_common::ParachainCandidate;
	use cumulus_test_client::{
		Client, ClientBlockImportExt, DefaultTestClientBuilderExt, InitBlockBuilder,
		TestClientBuilder, TestClientBuilderExt,
	};
	use cumulus_test_runtime::{Block, Header};
	use futures::{channel::mpsc, executor::block_on, StreamExt};
	use polkadot_node_subsystem_test_helpers::ForwardSubsystem;
	use polkadot_overseer::{dummy::dummy_overseer_builder, HeadSupportsParachains};
	use sp_consensus::BlockOrigin;
	use sp_core::{testing::TaskExecutor, Pair};
	use sp_runtime::traits::BlakeTwo256;
	use sp_state_machine::Backend;

	struct AlwaysSupportsParachains;
	impl HeadSupportsParachains for AlwaysSupportsParachains {
		fn head_supports_parachains(&self, _head: &PHash) -> bool {
			true
		}
	}

	#[derive(Clone)]
	struct DummyParachainConsensus {
		client: Arc<Client>,
	}

	#[async_trait::async_trait]
	impl ParachainConsensus<Block> for DummyParachainConsensus {
		async fn produce_candidate(
			&mut self,
			parent: &Header,
			_: PHash,
			validation_data: &PersistedValidationData,
		) -> Option<ParachainCandidate<Block>> {
			let block_id = BlockId::Hash(parent.hash());
			let builder = self.client.init_block_builder_at(
				&block_id,
				Some(validation_data.clone()),
				Default::default(),
			);

			let (block, _, proof) = builder.build().expect("Creates block").into_inner();

			self.client
				.import(BlockOrigin::Own, block.clone())
				.await
				.expect("Imports the block");

			Some(ParachainCandidate { block, proof: proof.expect("Proof is returned") })
		}
	}

	#[test]
	fn collates_produces_a_block_and_storage_proof_does_not_contains_code() {
		sp_tracing::try_init_simple();

		let spawner = TaskExecutor::new();
		let para_id = ParaId::from(100);
		let announce_block = |_, _| ();
		let client = Arc::new(TestClientBuilder::new().build());
		let header = client.header(&BlockId::Number(0)).unwrap().unwrap();

		let (sub_tx, sub_rx) = mpsc::channel(64);

		let (overseer, handle) =
			dummy_overseer_builder(spawner.clone(), AlwaysSupportsParachains, None)
				.expect("Creates overseer builder")
				.replace_collation_generation(|_| ForwardSubsystem(sub_tx))
				.build()
				.expect("Builds overseer");

		spawner.spawn("overseer", overseer.run().then(|_| async { () }).boxed());

		let collator_start = start_collator(StartExecutorParams {
			runtime_api: client.clone(),
			block_status: client.clone(),
			announce_block: Arc::new(announce_block),
			overseer_handle: OverseerHandle::new(handle),
			spawner,
			key: CollatorPair::generate().0,
			parachain_consensus: Box::new(DummyParachainConsensus { client: client.clone() }),
		});
		block_on(collator_start);

		let msg = block_on(sub_rx.into_future())
			.0
			.expect("message should be send by `start_collator` above.");

		let config = match msg {
			CollationGenerationMessage::Initialize(config) => config,
		};

		let mut validation_data = PersistedValidationData::default();
		validation_data.parent_head = header.encode().into();
		let relay_parent = Default::default();

		let collation = block_on((config.collator)(relay_parent, &validation_data))
			.expect("Collation is build")
			.collation;

		let block_data = collation.proof_of_validity.block_data;

		let block =
			ParachainBlockData::<Block>::decode(&mut &block_data.0[..]).expect("Is a valid block");

		assert_eq!(1, *block.header().number());

		// Ensure that we did not include `:code` in the proof.
		let db = block
			.storage_proof()
			.to_storage_proof::<BlakeTwo256>(Some(header.state_root()))
			.unwrap()
			.0
			.into_memory_db();

		let backend =
			sp_state_machine::new_in_mem::<BlakeTwo256>().update_backend(*header.state_root(), db);

		// Should return an error, as it was not included while building the proof.
		assert!(backend
			.storage(sp_core::storage::well_known_keys::CODE)
			.unwrap_err()
			.contains("Trie lookup error: Database missing expected key"));
	}
}
