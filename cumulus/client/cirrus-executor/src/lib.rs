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
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockStatus;
use sp_core::traits::SpawnNamed;
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Header as HeaderT, Zero},
	SaturatedConversion,
};

use cumulus_client_consensus_common::ParachainConsensus;

use polkadot_overseer::Handle as OverseerHandle;
use polkadot_node_subsystem::messages::CollationGenerationMessage;

use cirrus_node_primitives::{
	Collation, CollationResult, CollatorPair, HeadData, PersistedValidationData,
	BundleResult, CollationGenerationConfig
};
use sp_executor::Bundle;
use sc_consensus_subspace::NewSlotInfo;
use subspace_runtime_primitives::Hash as PHash;

use codec::{Decode, Encode};
use futures::FutureExt;
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
				return None;
			}
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
		mut self,
		slot_info: NewSlotInfo,
	) -> Option<BundleResult> {
		Some(BundleResult {
			bundle: Bundle {
				header: slot_info.slot.to_be_bytes().to_vec(),
				opaque_transactions: b"opaque_transactions".to_vec()
			}
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
		announce_block: _,
		mut overseer_handle,
		spawner: _,
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
	let executor = Executor::new(
		block_status,
		runtime_api,
		parachain_consensus,
		client,
	);

	let span = tracing::Span::current();
	let executor_clone = executor.clone();
	let span_clone = span.clone();
	let config = CollationGenerationConfig {
		key,
		collator: Box::new(move |relay_parent, validation_data| {
			let executor = executor_clone.clone();

			executor
				.produce_candidate(relay_parent, validation_data.clone())
				.instrument(span_clone.clone())
				.boxed()
		}),
		bundler: Box::new(move |slot_info| {
			let executor = executor.clone();

			executor
				.produce_bundle(slot_info)
				.instrument(span.clone())
				.boxed()
		}),
	};

	overseer_handle
		.send_msg(CollationGenerationMessage::Initialize(config), "StartCollator")
		.await;
}
