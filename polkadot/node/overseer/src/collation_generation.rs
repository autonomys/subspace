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

//! The collation generation subsystem is the interface between polkadot and the collators.

#![deny(missing_docs)]

use crate::{ActiveLeavesUpdate, OverseerSignal};
use cirrus_node_primitives::CollationGenerationConfig;
use sc_client_api::BlockBackend;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use sp_runtime::generic::DigestItem;
use std::sync::Arc;
use subspace_runtime_primitives::{
	opaque::{Block, BlockId},
	Hash,
};

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
pub enum CollationGenerationMessage {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig),
	/// Fraud proof needs to be submitted to primary chain.
	FraudProof(FraudProof),
	/// Bundle equivocation proof needs to be submitted to primary chain.
	BundleEquivocationProof(BundleEquivocationProof),
	/// Invalid transaction proof needs to be submitted to primary chain.
	InvalidTransactionProof(InvalidTransactionProof),
}

// Simplify usage without having to do large scale modifications of all
// subsystems at once.

const LOG_TARGET: &str = "parachain::collation-generation";

/// Collation Generation Subsystem
pub struct CollationGenerationSubsystem<Client> {
	primary_chain_client: Arc<Client>,
	config: Option<Arc<CollationGenerationConfig>>,
}

impl<Client> CollationGenerationSubsystem<Client>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	/// Create a new instance of the `CollationGenerationSubsystem`.
	pub fn new(primary_chain_client: Arc<Client>) -> Self {
		Self { primary_chain_client, config: None }
	}

	// handle an incoming message. return true if we should break afterwards.
	// note: this doesn't strictly need to be a separate function; it's more an administrative function
	// so that we don't clutter the run loop. It could in principle be inlined directly into there.
	// it should hopefully therefore be ok that it's an async function mutably borrowing self.
	pub(crate) async fn handle_incoming(&mut self, incoming: crate::FromOverseer) -> bool {
		match incoming {
			crate::FromOverseer::Signal(OverseerSignal::ActiveLeaves(ActiveLeavesUpdate {
				activated,
				..
			})) => {
				// follow the procedure from the guide
				if let Some(config) = &self.config {
					if let Err(err) = handle_new_activations(
						&self.primary_chain_client,
						config,
						activated.into_iter().map(|v| v.hash),
					)
					.await
					{
						tracing::warn!(target: LOG_TARGET, err = ?err, "failed to handle new activations");
					}
				}

				false
			},
			crate::FromOverseer::Signal(OverseerSignal::Conclude) => true,
			crate::FromOverseer::Communication { msg } => {
				let client = &self.primary_chain_client;

				match msg {
					CollationGenerationMessage::Initialize(config) =>
						if self.config.is_some() {
							tracing::error!(target: LOG_TARGET, "double initialization");
						} else {
							self.config = Some(Arc::new(config));
						},
					CollationGenerationMessage::FraudProof(fraud_proof) => {
						// TODO: Handle returned result?
						if let Err(err) = client.runtime_api().submit_fraud_proof_unsigned(
							&BlockId::Hash(client.info().best_hash),
							fraud_proof,
						) {
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit fraud proof"
							);
						}
					},
					CollationGenerationMessage::BundleEquivocationProof(
						bundle_equivocation_proof,
					) =>
					// TODO: Handle returned result?
						if let Err(err) =
							client.runtime_api().submit_bundle_equivocation_proof_unsigned(
								&BlockId::Hash(client.info().best_hash),
								bundle_equivocation_proof,
							) {
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit bundle equivocation proof"
							);
						},
					CollationGenerationMessage::InvalidTransactionProof(
						invalid_transaction_proof,
					) =>
					// TODO: Handle returned result?
						if let Err(err) = self
							.primary_chain_client
							.runtime_api()
							.submit_invalid_transaction_proof_unsigned(
								&BlockId::Hash(client.info().best_hash),
								invalid_transaction_proof,
							) {
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit invalid transaction proof"
							);
						},
				}
				false
			},
			crate::FromOverseer::Signal(OverseerSignal::NewSlot(slot_info)) => {
				// TODO: Handle returned result?
				if let Some(config) = &self.config {
					let client = &self.primary_chain_client;
					let best_hash = client.info().best_hash;

					let opaque_bundle = match (config.bundler)(best_hash, slot_info).await {
						Some(bundle_result) => bundle_result.to_opaque_bundle(),
						None => {
							tracing::debug!(
								target: LOG_TARGET,
								"executor returned no bundle on bundling",
							);
							return false
						},
					};

					if let Err(err) = client.runtime_api().submit_transaction_bundle_unsigned(
						&BlockId::Hash(best_hash),
						opaque_bundle,
					) {
						tracing::warn!(target: LOG_TARGET, err = ?err, "failed to produce new bundle");
					}
				}
				false
			},
		}
	}
}

/// Produces collations on each tip of primary chain.
async fn handle_new_activations<Client>(
	client: &Arc<Client>,
	config: &CollationGenerationConfig,
	activated: impl IntoIterator<Item = Hash>,
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
	for relay_parent in activated {
		// TODO: invoke this on finalized block?
		process_primary_block(Arc::clone(client), config, relay_parent).await?;
	}

	Ok(())
}

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
