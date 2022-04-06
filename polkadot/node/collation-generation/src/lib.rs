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

use cirrus_node_primitives::{CollationGenerationConfig, ExecutorSlotInfo};
use futures::future::FutureExt;
use polkadot_node_subsystem::{
	messages::CollationGenerationMessage, overseer, ActiveLeavesUpdate, FromOverseer,
	OverseerSignal, RuntimeApiError, SpawnedSubsystem, SubsystemContext, SubsystemError,
	SubsystemResult,
};
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use sp_runtime::generic::DigestItem;
use std::sync::Arc;
use subspace_runtime_primitives::{
	opaque::{Block, BlockId},
	Hash,
};

mod error;

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

	/// Run this subsystem
	///
	/// Conceptually, this is very simple: it just loops forever.
	///
	/// - On incoming overseer messages, it starts or stops jobs as appropriate.
	/// - On other incoming messages, if they can be converted into `Job::ToJob` and
	///   include a hash, then they're forwarded to the appropriate individual job.
	/// - On outgoing messages from the jobs, it forwards them to the overseer.
	///
	/// If `err_tx` is not `None`, errors are forwarded onto that channel as they occur.
	/// Otherwise, most are logged and then discarded.
	async fn run<Context>(mut self, mut ctx: Context)
	where
		Context: SubsystemContext<Message = CollationGenerationMessage>,
		Context: overseer::SubsystemContext<Message = CollationGenerationMessage>,
	{
		loop {
			let incoming = ctx.recv().await;
			if self.handle_incoming::<Context>(incoming, &mut ctx).await {
				break
			}
		}
	}

	// handle an incoming message. return true if we should break afterwards.
	// note: this doesn't strictly need to be a separate function; it's more an administrative function
	// so that we don't clutter the run loop. It could in principle be inlined directly into there.
	// it should hopefully therefore be ok that it's an async function mutably borrowing self.
	async fn handle_incoming<Context>(
		&mut self,
		incoming: SubsystemResult<FromOverseer<<Context as SubsystemContext>::Message>>,
		ctx: &mut Context,
	) -> bool
	where
		Context: SubsystemContext<Message = CollationGenerationMessage>,
		Context: overseer::SubsystemContext<Message = CollationGenerationMessage>,
	{
		match incoming {
			Ok(FromOverseer::Signal(OverseerSignal::ActiveLeaves(ActiveLeavesUpdate {
				activated,
				..
			}))) => {
				// follow the procedure from the guide
				if let Some(config) = &self.config {
					if let Err(err) = handle_new_activations(
						&self.primary_chain_client,
						config,
						activated.into_iter().map(|v| v.hash),
						ctx,
					)
					.await
					{
						tracing::warn!(target: LOG_TARGET, err = ?err, "failed to handle new activations");
					}
				}

				false
			},
			Ok(FromOverseer::Signal(OverseerSignal::Conclude)) => true,
			Ok(FromOverseer::Communication { msg }) => {
				match msg {
					CollationGenerationMessage::Initialize(config) =>
						if self.config.is_some() {
							tracing::error!(target: LOG_TARGET, "double initialization");
						} else {
							self.config = Some(Arc::new(config));
						},
					CollationGenerationMessage::FraudProof(fraud_proof) => {
						if let Err(err) = submit_fraud_proof(
							Arc::clone(&self.primary_chain_client),
							fraud_proof,
							ctx,
						)
						.await
						{
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
						if let Err(err) = submit_bundle_equivocation_proof(
							Arc::clone(&self.primary_chain_client),
							bundle_equivocation_proof,
							ctx,
						)
						.await
						{
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit bundle equivocation proof"
							);
						},
					CollationGenerationMessage::InvalidTransactionProof(
						invalid_transaction_proof,
					) =>
						if let Err(err) = submit_invalid_transaction_proof(
							Arc::clone(&self.primary_chain_client),
							invalid_transaction_proof,
							ctx,
						)
						.await
						{
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit invalid transaction proof"
							);
						},
				}
				false
			},
			Ok(FromOverseer::Signal(OverseerSignal::NewSlot(slot_info))) => {
				if let Some(config) = &self.config {
					if let Err(err) = produce_bundle(
						Arc::clone(&self.primary_chain_client),
						config.clone(),
						slot_info,
						ctx,
					)
					.await
					{
						tracing::warn!(target: LOG_TARGET, err = ?err, "failed to produce new bundle");
					}
				}
				false
			},
			Err(err) => {
				tracing::error!(
					target: LOG_TARGET,
					err = ?err,
					"error receiving message from subsystem context: {:?}",
					err
				);
				true
			},
		}
	}
}

impl<Client, Context> overseer::Subsystem<Context, SubsystemError>
	for CollationGenerationSubsystem<Client>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
	Context: SubsystemContext<Message = CollationGenerationMessage>,
	Context: overseer::SubsystemContext<Message = CollationGenerationMessage>,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		let future = async move {
			self.run(ctx).await;
			Ok(())
		}
		.boxed();

		SpawnedSubsystem { name: "collation-generation-subsystem", future }
	}
}

/// Produces collations on each tip of primary chain.
async fn handle_new_activations<Client, Context: SubsystemContext>(
	client: &Arc<Client>,
	config: &CollationGenerationConfig,
	activated: impl IntoIterator<Item = Hash>,
	ctx: &mut Context,
) -> crate::error::Result<()>
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
		process_primary_block(Arc::clone(client), config, relay_parent, ctx).await?;
	}

	Ok(())
}

/// Apply the transaction bundles for given primary block as follows:
///
/// 1. Extract the transaction bundles from the block.
/// 2. Pass the bundles to secondary node and do the computation there.
async fn process_primary_block<Client, Context: SubsystemContext>(
	client: Arc<Client>,
	config: &CollationGenerationConfig,
	block_hash: Hash,
	ctx: &mut Context,
) -> crate::error::Result<()>
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

	let bundles = client
		.runtime_api()
		.extract_bundles(&block_id, extrinsics)
		.map_err(|e| RuntimeApiError::from(e.to_string()))?;

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
		Some(
			client
				.runtime_api()
				.execution_wasm_bundle(&block_id)
				.map_err(|e| RuntimeApiError::from(e.to_string()))?,
		)
	} else {
		None
	};

	let shuffling_seed = client
		.runtime_api()
		.extrinsics_shuffling_seed(&block_id, header)
		.map_err(|e| RuntimeApiError::from(e.to_string()))?;

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

	ctx.spawn(
		"collation generation submit execution receipt",
		Box::pin(async move {
			if let Err(err) = client
				.runtime_api()
				.submit_execution_receipt_unsigned(
					&BlockId::Hash(best_hash),
					opaque_execution_receipt,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()))
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send execution receipt",
				);
			} else {
				tracing::debug!(target: LOG_TARGET, "Sent execution receipt successfully",);
			}
		}),
	)?;

	Ok(())
}

async fn produce_bundle<Client, Context: SubsystemContext>(
	client: Arc<Client>,
	config: Arc<CollationGenerationConfig>,
	slot_info: ExecutorSlotInfo,
	ctx: &mut Context,
) -> SubsystemResult<()>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	let best_hash = client.info().best_hash;

	let opaque_bundle = match (config.bundler)(best_hash, slot_info).await {
		Some(bundle_result) => bundle_result.to_opaque_bundle(),
		None => {
			tracing::debug!(target: LOG_TARGET, "executor returned no bundle on bundling",);
			return Ok(())
		},
	};

	ctx.spawn(
		"collation generation bundle builder",
		Box::pin(async move {
			if let Err(err) = client
				.runtime_api()
				.submit_transaction_bundle_unsigned(&BlockId::Hash(best_hash), opaque_bundle)
				.map_err(|e| RuntimeApiError::from(e.to_string()))
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send transaction bundle",
				);
			} else {
				tracing::debug!(target: LOG_TARGET, "Sent transaction bundle successfully",);
			}
		}),
	)?;

	Ok(())
}

async fn submit_fraud_proof<Client, Context: SubsystemContext>(
	client: Arc<Client>,
	fraud_proof: FraudProof,
	ctx: &mut Context,
) -> SubsystemResult<()>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	ctx.spawn(
		"collation generation fraud proof builder",
		Box::pin(async move {
			if let Err(err) = client
				.runtime_api()
				.submit_fraud_proof_unsigned(&BlockId::Hash(client.info().best_hash), fraud_proof)
				.map_err(|e| RuntimeApiError::from(e.to_string()))
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send fraud proof",
				);
			} else {
				tracing::debug!(target: LOG_TARGET, "Sent fraud proof successfully",);
			}
		}),
	)?;

	Ok(())
}

async fn submit_bundle_equivocation_proof<Client, Context: SubsystemContext>(
	client: Arc<Client>,
	bundle_equivocation_proof: BundleEquivocationProof,
	ctx: &mut Context,
) -> SubsystemResult<()>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	ctx.spawn(
		"collation generation bundle equivocation proof builder",
		Box::pin(async move {
			if let Err(err) = client
				.runtime_api()
				.submit_bundle_equivocation_proof_unsigned(
					&BlockId::Hash(client.info().best_hash),
					bundle_equivocation_proof,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()))
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send equivocation proof",
				);
			} else {
				tracing::debug!(target: LOG_TARGET, "Sent equivocation proof successfully",);
			}
		}),
	)?;

	Ok(())
}

async fn submit_invalid_transaction_proof<Client, Context: SubsystemContext>(
	client: Arc<Client>,
	invalid_transaction_proof: InvalidTransactionProof,
	ctx: &mut Context,
) -> SubsystemResult<()>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
{
	ctx.spawn(
		"collation generation invalid transaction proof builder",
		Box::pin(async move {
			if let Err(err) = client
				.runtime_api()
				.submit_invalid_transaction_proof_unsigned(
					&BlockId::Hash(client.info().best_hash),
					invalid_transaction_proof,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()))
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send invalid transaction proof",
				);
			} else {
				tracing::debug!(target: LOG_TARGET, "Sent invalid transaction proof successfully",);
			}
		}),
	)?;

	Ok(())
}
