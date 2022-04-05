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
#![allow(clippy::all)]

use futures::{
	channel::{mpsc, oneshot},
	future::FutureExt,
	select,
	sink::SinkExt,
	stream::StreamExt,
};
use polkadot_node_subsystem::{messages::{
	AllMessages, ChainApiMessage, CollationGenerationMessage, RuntimeApiMessage,
	RuntimeApiRequest, RuntimeApiSender
}, overseer, ActiveLeavesUpdate, FromOverseer, OverseerSignal, SpawnedSubsystem, SubsystemContext, SubsystemError, SubsystemSender, SubsystemResult, RuntimeApiError};
use sp_executor::OpaqueBundle;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::generic::DigestItem;
use std::borrow::Cow;
use std::sync::Arc;

use cirrus_node_primitives::{CollationGenerationConfig, ExecutorSlotInfo};
use sp_executor::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::Hash;
use subspace_runtime_primitives::{opaque::Header};

mod error;

const LOG_TARGET: &'static str = "parachain::collation-generation";

/// A type alias for Runtime API receivers.
type RuntimeApiReceiver<T> = oneshot::Receiver<Result<T, RuntimeApiError>>;

/// Request some data from the `RuntimeApi`.
async fn request_from_runtime<RequestBuilder, Response, Sender>(
	parent: Hash,
	sender: &mut Sender,
	request_builder: RequestBuilder,
) -> RuntimeApiReceiver<Response>
	where
		RequestBuilder: FnOnce(RuntimeApiSender<Response>) -> RuntimeApiRequest,
		Sender: SubsystemSender,
{
	let (tx, rx) = oneshot::channel();

	sender
		.send_message(RuntimeApiMessage::Request(parent, request_builder(tx)).into())
		.await;

	rx
}

/// Request `ExtractBundles` from the runtime
pub async fn request_extract_bundles(
	parent: Hash,
	extrinsics: Vec<OpaqueExtrinsic>,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Vec<OpaqueBundle>> {
	request_from_runtime(parent, sender, |tx| RuntimeApiRequest::ExtractBundles(extrinsics, tx))
		.await
}
/// Request `ExtrinsicsShufflingSeed "` from the runtime
pub async fn request_extrinsics_shuffling_seed(
	parent: Hash,
	header: Header,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Randomness> {
	request_from_runtime(parent, sender, |tx| {
		RuntimeApiRequest::ExtrinsicsShufflingSeed(header, tx)
	})
		.await
}
/// Rquest `ExecutionWasmBundle` from the runtime
pub async fn request_execution_wasm_bundle(
	parent: Hash,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Cow<'static, [u8]>> {
	request_from_runtime(parent, sender, RuntimeApiRequest::ExecutionWasmBundle).await
}


/// Collation Generation Subsystem
pub struct CollationGenerationSubsystem {
	config: Option<Arc<CollationGenerationConfig>>,
}

impl CollationGenerationSubsystem {
	/// Create a new instance of the `CollationGenerationSubsystem`.
	pub fn new() -> Self {
		Self { config: None }
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
		// when we activate new leaves, we spawn a bunch of sub-tasks, each of which is
		// expected to generate precisely one message. We don't want to block the main loop
		// at any point waiting for them all, so instead, we create a channel on which they can
		// send those messages. We can then just monitor the channel and forward messages on it
		// to the overseer here, via the context.
		let (sender, receiver) = mpsc::channel(0);

		let mut receiver = receiver.fuse();
		loop {
			select! {
				incoming = ctx.recv().fuse() => {
					if self.handle_incoming::<Context>(incoming, &mut ctx, &sender).await {
						break;
					}
				},
				msg = receiver.next() => {
					if let Some(msg) = msg {
						ctx.send_message(msg).await;
					}
				},
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
		sender: &mpsc::Sender<AllMessages>,
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
						config.clone(),
						activated.into_iter().map(|v| v.hash),
						ctx,
						sender,
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
						if let Err(err) = submit_fraud_proof(fraud_proof, ctx, sender).await {
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit fraud proof"
							);
						}
					},
					CollationGenerationMessage::BundleEquivocationProof(
						bundle_equivocation_proof,
					) => {
						if let Err(err) =
							submit_bundle_equivocation_proof(bundle_equivocation_proof, ctx, sender)
								.await
						{
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit bundle equivocation proof"
							);
						}
					},
					CollationGenerationMessage::InvalidTransactionProof(
						invalid_transaction_proof,
					) => {
						if let Err(err) =
							submit_invalid_transaction_proof(invalid_transaction_proof, ctx, sender)
								.await
						{
							tracing::warn!(
								target: LOG_TARGET,
								?err,
								"failed to submit invalid transaction proof"
							);
						}
					},
				}
				false
			},
			Ok(FromOverseer::Signal(OverseerSignal::NewSlot(slot_info))) => {
				if let Some(config) = &self.config {
					if let Err(err) = produce_bundle(config.clone(), slot_info, ctx, sender).await {
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

impl<Context> overseer::Subsystem<Context, SubsystemError> for CollationGenerationSubsystem
where
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
async fn handle_new_activations<Context: SubsystemContext>(
	config: Arc<CollationGenerationConfig>,
	activated: impl IntoIterator<Item = Hash>,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> crate::error::Result<()> {
	for relay_parent in activated {
		// TODO: invoke this on finalized block?
		process_primary_block(config.clone(), relay_parent, ctx, sender).await?;
	}

	Ok(())
}

/// Apply the transaction bundles for given primary block as follows:
///
/// 1. Extract the transaction bundles from the block.
/// 2. Pass the bundles to secondary node and do the computation there.
async fn process_primary_block<Context: SubsystemContext>(
	config: Arc<CollationGenerationConfig>,
	block_hash: Hash,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> crate::error::Result<()> {
	let extrinsics = {
		let (tx, rx) = oneshot::channel();
		ctx.send_message(ChainApiMessage::BlockBody(block_hash, tx)).await;
		match rx.await? {
			Err(err) => {
				tracing::error!(
					target: LOG_TARGET,
					?err,
					"Chain API subsystem temporarily unreachable"
				);
				return Ok(())
			},
			Ok(None) => {
				tracing::error!(target: LOG_TARGET, ?block_hash, "BlockBody unavailable");
				return Ok(())
			},
			Ok(Some(b)) => b,
		}
	};

	let bundles = request_extract_bundles(block_hash, extrinsics, ctx.sender()).await.await??;

	let header = {
		let (tx, rx) = oneshot::channel();
		ctx.send_message(ChainApiMessage::BlockHeader(block_hash, tx)).await;
		match rx.await? {
			Err(err) => {
				tracing::error!(
					target: LOG_TARGET,
					?err,
					"Chain API subsystem temporarily unreachable"
				);
				return Ok(())
			},
			Ok(None) => {
				tracing::error!(target: LOG_TARGET, ?block_hash, "BlockHeader unavailable");
				return Ok(())
			},
			Ok(Some(h)) => h,
		}
	};

	let maybe_new_runtime = if header
		.digest
		.logs
		.iter()
		.any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
	{
		Some(request_execution_wasm_bundle(block_hash, ctx.sender()).await.await??)
	} else {
		None
	};

	let shuffling_seed = request_extrinsics_shuffling_seed(block_hash, header, ctx.sender())
		.await
		.await??;

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

	let best_hash = request_best_primary_hash(ctx).await?;

	let mut task_sender = sender.clone();
	ctx.spawn(
		"collation generation submit execution receipt",
		Box::pin(async move {
			if let Err(err) = task_sender
				.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					best_hash,
					RuntimeApiRequest::SubmitExecutionReceipt(opaque_execution_receipt),
				)))
				.await
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send RuntimeApiRequest::SubmitExecutionReceipt",
				);
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					"Sent RuntimeApiRequest::SubmitExecutionReceipt successfully",
				);
			}
		}),
	)?;

	Ok(())
}

async fn request_best_primary_hash<Context: SubsystemContext>(
	ctx: &mut Context,
) -> SubsystemResult<Hash> {
	let (tx, rx) = oneshot::channel();
	ctx.send_message(ChainApiMessage::BestBlockHash(tx)).await;
	rx.await?.map_err(|e| SubsystemError::with_origin("chain-api", e))
}

async fn produce_bundle<Context: SubsystemContext>(
	config: Arc<CollationGenerationConfig>,
	slot_info: ExecutorSlotInfo,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> SubsystemResult<()> {
	let best_hash = request_best_primary_hash(ctx).await?;

	let opaque_bundle = match (config.bundler)(best_hash, slot_info).await {
		Some(bundle_result) => bundle_result.to_opaque_bundle(),
		None => {
			tracing::debug!(target: LOG_TARGET, "executor returned no bundle on bundling",);
			return Ok(())
		},
	};

	let mut task_sender = sender.clone();
	ctx.spawn(
		"collation generation bundle builder",
		Box::pin(async move {
			if let Err(err) = task_sender
				.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					best_hash,
					RuntimeApiRequest::SubmitTransactionBundle(opaque_bundle),
				)))
				.await
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send RuntimeApiRequest::SubmitTransactionBundle",
				);
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					"Sent RuntimeApiRequest::SubmitTransactionBundle successfully",
				);
			}
		}),
	)?;

	Ok(())
}

async fn submit_fraud_proof<Context: SubsystemContext>(
	fraud_proof: FraudProof,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> SubsystemResult<()> {
	let best_hash = request_best_primary_hash(ctx).await?;

	let mut task_sender = sender.clone();
	ctx.spawn(
		"collation generation fraud proof builder",
		Box::pin(async move {
			if let Err(err) = task_sender
				.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					best_hash,
					RuntimeApiRequest::SubmitFraudProof(fraud_proof),
				)))
				.await
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send RuntimeApiRequest::SubmitFraudProof",
				);
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					"Sent RuntimeApiRequest::SubmitFraudProof successfully",
				);
			}
		}),
	)?;

	Ok(())
}

async fn submit_bundle_equivocation_proof<Context: SubsystemContext>(
	bundle_equivocation_proof: BundleEquivocationProof,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> SubsystemResult<()> {
	let best_hash = request_best_primary_hash(ctx).await?;

	let mut task_sender = sender.clone();
	ctx.spawn(
		"collation generation bundle equivocation proof builder",
		Box::pin(async move {
			if let Err(err) = task_sender
				.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					best_hash,
					RuntimeApiRequest::SubmitBundleEquivocationProof(bundle_equivocation_proof),
				)))
				.await
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send RuntimeApiRequest::SubmitBundleEquivocationProof",
				);
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					"Sent RuntimeApiRequest::SubmitBundleEquivocationProof successfully",
				);
			}
		}),
	)?;

	Ok(())
}

async fn submit_invalid_transaction_proof<Context: SubsystemContext>(
	invalid_transaction_proof: InvalidTransactionProof,
	ctx: &mut Context,
	sender: &mpsc::Sender<AllMessages>,
) -> SubsystemResult<()> {
	let best_hash = request_best_primary_hash(ctx).await?;

	let mut task_sender = sender.clone();
	ctx.spawn(
		"collation generation invalid transaction proof builder",
		Box::pin(async move {
			if let Err(err) = task_sender
				.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					best_hash,
					RuntimeApiRequest::SubmitInvalidTransactionProof(invalid_transaction_proof),
				)))
				.await
			{
				tracing::warn!(
					target: LOG_TARGET,
					err = ?err,
					"Failed to send RuntimeApiRequest::SubmitInvalidTransactionProof",
				);
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					"Sent RuntimeApiRequest::SubmitInvalidTransactionProof successfully",
				);
			}
		}),
	)?;

	Ok(())
}
