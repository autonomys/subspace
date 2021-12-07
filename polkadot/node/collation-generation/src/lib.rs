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

use futures::{channel::mpsc, future::FutureExt, select, sink::SinkExt, stream::StreamExt};
use parity_scale_codec::Encode;
use polkadot_node_subsystem::{
	messages::{AllMessages, CollationGenerationMessage, RuntimeApiMessage, RuntimeApiRequest},
	overseer, ActiveLeavesUpdate, FromOverseer, OverseerSignal, SpawnedSubsystem, SubsystemContext,
	SubsystemError, SubsystemResult,
};
use polkadot_node_subsystem_util::{
	metrics::{self, prometheus},
	request_pending_head,
};
use std::sync::Arc;

use cirrus_node_primitives::{CollationGenerationConfig, PersistedValidationData};
use subspace_runtime_primitives::{Hash};

mod error;

const LOG_TARGET: &'static str = "parachain::collation-generation";

/// Collation Generation Subsystem
pub struct CollationGenerationSubsystem {
	config: Option<Arc<CollationGenerationConfig>>,
	metrics: Metrics,
}

impl CollationGenerationSubsystem {
	/// Create a new instance of the `CollationGenerationSubsystem`.
	pub fn new(metrics: Metrics) -> Self {
		Self { config: None, metrics }
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
					let metrics = self.metrics.clone();
					if let Err(err) = handle_new_activations_subspace(
						config.clone(),
						activated.into_iter().map(|v| v.hash),
						ctx,
						metrics,
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
			Ok(FromOverseer::Communication {
				msg: CollationGenerationMessage::Initialize(config),
			}) => {
				if self.config.is_some() {
					tracing::error!(target: LOG_TARGET, "double initialization");
				} else {
					self.config = Some(Arc::new(config));
				}
				false
			},
			Ok(FromOverseer::Signal(OverseerSignal::BlockFinalized(..))) => false,
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
async fn handle_new_activations_subspace<Context: SubsystemContext>(
	config: Arc<CollationGenerationConfig>,
	activated: impl IntoIterator<Item = Hash>,
	ctx: &mut Context,
	_metrics: Metrics,
	sender: &mpsc::Sender<AllMessages>,
) -> crate::error::Result<()> {
	for relay_parent in activated {
		let task_config = config.clone();

		// Request the current pending head of executor chain because the executor chain
		// needs it to form a chain correctly.
		let maybe_pending_head: Option<Hash> =
			match request_pending_head(relay_parent, ctx.sender()).await.await? {
				Ok(h) => h,
				Err(e) => {
					tracing::trace!(
						target: LOG_TARGET,
						relay_parent = ?relay_parent,
						error = ?e,
						"Pending head is not available",
					);
					continue
				},
			};

		let validation_data = PersistedValidationData {
			parent_head: maybe_pending_head.encode(),
			..Default::default()
		};

		let (collation, _result_sender) =
			match (task_config.collator)(relay_parent, &validation_data).await {
				Some(collation) => collation.into_inner(),
				None => {
					tracing::debug!(
						target: LOG_TARGET,
						"collator returned no collation on collate",
					);
					return Ok(())
				},
			};

		// Pretend we are processing the ER and then submit it
		// to primary chain via an unsigned extrinsic.
		let head_hash = collation.head_data.hash();
		let head_number = collation.number;

		let mut task_sender = sender.clone();
		ctx.spawn(
			"collation generation collation builder",
			Box::pin(async move {
				if let Err(err) = task_sender
					.send(AllMessages::RuntimeApi(RuntimeApiMessage::Request(
						relay_parent,
						RuntimeApiRequest::SubmitCandidateReceipt(head_number, head_hash),
					)))
					.await
				{
					tracing::warn!(
						target: LOG_TARGET,
						err = ?err,
						"failed to send RuntimeApiRequest::SubmitCandidateReceipt",
					);
				} else {
					tracing::debug!(
						target: LOG_TARGET,
						"Sent RuntimeApiRequest::SubmitCandidateReceipt successfully",
					);
				}
			}),
		)?;
	}

	Ok(())
}

// TODO: fix unused
#[allow(unused)]
#[derive(Clone)]
struct MetricsInner {
	collations_generated_total: prometheus::Counter<prometheus::U64>,
	new_activations_overall: prometheus::Histogram,
	new_activations_per_relay_parent: prometheus::Histogram,
	new_activations_per_availability_core: prometheus::Histogram,
}

/// `CollationGenerationSubsystem` metrics.
#[derive(Default, Clone)]
pub struct Metrics(Option<MetricsInner>);

// TODO: fix unused
#[allow(unused)]
impl Metrics {
	fn on_collation_generated(&self) {
		if let Some(metrics) = &self.0 {
			metrics.collations_generated_total.inc();
		}
	}

	/// Provide a timer for new activations which updates on drop.
	fn time_new_activations(&self) -> Option<metrics::prometheus::prometheus::HistogramTimer> {
		self.0.as_ref().map(|metrics| metrics.new_activations_overall.start_timer())
	}

	/// Provide a timer per relay parents which updates on drop.
	fn time_new_activations_relay_parent(
		&self,
	) -> Option<metrics::prometheus::prometheus::HistogramTimer> {
		self.0
			.as_ref()
			.map(|metrics| metrics.new_activations_per_relay_parent.start_timer())
	}

	/// Provide a timer per availability core which updates on drop.
	fn time_new_activations_availability_core(
		&self,
	) -> Option<metrics::prometheus::prometheus::HistogramTimer> {
		self.0
			.as_ref()
			.map(|metrics| metrics.new_activations_per_availability_core.start_timer())
	}
}

impl metrics::Metrics for Metrics {
	fn try_register(registry: &prometheus::Registry) -> Result<Self, prometheus::PrometheusError> {
		let metrics = MetricsInner {
			collations_generated_total: prometheus::register(
				prometheus::Counter::new(
					"parachain_collations_generated_total",
					"Number of collations generated."
				)?,
				registry,
			)?,
			new_activations_overall: prometheus::register(
				prometheus::Histogram::with_opts(
					prometheus::HistogramOpts::new(
						"parachain_collation_generation_new_activations",
						"Time spent within fn handle_new_activations",
					)
				)?,
				registry,
			)?,
			new_activations_per_relay_parent: prometheus::register(
				prometheus::Histogram::with_opts(
					prometheus::HistogramOpts::new(
						"parachain_collation_generation_per_relay_parent",
						"Time spent handling a particular relay parent within fn handle_new_activations"
					)
				)?,
				registry,
			)?,
			new_activations_per_availability_core: prometheus::register(
				prometheus::Histogram::with_opts(
					prometheus::HistogramOpts::new(
						"parachain_collation_generation_per_availability_core",
						"Time spent handling a particular availability core for a relay parent in fn handle_new_activations",
					)
				)?,
				registry,
			)?,
		};
		Ok(Metrics(Some(metrics)))
	}
}
