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

//! Implements the Runtime API Subsystem
//!
//! This provides a clean, ownerless wrapper around the parachain-related runtime APIs. This crate
//! can also be used to cache responses from heavy runtime APIs.

#![deny(unused_crate_dependencies)]
#![warn(missing_docs)]
#![allow(clippy::all)]

use polkadot_node_subsystem_util::metrics::{self, prometheus};
use polkadot_subsystem::{
	errors::RuntimeApiError,
	messages::{RuntimeApiMessage, RuntimeApiRequest as Request},
	overseer, FromOverseer, OverseerSignal, SpawnedSubsystem, SubsystemContext, SubsystemError,
	SubsystemResult,
};
use subspace_runtime_primitives::{
	opaque::{Block, BlockId},
	Hash,
};

use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_executor::ExecutorApi;

use cache::{RequestResult, RequestResultCache};
use futures::{channel::oneshot, prelude::*, select, stream::FuturesUnordered};
use std::{collections::VecDeque, pin::Pin, sync::Arc};

mod cache;

const LOG_TARGET: &str = "parachain::runtime-api";

/// The number of maximum runtime API requests can be executed in parallel. Further requests will be buffered.
const MAX_PARALLEL_REQUESTS: usize = 4;

/// The name of the blocking task that executes a runtime API request.
const API_REQUEST_TASK_NAME: &str = "polkadot-runtime-api-request";

/// The `RuntimeApiSubsystem`. See module docs for more details.
pub struct RuntimeApiSubsystem<Client> {
	client: Arc<Client>,
	metrics: Metrics,
	spawn_handle: Box<dyn SpawnNamed>,
	/// If there are [`MAX_PARALLEL_REQUESTS`] requests being executed, we buffer them in here until they can be executed.
	#[allow(unused)]
	waiting_requests: VecDeque<(
		Pin<Box<dyn Future<Output = ()> + Send>>,
		oneshot::Receiver<Option<RequestResult>>,
	)>,
	/// All the active runtime API requests that are currently being executed.
	active_requests: FuturesUnordered<oneshot::Receiver<Option<RequestResult>>>,
	/// Requests results cache
	#[allow(unused)]
	requests_cache: RequestResultCache,
}

impl<Client> RuntimeApiSubsystem<Client> {
	/// Create a new Runtime API subsystem wrapping the given client and metrics.
	pub fn new(
		client: Arc<Client>,
		metrics: Metrics,
		spawn_handle: impl SpawnNamed + 'static,
	) -> Self {
		RuntimeApiSubsystem {
			client,
			metrics,
			spawn_handle: Box::new(spawn_handle),
			waiting_requests: Default::default(),
			active_requests: Default::default(),
			requests_cache: RequestResultCache::default(),
		}
	}
}

impl<Client, Context> overseer::Subsystem<Context, SubsystemError> for RuntimeApiSubsystem<Client>
where
	Client: ProvideRuntimeApi<Block> + Send + 'static + Sync,
	Client::Api: ExecutorApi<Block>,
	Context: SubsystemContext<Message = RuntimeApiMessage>,
	Context: overseer::SubsystemContext<Message = RuntimeApiMessage>,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		SpawnedSubsystem { future: run(ctx, self).boxed(), name: "runtime-api-subsystem" }
	}
}

impl<Client> RuntimeApiSubsystem<Client>
where
	Client: ProvideRuntimeApi<Block> + Send + 'static + Sync,
	Client::Api: ExecutorApi<Block>,
{
	fn store_cache(&mut self, result: RequestResult) {
		use RequestResult::*;

		match result {
			SubmitCandidateReceipt(..) => {},
			SubmitExecutionReceipt(..) => {},
			SubmitTransactionBundle(..) => {},
			ExtractBundles(..) => {},
			PendingHead(..) => {},
		}
	}

	#[allow(unused)]
	fn query_cache(&mut self, _relay_parent: Hash, request: Request) -> Option<Request> {
		macro_rules! query {
			// Just query by relay parent
			($cache_api_name:ident (), $sender:expr) => {{
				let sender = $sender;
				if let Some(value) = self.requests_cache.$cache_api_name(&relay_parent) {
					let _ = sender.send(Ok(value.clone()));
					self.metrics.on_cached_request();
					None
				} else {
					Some(sender)
				}
			}};
			// Query by relay parent + additional parameters
			($cache_api_name:ident ($($param:expr),+), $sender:expr) => {{
				let sender = $sender;
				if let Some(value) = self.requests_cache.$cache_api_name((relay_parent.clone(), $($param.clone()),+)) {
					self.metrics.on_cached_request();
					let _ = sender.send(Ok(value.clone()));
					None
				} else {
					Some(sender)
				}
			}}
		}

		match request {
			Request::SubmitCandidateReceipt(..) => None,
			Request::SubmitExecutionReceipt(..) => None,
			Request::SubmitTransactionBundle(..) => None,
			Request::ExtractBundles(..) => None,
			Request::PendingHead(..) => None,
		}
	}

	/// Spawn a runtime API request.
	///
	/// If there are already [`MAX_PARALLEL_REQUESTS`] requests being executed, the request will be buffered.
	fn spawn_request(&mut self, relay_parent: Hash, request: Request) {
		let client = self.client.clone();
		let metrics = self.metrics.clone();
		let (sender, receiver) = oneshot::channel();

		// FIXME: Re-enable the cache
		// let request = match self.query_cache(relay_parent.clone(), request) {
		// Some(request) => request,
		// None => return,
		// };

		let request = async move {
			let result = make_runtime_api_request(client, metrics, relay_parent, request);
			let _ = sender.send(result);
		}
		.boxed();

		if self.active_requests.len() >= MAX_PARALLEL_REQUESTS {
			self.waiting_requests.push_back((request, receiver));

			if self.waiting_requests.len() > MAX_PARALLEL_REQUESTS * 10 {
				tracing::warn!(
					target: LOG_TARGET,
					"{} runtime API requests waiting to be executed.",
					self.waiting_requests.len(),
				)
			}
		} else {
			self.spawn_handle
				.spawn_blocking(API_REQUEST_TASK_NAME, Some("runtime-api"), request);
			self.active_requests.push(receiver);
		}
	}

	/// Poll the active runtime API requests.
	async fn poll_requests(&mut self) {
		// If there are no active requests, this future should be pending forever.
		if self.active_requests.len() == 0 {
			return futures::pending!()
		}

		// If there are active requests, this will always resolve to `Some(_)` when a request is finished.
		if let Some(Ok(Some(result))) = self.active_requests.next().await {
			self.store_cache(result);
		}

		if let Some((req, recv)) = self.waiting_requests.pop_front() {
			self.spawn_handle
				.spawn_blocking(API_REQUEST_TASK_NAME, Some("runtime-api"), req);
			self.active_requests.push(recv);
		}
	}
}

async fn run<Client, Context>(
	mut ctx: Context,
	mut subsystem: RuntimeApiSubsystem<Client>,
) -> SubsystemResult<()>
where
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	Client::Api: ExecutorApi<Block>,
	Context: SubsystemContext<Message = RuntimeApiMessage>,
	Context: overseer::SubsystemContext<Message = RuntimeApiMessage>,
{
	loop {
		select! {
			req = ctx.recv().fuse() => match req? {
				FromOverseer::Signal(OverseerSignal::Conclude) => return Ok(()),
				FromOverseer::Signal(OverseerSignal::ActiveLeaves(_)) => {},
				FromOverseer::Signal(OverseerSignal::BlockFinalized(..)) => {},
				FromOverseer::Signal(OverseerSignal::NewSlot(..)) => {},
				FromOverseer::Communication { msg } => match msg {
					RuntimeApiMessage::Request(relay_parent, request) => {
						subsystem.spawn_request(relay_parent, request);
					},
				}
			},
			_ = subsystem.poll_requests().fuse() => {},
		}
	}
}

fn make_runtime_api_request<Client>(
	client: Arc<Client>,
	metrics: Metrics,
	relay_parent: Hash,
	request: Request,
) -> Option<RequestResult>
where
	Client: ProvideRuntimeApi<Block>,
	Client::Api: ExecutorApi<Block>,
{
	let _timer = metrics.time_make_runtime_api_request();

	// TODO: re-enable the marco to reduce the pattern duplication.
	match request {
		Request::SubmitCandidateReceipt(head_number, head_hash) => {
			let api = client.runtime_api();
			let res = api
				.submit_candidate_receipt_unsigned(
					&BlockId::Hash(relay_parent),
					head_number,
					head_hash,
				)
				.map_err(|e| RuntimeApiError::from(format!("{:?}", e)));
			metrics.on_request(res.is_ok());
			res.ok().map(|_res| {
				RequestResult::SubmitCandidateReceipt(relay_parent, head_number, head_hash)
			});
		},
		Request::SubmitExecutionReceipt(execution_receipt) => {
			let api = client.runtime_api();
			let execution_receipt_hash = execution_receipt.hash();
			let res = api
				.submit_execution_receipt_unsigned(&BlockId::Hash(relay_parent), execution_receipt)
				.map_err(|e| RuntimeApiError::from(format!("{:?}", e)));
			metrics.on_request(res.is_ok());
			res.ok().map(|_res| {
				RequestResult::SubmitExecutionReceipt(relay_parent, execution_receipt_hash)
			});
		},
		Request::SubmitTransactionBundle(bundle) => {
			let api = client.runtime_api();
			let bundle_hash = bundle.hash();
			let res = api
				.submit_transaction_bundle_unsigned(&BlockId::Hash(relay_parent), bundle)
				.map_err(|e| RuntimeApiError::from(format!("{:?}", e)));
			metrics.on_request(res.is_ok());
			res.ok()
				.map(|_res| RequestResult::SubmitTransactionBundle(relay_parent, bundle_hash));
		},
		Request::ExtractBundles(extrinsics, sender) => {
			let api = client.runtime_api();
			let res = api
				.extract_bundles(&BlockId::Hash(relay_parent), extrinsics)
				.map_err(|e| RuntimeApiError::from(format!("{:?}", e)));
			metrics.on_request(res.is_ok());

			let _ = sender.send(res.clone());

			res.ok().map(|_res| RequestResult::ExtractBundles(relay_parent));
		},

		Request::PendingHead(sender) => {
			let api = client.runtime_api();
			let res = api
				.pending_head(&BlockId::Hash(relay_parent))
				.map_err(|e| RuntimeApiError::from(format!("{:?}", e)));
			metrics.on_request(res.is_ok());

			let _ = sender.send(res.clone());

			res.ok().map(|res| RequestResult::PendingHead(relay_parent, res));
		},
	}

	None
}

#[derive(Clone)]
struct MetricsInner {
	chain_api_requests: prometheus::CounterVec<prometheus::U64>,
	make_runtime_api_request: prometheus::Histogram,
}

/// Runtime API metrics.
#[derive(Default, Clone)]
pub struct Metrics(Option<MetricsInner>);

impl Metrics {
	fn on_request(&self, succeeded: bool) {
		if let Some(metrics) = &self.0 {
			if succeeded {
				metrics.chain_api_requests.with_label_values(&["succeeded"]).inc();
			} else {
				metrics.chain_api_requests.with_label_values(&["failed"]).inc();
			}
		}
	}

	#[allow(unused)]
	fn on_cached_request(&self) {
		self.0
			.as_ref()
			.map(|metrics| metrics.chain_api_requests.with_label_values(&["cached"]).inc());
	}

	/// Provide a timer for `make_runtime_api_request` which observes on drop.
	fn time_make_runtime_api_request(
		&self,
	) -> Option<metrics::prometheus::prometheus::HistogramTimer> {
		self.0.as_ref().map(|metrics| metrics.make_runtime_api_request.start_timer())
	}
}

impl metrics::Metrics for Metrics {
	fn try_register(registry: &prometheus::Registry) -> Result<Self, prometheus::PrometheusError> {
		let metrics = MetricsInner {
			chain_api_requests: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"parachain_runtime_api_requests_total",
						"Number of Runtime API requests served.",
					),
					&["success"],
				)?,
				registry,
			)?,
			make_runtime_api_request: prometheus::register(
				prometheus::Histogram::with_opts(prometheus::HistogramOpts::new(
					"parachain_runtime_api_make_runtime_api_request",
					"Time spent within `runtime_api::make_runtime_api_request`",
				))?,
				registry,
			)?,
		};
		Ok(Metrics(Some(metrics)))
	}
}
