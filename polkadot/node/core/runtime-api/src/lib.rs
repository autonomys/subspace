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
	/// Create a new Runtime API subsystem wrapping the given client.
	pub fn new(client: Arc<Client>, spawn_handle: impl SpawnNamed + 'static) -> Self {
		RuntimeApiSubsystem {
			client,
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
			SubmitExecutionReceipt(..) => {},
			SubmitTransactionBundle(..) => {},
			SubmitFraudProof(..) => {},
			SubmitBundleEquivocationProof(..) => {},
			SubmitInvalidTransactionProof(..) => {},
			ExtractBundles(..) => {},
			ExtrinsicsShufflingSeed(..) => {},
			ExecutionWasmBundle(..) => {},
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
					None
				} else {
					Some(sender)
				}
			}};
			// Query by relay parent + additional parameters
			($cache_api_name:ident ($($param:expr),+), $sender:expr) => {{
				let sender = $sender;
				if let Some(value) = self.requests_cache.$cache_api_name((relay_parent.clone(), $($param.clone()),+)) {
					let _ = sender.send(Ok(value.clone()));
					None
				} else {
					Some(sender)
				}
			}}
		}

		match request {
			Request::SubmitExecutionReceipt(..) => None,
			Request::SubmitTransactionBundle(..) => None,
			Request::SubmitFraudProof(..) => None,
			Request::SubmitBundleEquivocationProof(..) => None,
			Request::SubmitInvalidTransactionProof(..) => None,
			Request::ExtractBundles(..) => None,
			Request::ExtrinsicsShufflingSeed(..) => None,
			Request::ExecutionWasmBundle(..) => None,
		}
	}

	/// Spawn a runtime API request.
	///
	/// If there are already [`MAX_PARALLEL_REQUESTS`] requests being executed, the request will be buffered.
	fn spawn_request(&mut self, relay_parent: Hash, request: Request) {
		let client = self.client.clone();
		let (sender, receiver) = oneshot::channel();

		// FIXME: Re-enable the cache
		// let request = match self.query_cache(relay_parent.clone(), request) {
		// Some(request) => request,
		// None => return,
		// };

		let request = async move {
			let result = make_runtime_api_request(client, relay_parent, request);
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
	relay_parent: Hash,
	request: Request,
) -> Option<RequestResult>
where
	Client: ProvideRuntimeApi<Block>,
	Client::Api: ExecutorApi<Block>,
{
	// TODO: re-enable the marco to reduce the pattern duplication.
	match request {
		Request::SubmitExecutionReceipt(opaque_execution_receipt) => {
			let api = client.runtime_api();
			let res = api
				.submit_execution_receipt_unsigned(
					&BlockId::Hash(relay_parent),
					opaque_execution_receipt,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()));
			res.ok().map(|_res| RequestResult::SubmitExecutionReceipt(relay_parent));
		},
		Request::SubmitTransactionBundle(opaque_bundle) => {
			let api = client.runtime_api();
			let bundle_hash = opaque_bundle.hash();
			let res = api
				.submit_transaction_bundle_unsigned(&BlockId::Hash(relay_parent), opaque_bundle)
				.map_err(|e| RuntimeApiError::from(e.to_string()));
			res.ok()
				.map(|_res| RequestResult::SubmitTransactionBundle(relay_parent, bundle_hash));
		},
		Request::SubmitFraudProof(fraud_proof) => {
			let api = client.runtime_api();
			let res = api
				.submit_fraud_proof_unsigned(&BlockId::Hash(relay_parent), fraud_proof)
				.map_err(|e| RuntimeApiError::from(e.to_string()));
			res.ok().map(|_res| RequestResult::SubmitFraudProof(relay_parent));
		},
		Request::SubmitBundleEquivocationProof(bundle_equivocation_proof) => {
			let api = client.runtime_api();
			let res = api
				.submit_bundle_equivocation_proof_unsigned(
					&BlockId::Hash(relay_parent),
					bundle_equivocation_proof,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()));
			res.ok().map(|_res| RequestResult::SubmitBundleEquivocationProof(relay_parent));
		},
		Request::SubmitInvalidTransactionProof(invalid_transaction_proof) => {
			let api = client.runtime_api();
			let res = api
				.submit_invalid_transaction_proof_unsigned(
					&BlockId::Hash(relay_parent),
					invalid_transaction_proof,
				)
				.map_err(|e| RuntimeApiError::from(e.to_string()));
			res.ok().map(|_res| RequestResult::SubmitInvalidTransactionProof(relay_parent));
		},
		Request::ExtractBundles(extrinsics, sender) => {
			let api = client.runtime_api();
			let res = api
				.extract_bundles(&BlockId::Hash(relay_parent), extrinsics)
				.map_err(|e| RuntimeApiError::from(e.to_string()));

			let _ = sender.send(res.clone());

			res.ok().map(|_res| RequestResult::ExtractBundles(relay_parent));
		},
		Request::ExtrinsicsShufflingSeed(header, sender) => {
			let api = client.runtime_api();
			let res = api
				.extrinsics_shuffling_seed(&BlockId::Hash(relay_parent), header)
				.map_err(|e| RuntimeApiError::from(e.to_string()));

			let _ = sender.send(res.clone());

			res.ok().map(|_res| RequestResult::ExtrinsicsShufflingSeed(relay_parent));
		},
		Request::ExecutionWasmBundle(sender) => {
			let api = client.runtime_api();
			let res = api
				.execution_wasm_bundle(&BlockId::Hash(relay_parent))
				.map_err(|e| RuntimeApiError::from(e.to_string()));

			let _ = sender.send(res.clone());

			res.ok().map(|_res| RequestResult::ExecutionWasmBundle(relay_parent));
		},
	}

	None
}
