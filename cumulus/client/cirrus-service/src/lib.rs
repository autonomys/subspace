// Copyright 2020-2021 Parity Technologies (UK) Ltd.
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

//! Cirrus service
//!
//! Provides functions for starting an executor node or a normal full node.

use cirrus_client_executor::Executor;
use sc_client_api::{
	AuxStore, Backend as BackendT, BlockBackend, BlockchainEvents, Finalizer, UsageProvider,
};
use sc_consensus::BlockImport;
use sc_network::NetworkService;
use sc_service::TaskManager;
use sc_transaction_pool_api::TransactionPool;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_runtime_primitives::opaque::Block as PBlock;

/// Parameters given to [`start_executor`].
pub struct StartExecutorParams<'a, Block: BlockT, Client, Spawner, RClient, TP, Backend, E> {
	pub client: Arc<Client>,
	pub spawner: Box<Spawner>,
	pub primary_chain_full_node: subspace_service::NewFull<Arc<RClient>>,
	pub task_manager: &'a mut TaskManager,
	pub transaction_pool: Arc<TP>,
	pub network: Arc<NetworkService<Block, Block::Hash>>,
	pub backend: Arc<Backend>,
	pub code_executor: Arc<E>,
	pub is_authority: bool,
}

/// Start an executor node.
pub async fn start_executor<'a, Block, Client, Backend, Spawner, RClient, TP, E>(
	StartExecutorParams {
		client,
		spawner,
		task_manager,
		primary_chain_full_node,
		transaction_pool,
		network,
		backend,
		code_executor,
		is_authority,
	}: StartExecutorParams<'a, Block, Client, Spawner, RClient, TP, Backend, E>,
) -> sc_service::error::Result<Executor<Block, Client, TP, Backend, E>>
where
	Block: BlockT,
	Client: Finalizer<Block, Backend>
		+ UsageProvider<Block>
		+ HeaderBackend<Block>
		+ BlockBackend<Block>
		+ BlockchainEvents<Block>
		+ ProvideRuntimeApi<Block>
		+ AuxStore
		+ Send
		+ Sync
		+ 'static,
	Client::Api: cirrus_primitives::SecondaryApi<Block, cirrus_primitives::AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	RClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + Send + Sync + 'static,
	for<'b> &'b Client: BlockImport<
		Block,
		Transaction = sp_api::TransactionFor<Client, Block>,
		Error = sp_consensus::Error,
	>,
	Spawner: SpawnNamed + Clone + Send + Sync + 'static,
	Backend: BackendT<Block> + 'static,
	<<Backend as sc_client_api::Backend<Block>>::State as sc_client_api::backend::StateBackend<
		sp_api::HashFor<Block>,
	>>::Transaction: sp_trie::HashDBT<sp_api::HashFor<Block>, sp_trie::DBValue>,
	TP: TransactionPool<Block = Block> + 'static,
	E: CodeExecutor,
{
	let (bundle_sender, bundle_receiver) = tracing_unbounded("transaction_bundle_stream");
	let (execution_receipt_sender, execution_receipt_receiver) =
		tracing_unbounded("execution_receipt_stream");

	let overseer_handle = primary_chain_full_node
		.overseer_handle
		.clone()
		.ok_or("Subspace full node did not provide an `OverseerHandle`!")?;

	let executor =
		cirrus_client_executor::start_executor(cirrus_client_executor::StartExecutorParams {
			client,
			overseer_handle,
			spawner,
			primary_chain_client: primary_chain_full_node.client.clone(),
			transaction_pool,
			bundle_sender,
			execution_receipt_sender,
			backend,
			code_executor,
			is_authority,
		})
		.await;

	let executor_gossip = cirrus_client_executor_gossip::start_gossip_worker(
		cirrus_client_executor_gossip::ExecutorGossipParams {
			network,
			executor: executor.clone(),
			bundle_receiver,
			execution_receipt_receiver,
		},
	);
	task_manager
		.spawn_essential_handle()
		.spawn_blocking("cirrus-gossip", None, executor_gossip);

	task_manager.add_child(primary_chain_full_node.task_manager);

	Ok(executor)
}
