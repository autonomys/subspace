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

#![allow(clippy::all)]

use cumulus_client_consensus_common::ParachainConsensus;

use sc_client_api::{
	AuxStore, Backend as BackendT, BlockBackend, BlockchainEvents, Finalizer, UsageProvider,
};
use sc_consensus::{
	import_queue::{ImportQueue, IncomingBlock, Link, Origin},
	BlockImport,
};
use sc_network::NetworkService;
use sc_service::{Configuration, TaskManager};
use sc_transaction_pool_api::TransactionPool;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::{
	traits::{Block as BlockT, NumberFor},
	Justifications,
};
use std::sync::Arc;

use cumulus_client_consensus_common::RelaychainClient;

/// Parameters given to [`start_executor`].
pub struct StartExecutorParams<
	'a,
	Block: BlockT,
	Client,
	Spawner,
	RClient,
	IQ,
	TP,
	Backend,
	CIDP,
	E,
> {
	pub client: Arc<Client>,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
	pub spawner: Box<Spawner>,
	pub primary_chain_full_node: subspace_service::NewFull<RClient>,
	pub task_manager: &'a mut TaskManager,
	pub parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	pub import_queue: IQ,
	pub transaction_pool: Arc<TP>,
	pub network: Arc<NetworkService<Block, Block::Hash>>,
	pub backend: Arc<Backend>,
	pub create_inherent_data_providers: Arc<CIDP>,
	pub code_executor: Arc<E>,
	pub is_authority: bool,
}

/// Start an executor node.
pub async fn start_executor<'a, Block, Client, Backend, Spawner, RClient, IQ, TP, CIDP, E>(
	StartExecutorParams {
		client,
		announce_block,
		spawner,
		task_manager,
		primary_chain_full_node,
		parachain_consensus,
		import_queue: _,
		transaction_pool,
		network,
		backend,
		create_inherent_data_providers,
		code_executor,
		is_authority,
	}: StartExecutorParams<'a, Block, Client, Spawner, RClient, IQ, TP, Backend, CIDP, E>,
) -> sc_service::error::Result<cirrus_client_executor::Executor<Block, Client, TP, Backend, CIDP, E>>
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
	RClient: RelaychainClient + Clone + Send + Sync + 'static,
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
	IQ: ImportQueue<Block> + 'static,
	TP: TransactionPool<Block = Block> + 'static,
	CIDP: CreateInherentDataProviders<Block, cirrus_primitives::Hash> + 'static,
	E: CodeExecutor,
{
	let consensus = cumulus_client_consensus_common::run_parachain_consensus(
		client.clone(),
		primary_chain_full_node.client.clone(),
		announce_block.clone(),
	);
	task_manager
		.spawn_essential_handle()
		.spawn("cumulus-consensus", None, consensus);

	let (bundle_sender, bundle_receiver) = tracing_unbounded("transaction_bundle_stream");
	let (execution_receipt_sender, execution_receipt_receiver) =
		tracing_unbounded("execution_receipt_stream");

	let overseer_handle = primary_chain_full_node
		.overseer_handle
		.clone()
		.ok_or_else(|| "Subspace full node did not provide an `OverseerHandle`!")?;

	let executor =
		cirrus_client_executor::start_executor(cirrus_client_executor::StartExecutorParams {
			client,
			announce_block,
			overseer_handle,
			spawner,
			parachain_consensus,
			transaction_pool,
			bundle_sender,
			execution_receipt_sender,
			backend,
			create_inherent_data_providers,
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

/// Parameters given to [`start_full_node`].
pub struct StartFullNodeParams<'a, Block: BlockT, Client, PClient> {
	pub client: Arc<Client>,
	pub primary_chain_full_node: subspace_service::NewFull<PClient>,
	pub task_manager: &'a mut TaskManager,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
}

// TODO: maybe remove this later.
/// Start a full node for a parachain.
///
/// A full node will only sync the given parachain and will follow the
/// tip of the chain.
pub fn start_full_node<Block, Client, Backend, PClient>(
	StartFullNodeParams {
		client,
		announce_block,
		task_manager,
		primary_chain_full_node,
	}: StartFullNodeParams<Block, Client, PClient>,
) -> sc_service::error::Result<()>
where
	Block: BlockT,
	Client: Finalizer<Block, Backend>
		+ UsageProvider<Block>
		+ Send
		+ Sync
		+ BlockBackend<Block>
		+ HeaderBackend<Block>
		+ BlockchainEvents<Block>
		+ 'static,
	for<'a> &'a Client: BlockImport<Block>,
	PClient: RelaychainClient + Clone + Send + Sync + 'static,
	Backend: BackendT<Block> + 'static,
{
	let consensus = cumulus_client_consensus_common::run_parachain_consensus(
		client.clone(),
		primary_chain_full_node.client.clone(),
		announce_block.clone(),
	);
	task_manager
		.spawn_essential_handle()
		.spawn("cumulus-consensus", None, consensus);

	task_manager.add_child(primary_chain_full_node.task_manager);

	Ok(())
}

/// Prepare the parachain's node condifugration
///
/// This function will disable the default announcement of Substrate for the parachain in favor
/// of the one of Cumulus.
pub fn prepare_node_config(mut parachain_config: Configuration) -> Configuration {
	parachain_config.announce_block = false;

	parachain_config
}

/// A shared import queue
///
/// This is basically a hack until the Substrate side is implemented properly.
#[derive(Clone)]
pub struct SharedImportQueue<Block: BlockT>(Arc<parking_lot::Mutex<dyn ImportQueue<Block>>>);

impl<Block: BlockT> SharedImportQueue<Block> {
	/// Create a new instance of the shared import queue.
	pub fn new<IQ: ImportQueue<Block> + 'static>(import_queue: IQ) -> Self {
		Self(Arc::new(parking_lot::Mutex::new(import_queue)))
	}
}

impl<Block: BlockT> ImportQueue<Block> for SharedImportQueue<Block> {
	fn import_blocks(&mut self, origin: BlockOrigin, blocks: Vec<IncomingBlock<Block>>) {
		self.0.lock().import_blocks(origin, blocks)
	}

	fn import_justifications(
		&mut self,
		who: Origin,
		hash: Block::Hash,
		number: NumberFor<Block>,
		justifications: Justifications,
	) {
		self.0.lock().import_justifications(who, hash, number, justifications)
	}

	fn poll_actions(&mut self, cx: &mut std::task::Context, link: &mut dyn Link<Block>) {
		self.0.lock().poll_actions(cx, link)
	}
}
