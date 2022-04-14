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

use cirrus_client_executor::{Executor, ExecutorSlotInfo};
use cirrus_client_executor_gossip::ExecutorGossipParams;
use futures::Stream;
use sc_client_api::{
	AuxStore, Backend as BackendT, BlockBackend, BlockchainEvents, Finalizer, UsageProvider,
};
use sc_consensus::BlockImport;
use sc_network::NetworkService;
use sc_transaction_pool_api::TransactionPool;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed, SpawnNamed};
use sp_executor::ExecutorApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;

/// Parameters given to [`start_executor`].
pub struct StartExecutorParams<
	'a,
	Block,
	Client,
	PClient,
	SE,
	SC,
	IBNS,
	NSNS,
	Spawner,
	TP,
	Backend,
	E,
> where
	Block: BlockT,
{
	pub primary_chain_client: Arc<PClient>,
	pub spawn_essential: &'a SE,
	pub select_chain: &'a SC,
	pub imported_block_notification_stream: IBNS,
	pub new_slot_notification_stream: NSNS,
	pub client: Arc<Client>,
	pub spawner: Box<Spawner>,
	pub transaction_pool: Arc<TP>,
	pub network: Arc<NetworkService<Block, Block::Hash>>,
	pub backend: Arc<Backend>,
	pub code_executor: Arc<E>,
	pub is_authority: bool,
}

/// Start an executor node.
pub async fn start_executor<
	'a,
	Block,
	PBlock,
	Client,
	PClient,
	SE,
	SC,
	IBNS,
	NSNS,
	Backend,
	Spawner,
	TP,
	E,
>(
	StartExecutorParams {
		primary_chain_client,
		spawn_essential,
		select_chain,
		imported_block_notification_stream,
		new_slot_notification_stream,
		client,
		spawner,
		transaction_pool,
		network,
		backend,
		code_executor,
		is_authority,
	}: StartExecutorParams<'a, Block, Client, PClient, SE, SC, IBNS, NSNS, Spawner, TP, Backend, E>,
) -> sc_service::error::Result<Executor<Block, PBlock, Client, TP, Backend, E>>
where
	Block: BlockT,
	PBlock: BlockT,
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
	for<'b> &'b Client: BlockImport<
		Block,
		Transaction = sp_api::TransactionFor<Client, Block>,
		Error = sp_consensus::Error,
	>,
	PClient: HeaderBackend<PBlock>
		+ BlockBackend<PBlock>
		+ ProvideRuntimeApi<PBlock>
		+ Send
		+ 'static
		+ Sync,
	PClient::Api: ExecutorApi<PBlock>,
	SE: SpawnEssentialNamed,
	SC: SelectChain<PBlock>,
	IBNS: Stream<Item = NumberFor<PBlock>> + Send + 'static,
	NSNS: Stream<Item = ExecutorSlotInfo> + Send + 'static,
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

	let executor = Executor::new(
		primary_chain_client,
		spawn_essential,
		select_chain,
		imported_block_notification_stream,
		new_slot_notification_stream,
		client,
		spawner,
		transaction_pool,
		Arc::new(bundle_sender),
		Arc::new(execution_receipt_sender),
		backend,
		code_executor,
		is_authority,
	)
	.await?;

	let executor_gossip =
		cirrus_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
			network,
			executor: executor.clone(),
			bundle_receiver,
			execution_receipt_receiver,
		});
	spawn_essential.spawn_essential_blocking("cirrus-gossip", None, Box::pin(executor_gossip));

	Ok(executor)
}
