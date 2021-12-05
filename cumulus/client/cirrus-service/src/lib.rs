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

use cumulus_client_consensus_common::ParachainConsensus;
use cumulus_primitives_core::{CollectCollationInfo, ParaId};

use sc_client_api::{
	Backend as BackendT, BlockBackend, BlockchainEvents, Finalizer, UsageProvider,
};
use sc_consensus::{
	import_queue::{ImportQueue, IncomingBlock, Link, Origin},
	BlockImport,
};
use sc_service::{Configuration, Role, TaskManager};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_core::{traits::SpawnNamed, Pair};
use sp_runtime::{
	traits::{BlakeTwo256, Block as BlockT, NumberFor},
	Justifications,
};
use std::{marker::PhantomData, ops::Deref, sync::Arc};

pub mod genesis;

use subspace_runtime_primitives::CollatorPair;
use subspace_node::service::{self as subspace_service, FullClient};

/// The primary chain full node handle.
pub struct PrimaryFullNode<C> {
	/// The relay chain full node handles.
	pub primary_chain_full_node: subspace_service::NewFull<C>,
	/// The collator key used by the node.
	pub collator_key: CollatorPair,
}

impl<C> Deref for PrimaryFullNode<C> {
	type Target = subspace_service::NewFull<C>;

	fn deref(&self) -> &Self::Target {
		&self.primary_chain_full_node
	}
}

/// Parameters given to [`start_executor`].
pub struct StartExecutorParams<'a, Block: BlockT, BS, Client, Spawner, RClient, IQ> {
	pub block_status: Arc<BS>,
	pub client: Arc<Client>,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
	pub spawner: Spawner,
	pub primary_chain_full_node: PrimaryFullNode<RClient>,
	pub task_manager: &'a mut TaskManager,
	pub parachain_consensus: Box<dyn ParachainConsensus<Block>>,
	pub import_queue: IQ,
}

/// Start an executor node.
pub async fn start_executor<'a, Block, BS, Client, Backend, Spawner, RClient, IQ>(
	StartExecutorParams {
		block_status,
		client,
		announce_block,
		spawner,
		task_manager,
		primary_chain_full_node,
		parachain_consensus,
		import_queue,
	}: StartExecutorParams<'a, Block, BS, Client, Spawner, RClient, IQ>,
) -> sc_service::error::Result<()>
where
	Block: BlockT,
	BS: BlockBackend<Block> + Send + Sync + 'static,
	Client: Finalizer<Block, Backend>
		+ UsageProvider<Block>
		+ HeaderBackend<Block>
		+ Send
		+ Sync
		+ BlockBackend<Block>
		+ BlockchainEvents<Block>
		+ ProvideRuntimeApi<Block>
		+ 'static,
	Client::Api: CollectCollationInfo<Block>,
	RClient: Clone + cumulus_client_consensus_common::RelaychainClient + Send + Sync + 'static,
	for<'b> &'b Client: BlockImport<Block>,
	Spawner: SpawnNamed + Clone + Send + Sync + 'static,
	Backend: BackendT<Block> + 'static,
	IQ: ImportQueue<Block> + 'static,
{
	// FIXME: This should be used to start the parachain consensus, but we can skip it for now?
	/*
	primary_chain_full_node.client.execute_with(StartConsensus {
		para_id,
		announce_block: announce_block.clone(),
		client: client.clone(),
		task_manager,
		_phantom: PhantomData,
	});
	*/

	let para_id = 2000.into();
	let consensus = cumulus_client_consensus_common::run_parachain_consensus(
		para_id,
		client.clone(),
		primary_chain_full_node.client.clone(),
		announce_block.clone(),
	);
	task_manager
		.spawn_essential_handle()
		.spawn("cumulus-consensus", None, consensus);

	cirrus_client_executor::start_executor(cirrus_client_executor::StartExecutorParams {
		runtime_api: client.clone(),
		client,
		block_status,
		announce_block,
		overseer_handle: primary_chain_full_node
			.overseer_handle
			.clone()
			.ok_or_else(|| "Subspace full node did not provide an `OverseerHandle`!")?,
		spawner,
		// para_id,
		key: primary_chain_full_node.collator_key.clone(),
		parachain_consensus,
	})
	.await;

	task_manager.add_child(primary_chain_full_node.primary_chain_full_node.task_manager);

	Ok(())
}

/// Parameters given to [`start_full_node`].
pub struct StartFullNodeParams<'a, Block: BlockT, Client, PClient> {
	pub para_id: ParaId,
	pub client: Arc<Client>,
	pub primary_chain_full_node: PrimaryFullNode<PClient>,
	pub task_manager: &'a mut TaskManager,
	pub announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
}

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
		para_id,
	}: StartFullNodeParams<Block, Client, PClient>,
) -> sc_service::error::Result<()>
where
	Block: BlockT,
	Client: Finalizer<Block, Backend>
		+ UsageProvider<Block>
		+ Send
		+ Sync
		+ BlockBackend<Block>
		+ BlockchainEvents<Block>
		+ 'static,
	for<'a> &'a Client: BlockImport<Block>,
	Backend: BackendT<Block> + 'static,
{
	todo!("Impl `start_full_node`");
	/*
	primary_chain_full_node.client.execute_with(StartConsensus {
		announce_block,
		para_id,
		client,
		task_manager,
		_phantom: PhantomData,
	});

	task_manager.add_child(primary_chain_full_node.primary_chain_full_node.task_manager);

	Ok(())
	*/
}

/// Prepare the parachain's node condifugration
///
/// This function will disable the default announcement of Substrate for the parachain in favor
/// of the one of Cumulus.
pub fn prepare_node_config(mut parachain_config: Configuration) -> Configuration {
	parachain_config.announce_block = false;

	parachain_config
}

/// Build the Subspace full node using the given `config`.
#[sc_tracing::logging::prefix_logs_with("Primarychain")]
pub fn build_subspace_full_node(
	config: Configuration,
) -> Result<PrimaryFullNode<Arc<FullClient>>, sc_service::Error> {
	let is_light = matches!(config.role, Role::Light);
	if is_light {
		Err(sc_service::Error::Other("Light client not supported.".into()))
	} else {
		let collator_key = CollatorPair::generate().0;
		let primary_chain_full_node = subspace_service::new_full(
			config,
			subspace_service::IsCollator::Yes(collator_key.clone()),
		)
		.map_err(|_| sc_service::Error::Other("Failed to build a full subspace node".into()))?;
		Ok(PrimaryFullNode { primary_chain_full_node, collator_key })
	}
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
