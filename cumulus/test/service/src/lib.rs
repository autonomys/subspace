// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Crate used for testing with Cirrus.

#![warn(missing_docs)]

pub mod chain_spec;

use std::{future::Future, sync::Arc};

use sc_basic_authorship::ProposerFactory;
use sc_client_api::execution_extensions::ExecutionStrategies;
use sc_network::{config::TransportConfig, multiaddr, NetworkService};
use sc_service::{
	config::{
		DatabaseSource, KeepBlocks, KeystoreConfig, MultiaddrWithPeerId, NetworkConfiguration,
		OffchainWorkerConfig, PruningMode, WasmExecutionMethod,
	},
	BasePath, ChainSpec, Configuration, Error as ServiceError, PartialComponents, Role,
	RpcHandlers, TFullBackend, TFullClient, TaskManager,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_core::{Pair, H256};
use sp_keyring::Sr25519Keyring;
use sp_runtime::{codec::Encode, generic, traits::BlakeTwo256, OpaqueExtrinsic};
use sp_trie::PrefixedMemoryDB;
use substrate_test_client::{
	BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};

use cirrus_client_service::{start_executor, StartExecutorParams};
use cirrus_node_primitives::CollatorPair;
use cirrus_test_runtime::{opaque::Block, Hash, RuntimeApi};
use cumulus_client_consensus_relay_chain::PrimaryChainConsensus;

pub use cirrus_test_runtime as runtime;
pub use sp_keyring::Sr25519Keyring as Keyring;

/// The signature of the announce block fn.
pub type WrapAnnounceBlockFn = Arc<dyn Fn(Hash, Option<Vec<u8>>) + Send + Sync>;

/// The backend type used by the test service.
pub type Backend = TFullBackend<Block>;

/// Code executor for the test service.
pub type CodeExecutor = sc_executor::NativeElseWasmExecutor<RuntimeExecutor>;

/// Secondary executor for the test service.
pub type Executor = cirrus_client_executor::Executor<
	Block,
	Client,
	sc_transaction_pool::BasicPool<sc_transaction_pool::FullChainApi<Client, Block>, Block>,
	Backend,
	Box<dyn sp_inherents::CreateInherentDataProviders<Block, Hash, InherentDataProviders = ()>>,
	CodeExecutor,
>;

/// Native executor instance.
pub struct RuntimeExecutor;

impl sc_executor::NativeExecutionDispatch for RuntimeExecutor {
	type ExtendHostFunctions = ();

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		cirrus_test_runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		cirrus_test_runtime::native_version()
	}
}

/// The client type being used by the test service.
pub type Client =
	TFullClient<Block, runtime::RuntimeApi, sc_executor::NativeElseWasmExecutor<RuntimeExecutor>>;

/// Starts a `ServiceBuilder` for a full service.
///
/// Use this macro if you don't actually need the full service, but just the builder in order to
/// be able to perform chain operations.
#[allow(clippy::type_complexity)]
pub fn new_partial(
	config: &mut Configuration,
) -> Result<
	PartialComponents<
		Client,
		TFullBackend<Block>,
		(),
		sc_consensus::import_queue::BasicQueue<Block, PrefixedMemoryDB<BlakeTwo256>>,
		sc_transaction_pool::FullPool<Block, Client>,
		CodeExecutor,
	>,
	sc_service::Error,
> {
	let executor = sc_executor::NativeElseWasmExecutor::<RuntimeExecutor>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
		config.runtime_cache_size,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(config, None, executor.clone())?;
	let client = Arc::new(client);

	let registry = config.prometheus_registry();

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let import_queue = cumulus_client_consensus_relay_chain::import_queue(
		client.clone(),
		client.clone(),
		|_relay_parent, _validation_data| async { Ok(()) },
		&task_manager.spawn_essential_handle(),
		registry,
	)?;

	let params = PartialComponents {
		backend,
		client,
		import_queue,
		keystore_container,
		task_manager,
		transaction_pool,
		select_chain: (),
		other: (executor),
	};

	Ok(params)
}

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[sc_tracing::logging::prefix_logs_with(parachain_config.network.node_name.as_str())]
async fn start_node_impl<RB>(
	mut parachain_config: Configuration,
	_collator_key: Option<CollatorPair>,
	relay_chain_config: Configuration,
	wrap_announce_block: Option<Box<dyn FnOnce(WrapAnnounceBlockFn) -> WrapAnnounceBlockFn>>,
	rpc_ext_builder: RB,
) -> sc_service::error::Result<(
	TaskManager,
	Arc<Client>,
	Arc<Backend>,
	Arc<CodeExecutor>,
	Arc<NetworkService<Block, H256>>,
	RpcHandlers,
	Executor,
)>
where
	RB: Fn(Arc<Client>) -> Result<jsonrpc_core::IoHandler<sc_rpc::Metadata>, sc_service::Error>
		+ Send
		+ 'static,
{
	if matches!(parachain_config.role, Role::Light) {
		return Err("Light client not supported!".into())
	}

	// Disable the default announcement of Substrate in favor of the one of Cumulus.
	parachain_config.announce_block = false;

	let params = new_partial(&mut parachain_config)?;

	let validator = parachain_config.role.is_authority();
	let prometheus_registry = parachain_config.prometheus_registry().cloned();
	let transaction_pool = params.transaction_pool.clone();
	let mut task_manager = params.task_manager;

	let primary_chain_full_node = {
		let span = tracing::info_span!(
			sc_tracing::logging::PREFIX_LOG_SPAN,
			name = relay_chain_config.network.node_name.as_str()
		);
		let _enter = span.enter();

		subspace_service::new_full::<
			subspace_test_runtime::RuntimeApi,
			subspace_test_client::TestExecutorDispatch,
		>(relay_chain_config, false)
		.await
		.map_err(|_| sc_service::Error::Other("Failed to build a full subspace node".into()))?
	};

	let client = params.client.clone();
	let backend = params.backend.clone();

	let (network, system_rpc_tx, start_network) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &parachain_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue: params.import_queue,
			block_announce_validator_builder: None,
			warp_sync: None,
		})?;

	let rpc_extensions_builder = {
		let client = client.clone();

		Box::new(move |_, _| rpc_ext_builder(client.clone()))
	};

	let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		rpc_extensions_builder,
		client: client.clone(),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		config: parachain_config,
		keystore: params.keystore_container.sync_keystore(),
		backend: backend.clone(),
		network: network.clone(),
		system_rpc_tx,
		telemetry: None,
	})?;

	let announce_block = {
		let network = network.clone();
		Arc::new(move |hash, data| network.announce_block(hash, data))
	};

	let announce_block = wrap_announce_block
		.map(|w| (w)(announce_block.clone()))
		.unwrap_or_else(|| announce_block);

	let parachain_consensus = {
		let proposer_factory = ProposerFactory::with_proof_recording(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			None,
		);

		Box::new(PrimaryChainConsensus::new(
			proposer_factory,
			move |_, (_relay_parent, _validation_data)| async move { Ok(()) },
			client.clone(),
			primary_chain_full_node.client.clone(),
			primary_chain_full_node.backend.clone(),
		))
	};

	let code_executor = Arc::new(params.other);
	let params = StartExecutorParams {
		announce_block,
		client: client.clone(),
		spawner: Box::new(task_manager.spawn_handle()),
		task_manager: &mut task_manager,
		primary_chain_full_node,
		parachain_consensus,
		transaction_pool,
		network: network.clone(),
		backend: backend.clone(),
		create_inherent_data_providers: Arc::new(Box::new(
			move |_, _relay_parent| async move { Ok(()) },
		)
			as Box<
				dyn sp_inherents::CreateInherentDataProviders<
					Block,
					Hash,
					InherentDataProviders = (),
				>,
			>),
		code_executor: code_executor.clone(),
		is_authority: validator,
	};

	let executor = start_executor(params).await?;

	start_network.start_network();

	Ok((task_manager, client, backend, code_executor, network, rpc_handlers, executor))
}

/// A Cumulus test node instance used for testing.
pub struct TestNode {
	/// TaskManager's instance.
	pub task_manager: TaskManager,
	/// Client's instance.
	pub client: Arc<Client>,
	/// Client backend.
	pub backend: Arc<Backend>,
	/// Code executor.
	pub code_executor: Arc<CodeExecutor>,
	/// Node's network.
	pub network: Arc<NetworkService<Block, H256>>,
	/// The `MultiaddrWithPeerId` to this node. This is useful if you want to pass it as "boot node"
	/// to other nodes.
	pub addr: MultiaddrWithPeerId,
	/// RPCHandlers to make RPC queries.
	pub rpc_handlers: RpcHandlers,
	/// Secondary executor.
	pub executor: Executor,
}

/// A builder to create a [`TestNode`].
pub struct TestNodeBuilder {
	tokio_handle: tokio::runtime::Handle,
	key: Sr25519Keyring,
	collator_key: Option<CollatorPair>,
	parachain_nodes: Vec<MultiaddrWithPeerId>,
	parachain_nodes_exclusive: bool,
	relay_chain_nodes: Vec<MultiaddrWithPeerId>,
	wrap_announce_block: Option<Box<dyn FnOnce(WrapAnnounceBlockFn) -> WrapAnnounceBlockFn>>,
	storage_update_func_parachain: Option<Box<dyn Fn()>>,
	storage_update_func_relay_chain: Option<Box<dyn Fn()>>,
}

impl TestNodeBuilder {
	/// Create a new instance of `Self`.
	///
	/// `para_id` - The parachain id this node is running for.
	/// `tokio_handle` - The tokio handler to use.
	/// `key` - The key that will be used to generate the name and that will be passed as `dev_seed`.
	pub fn new(tokio_handle: tokio::runtime::Handle, key: Sr25519Keyring) -> Self {
		TestNodeBuilder {
			key,
			tokio_handle,
			collator_key: None,
			parachain_nodes: Vec::new(),
			parachain_nodes_exclusive: false,
			relay_chain_nodes: Vec::new(),
			wrap_announce_block: None,
			storage_update_func_parachain: None,
			storage_update_func_relay_chain: None,
		}
	}

	/// Enable collator for this node.
	pub fn enable_collator(mut self) -> Self {
		let collator_key = CollatorPair::generate().0;
		self.collator_key = Some(collator_key);
		self
	}

	/// Instruct the node to exclusively connect to registered parachain nodes.
	///
	/// Parachain nodes can be registered using [`Self::connect_to_parachain_node`] and
	/// [`Self::connect_to_parachain_nodes`].
	pub fn exclusively_connect_to_registered_parachain_nodes(mut self) -> Self {
		self.parachain_nodes_exclusive = true;
		self
	}

	/// Make the node connect to the given parachain node.
	///
	/// By default the node will not be connected to any node or will be able to discover any other
	/// node.
	pub fn connect_to_parachain_node(mut self, node: &TestNode) -> Self {
		self.parachain_nodes.push(node.addr.clone());
		self
	}

	/// Make the node connect to the given parachain nodes.
	///
	/// By default the node will not be connected to any node or will be able to discover any other
	/// node.
	pub fn connect_to_parachain_nodes<'a>(
		mut self,
		nodes: impl Iterator<Item = &'a TestNode>,
	) -> Self {
		self.parachain_nodes.extend(nodes.map(|n| n.addr.clone()));
		self
	}

	/// Make the node connect to the given relay chain node.
	///
	/// By default the node will not be connected to any node or will be able to discover any other
	/// node.
	pub fn connect_to_relay_chain_node(
		mut self,
		node: &subspace_test_service::SubspaceTestNode,
	) -> Self {
		self.relay_chain_nodes.push(node.addr.clone());
		self
	}

	/// Make the node connect to the given relay chain nodes.
	///
	/// By default the node will not be connected to any node or will be able to discover any other
	/// node.
	pub fn connect_to_relay_chain_nodes<'a>(
		mut self,
		nodes: impl IntoIterator<Item = &'a subspace_test_service::SubspaceTestNode>,
	) -> Self {
		self.relay_chain_nodes.extend(nodes.into_iter().map(|n| n.addr.clone()));
		self
	}

	/// Wrap the announce block function of this node.
	pub fn wrap_announce_block(
		mut self,
		wrap: impl FnOnce(WrapAnnounceBlockFn) -> WrapAnnounceBlockFn + 'static,
	) -> Self {
		self.wrap_announce_block = Some(Box::new(wrap));
		self
	}

	/// Allows accessing the parachain storage before the test node is built.
	pub fn update_storage_parachain(mut self, updater: impl Fn() + 'static) -> Self {
		self.storage_update_func_parachain = Some(Box::new(updater));
		self
	}

	/// Allows accessing the relay chain storage before the test node is built.
	pub fn update_storage_relay_chain(mut self, updater: impl Fn() + 'static) -> Self {
		self.storage_update_func_relay_chain = Some(Box::new(updater));
		self
	}

	/// Build the [`TestNode`].
	pub async fn build(self) -> TestNode {
		let parachain_config = node_config(
			self.tokio_handle.clone(),
			self.key,
			self.parachain_nodes,
			self.parachain_nodes_exclusive,
			self.collator_key.is_some(),
		)
		.expect("could not generate Configuration");

		let mut relay_chain_config = subspace_test_service::node_config(
			self.tokio_handle,
			self.key,
			self.relay_chain_nodes,
			true,
		);

		relay_chain_config.network.node_name =
			format!("{} (primary chain)", relay_chain_config.network.node_name);

		let multiaddr = parachain_config.network.listen_addresses[0].clone();
		let (task_manager, client, backend, code_executor, network, rpc_handlers, executor) =
			start_node_impl(
				parachain_config,
				self.collator_key,
				relay_chain_config,
				self.wrap_announce_block,
				|_| Ok(Default::default()),
			)
			.await
			.expect("could not create Cumulus test service");

		let peer_id = *network.local_peer_id();
		let addr = MultiaddrWithPeerId { multiaddr, peer_id };

		TestNode {
			task_manager,
			client,
			backend,
			code_executor,
			network,
			addr,
			rpc_handlers,
			executor,
		}
	}
}

/// Create a Cumulus `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide nodes if you want the
/// node to be connected to other nodes. If `nodes_exclusive` is `true`, the node will only connect
/// to the given `nodes` and not to any other node. The `storage_update_func` can be used to make
/// adjustments to the runtime genesis.
pub fn node_config(
	tokio_handle: tokio::runtime::Handle,
	key: Sr25519Keyring,
	nodes: Vec<MultiaddrWithPeerId>,
	nodes_exlusive: bool,
	is_collator: bool,
) -> Result<Configuration, ServiceError> {
	let base_path = BasePath::new_temp_dir()?;
	let root = base_path.path().to_path_buf();
	let role = if is_collator { Role::Authority } else { Role::Full };
	let key_seed = key.to_seed();

	let mut spec = Box::new(chain_spec::get_chain_spec());

	let storage = spec.as_storage_builder().build_storage().expect("could not build storage");
	// BasicExternalities::execute_with_storage(&mut storage, storage_update_func);
	spec.set_storage(storage);

	let mut network_config = NetworkConfiguration::new(
		format!("{} (parachain)", key_seed),
		"network/test/0.1",
		Default::default(),
		None,
	);

	if nodes_exlusive {
		network_config.default_peers_set.reserved_nodes = nodes;
		network_config.default_peers_set.non_reserved_mode =
			sc_network::config::NonReservedPeerMode::Deny;
	} else {
		network_config.boot_nodes = nodes;
	}

	network_config.allow_non_globals_in_dht = true;

	network_config
		.listen_addresses
		.push(multiaddr::Protocol::Memory(rand::random()).into());

	network_config.transport = TransportConfig::MemoryOnly;

	Ok(Configuration {
		impl_name: "cirrus-test-node".to_string(),
		impl_version: "0.1".to_string(),
		role,
		tokio_handle,
		transaction_pool: Default::default(),
		network: network_config,
		keystore: KeystoreConfig::InMemory,
		keystore_remote: Default::default(),
		database: DatabaseSource::RocksDb { path: root.join("db"), cache_size: 128 },
		state_cache_size: 67108864,
		state_cache_child_ratio: None,
		state_pruning: PruningMode::ArchiveAll,
		keep_blocks: KeepBlocks::All,
		chain_spec: spec,
		wasm_method: WasmExecutionMethod::Interpreted,
		// NOTE: we enforce the use of the native runtime to make the errors more debuggable
		execution_strategies: ExecutionStrategies {
			syncing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
			importing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
			block_construction: sc_client_api::ExecutionStrategy::NativeWhenPossible,
			offchain_worker: sc_client_api::ExecutionStrategy::NativeWhenPossible,
			other: sc_client_api::ExecutionStrategy::NativeWhenPossible,
		},
		rpc_http: None,
		rpc_ws: None,
		rpc_ipc: None,
		rpc_ws_max_connections: None,
		rpc_cors: None,
		rpc_methods: Default::default(),
		rpc_max_payload: None,
		ws_max_out_buffer_capacity: None,
		prometheus_config: None,
		telemetry_endpoints: None,
		default_heap_pages: None,
		offchain_worker: OffchainWorkerConfig { enabled: true, indexing_enabled: false },
		force_authoring: false,
		disable_grandpa: false,
		dev_key_seed: Some(key_seed),
		tracing_targets: None,
		tracing_receiver: Default::default(),
		max_runtime_instances: 8,
		announce_block: true,
		base_path: Some(base_path),
		informant_output_format: Default::default(),
		wasm_runtime_overrides: None,
		runtime_cache_size: 2,
	})
}

impl TestNode {
	/// Wait for `count` blocks to be imported in the node and then exit. This function will not
	/// return if no blocks are ever created, thus you should restrict the maximum amount of time of
	/// the test execution.
	pub fn wait_for_blocks(&self, count: usize) -> impl Future<Output = ()> {
		self.client.wait_for_blocks(count)
	}

	/// Construct and send an extrinsic to this node.
	pub async fn construct_and_send_extrinsic(
		&self,
		function: impl Into<runtime::Call>,
		caller: Sr25519Keyring,
		immortal: bool,
		nonce: u32,
	) -> Result<RpcTransactionOutput, RpcTransactionError> {
		let extrinsic = construct_extrinsic(&*self.client, function, caller, immortal, nonce);

		self.rpc_handlers.send_transaction(extrinsic.into()).await
	}

	/// Send an extrinsic to this node.
	pub async fn send_extrinsic(
		&self,
		extrinsic: impl Into<OpaqueExtrinsic>,
	) -> Result<RpcTransactionOutput, RpcTransactionError> {
		self.rpc_handlers.send_transaction(extrinsic.into()).await
	}
}

/// Construct an extrinsic that can be applied to the test runtime.
pub fn construct_extrinsic(
	client: &Client,
	function: impl Into<runtime::Call>,
	caller: Sr25519Keyring,
	immortal: bool,
	nonce: u32,
) -> runtime::UncheckedExtrinsic {
	let function = function.into();
	let current_block_hash = client.info().best_hash;
	let current_block = client.info().best_number.saturated_into();
	let genesis_block = client.hash(0).unwrap().unwrap();
	let period = runtime::BlockHashCount::get()
		.checked_next_power_of_two()
		.map(|c| c / 2)
		.unwrap_or(2) as u64;
	let tip = 0;
	let extra: runtime::SignedExtra = (
		frame_system::CheckNonZeroSender::<runtime::Runtime>::new(),
		frame_system::CheckSpecVersion::<runtime::Runtime>::new(),
		frame_system::CheckTxVersion::<runtime::Runtime>::new(),
		frame_system::CheckGenesis::<runtime::Runtime>::new(),
		frame_system::CheckEra::<runtime::Runtime>::from(if immortal {
			generic::Era::Immortal
		} else {
			generic::Era::mortal(period, current_block)
		}),
		frame_system::CheckNonce::<runtime::Runtime>::from(nonce),
		frame_system::CheckWeight::<runtime::Runtime>::new(),
		pallet_transaction_payment::ChargeTransactionPayment::<runtime::Runtime>::from(tip),
	);
	let raw_payload = runtime::SignedPayload::from_raw(
		function.clone(),
		extra.clone(),
		(
			(),
			runtime::VERSION.spec_version,
			runtime::VERSION.transaction_version,
			genesis_block,
			current_block_hash,
			(),
			(),
			(),
		),
	);
	let signature = raw_payload.using_encoded(|e| caller.sign(e));
	runtime::UncheckedExtrinsic::new_signed(
		function,
		subspace_test_runtime::Address::Id(caller.public().into()),
		runtime::Signature::Sr25519(signature),
		extra,
	)
}

/// Run a primary-chain validator node.
///
/// This is essentially a wrapper around
/// [`run_validator_node`](polkadot_test_service::run_validator_node).
pub fn run_primary_chain_validator_node(
	tokio_handle: tokio::runtime::Handle,
	key: Sr25519Keyring,
	boot_nodes: Vec<MultiaddrWithPeerId>,
	is_validator: bool,
) -> subspace_test_service::SubspaceTestNode {
	subspace_test_service::run_validator_node(tokio_handle, key, boot_nodes, is_validator)
}
