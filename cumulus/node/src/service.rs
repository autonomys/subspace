//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use cirrus_client_executor::Executor;
use cirrus_client_executor_gossip::ExecutorGossipParams;
use cirrus_primitives::SecondaryApi;
use cirrus_runtime::{opaque::Block, AccountId, Balance, Hash};
use futures::Stream;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{BlockBackend, StateBackendFor};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_network::NetworkService;
use sc_service::{
	BuildNetworkParams, Configuration, NetworkStarter, PartialComponents, Role, SpawnTasksParams,
	TFullBackend, TFullClient, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryWorkerHandle};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_executor::ExecutorApi;
use sp_offchain::OffchainWorkerApi;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_core_primitives::Sha256Hash;
use subspace_runtime_primitives::Index as Nonce;
use substrate_frame_rpc_system::AccountNonceApi;

/// Native executor instance.
pub struct CirrusRuntimeExecutor;

impl NativeExecutionDispatch for CirrusRuntimeExecutor {
	type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		cirrus_runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		cirrus_runtime::native_version()
	}
}

/// Cirrus-like full client.
pub type FullClient<RuntimeApi, ExecutorDispatch> =
	TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub type FullBackend = sc_service::TFullBackend<Block>;

pub type FullPool<RuntimeApi, ExecutorDispatch> = sc_transaction_pool::BasicPool<
	sc_transaction_pool::FullChainApi<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
	Block,
>;

/// Starts a `ServiceBuilder` for a full service.
///
/// Use this macro if you don't actually need the full service, but just the builder in order to
/// be able to perform chain operations.
#[allow(clippy::type_complexity)]
fn new_partial<RuntimeApi, Executor>(
	config: &Configuration,
) -> Result<
	PartialComponents<
		FullClient<RuntimeApi, Executor>,
		TFullBackend<Block>,
		(),
		sc_consensus::DefaultImportQueue<Block, FullClient<RuntimeApi, Executor>>,
		sc_transaction_pool::FullPool<Block, FullClient<RuntimeApi, Executor>>,
		(Option<Telemetry>, Option<TelemetryWorkerHandle>, NativeElseWasmExecutor<Executor>),
	>,
	sc_service::Error,
>
where
	RuntimeApi:
		ConstructRuntimeApi<Block, FullClient<RuntimeApi, Executor>> + Send + Sync + 'static,
	RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
		+ ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>,
	Executor: NativeExecutionDispatch + 'static,
{
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
		config.runtime_cache_size,
	);

	let (client, backend, keystore_container, task_manager) = sc_service::new_full_parts(
		config,
		telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
		executor.clone(),
	)?;
	let client = Arc::new(client);

	let telemetry_worker_handle = telemetry.as_ref().map(|(worker, _)| worker.handle());

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let import_queue = cumulus_client_consensus_relay_chain::import_queue(
		client.clone(),
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
	)?;

	let params = PartialComponents {
		backend,
		client,
		import_queue,
		keystore_container,
		task_manager,
		transaction_pool,
		select_chain: (),
		other: (telemetry, telemetry_worker_handle, executor),
	};

	Ok(params)
}

type CirrusExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch> = Executor<
	Block,
	PBlock,
	FullClient<RuntimeApi, ExecutorDispatch>,
	PClient,
	FullPool<RuntimeApi, ExecutorDispatch>,
	FullBackend,
	NativeElseWasmExecutor<ExecutorDispatch>,
>;

/// Full node along with some other components.
pub struct NewFull<C, CodeExecutor, PBlock, PClient, RuntimeApi, ExecutorDispatch>
where
	PBlock: BlockT,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
		+ Metadata<Block>
		+ BlockBuilder<Block>
		+ OffchainWorkerApi<Block>
		+ SessionKeys<Block>
		+ SecondaryApi<Block, AccountId>
		+ TaggedTransactionQueue<Block>
		+ AccountNonceApi<Block, AccountId, Nonce>
		+ TransactionPaymentRuntimeApi<Block, Balance>,
{
	/// Task manager.
	pub task_manager: TaskManager,
	/// Full client.
	pub client: C,
	/// Backend.
	pub backend: Arc<FullBackend>,
	/// Code executor.
	pub code_executor: Arc<CodeExecutor>,
	/// Network.
	pub network: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
	/// RPCHandlers to make RPC queries.
	pub rpc_handlers: sc_service::RpcHandlers,
	/// Network starter.
	pub network_starter: NetworkStarter,
	/// Executor.
	pub executor: CirrusExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
}

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
pub async fn new_full<PBlock, PClient, SC, IBNS, NSNS, RuntimeApi, ExecutorDispatch>(
	mut secondary_chain_config: Configuration,
	primary_chain_client: Arc<PClient>,
	primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
	select_chain: &SC,
	imported_block_notification_stream: IBNS,
	new_slot_notification_stream: NSNS,
) -> sc_service::error::Result<
	NewFull<
		Arc<FullClient<RuntimeApi, ExecutorDispatch>>,
		NativeElseWasmExecutor<ExecutorDispatch>,
		PBlock,
		PClient,
		RuntimeApi,
		ExecutorDispatch,
	>,
>
where
	PBlock: BlockT,
	PClient: HeaderBackend<PBlock>
		+ BlockBackend<PBlock>
		+ ProvideRuntimeApi<PBlock>
		+ Send
		+ Sync
		+ 'static,
	PClient::Api: ExecutorApi<PBlock, Hash>,
	SC: SelectChain<PBlock>,
	IBNS: Stream<Item = NumberFor<PBlock>> + Send + 'static,
	NSNS: Stream<Item = (Slot, Sha256Hash)> + Send + 'static,
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
		+ Metadata<Block>
		+ BlockBuilder<Block>
		+ OffchainWorkerApi<Block>
		+ SessionKeys<Block>
		+ SecondaryApi<Block, AccountId>
		+ TaggedTransactionQueue<Block>
		+ AccountNonceApi<Block, AccountId, Nonce>
		+ TransactionPaymentRuntimeApi<Block, Balance>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
{
	if matches!(secondary_chain_config.role, Role::Light) {
		return Err("Light client not supported!".into())
	}

	// TODO: Do we even need block announcement on secondary node?
	// secondary_chain_config.announce_block = false;

	secondary_chain_config
		.network
		.extra_sets
		.push(cirrus_client_executor_gossip::executor_gossip_peers_set_config());

	let params = new_partial(&secondary_chain_config)?;

	let (mut telemetry, _telemetry_worker_handle, code_executor) = params.other;

	let client = params.client.clone();
	let backend = params.backend.clone();

	let validator = secondary_chain_config.role.is_authority();
	let transaction_pool = params.transaction_pool.clone();
	let mut task_manager = params.task_manager;
	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(BuildNetworkParams {
			config: &secondary_chain_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue: params.import_queue,
			// TODO: we might want to re-enable this some day.
			block_announce_validator_builder: None,
			warp_sync: None,
		})?;

	let rpc_builder = {
		let client = client.clone();
		let transaction_pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, _| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: transaction_pool.clone(),
				deny_unsafe,
			};

			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
		rpc_builder,
		client: client.clone(),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		config: secondary_chain_config,
		keystore: params.keystore_container.sync_keystore(),
		backend: backend.clone(),
		network: network.clone(),
		system_rpc_tx,
		telemetry: telemetry.as_mut(),
	})?;

	let code_executor = Arc::new(code_executor);

	let spawn_essential = task_manager.spawn_essential_handle();
	let (bundle_sender, bundle_receiver) = tracing_unbounded("transaction_bundle_stream");
	let (execution_receipt_sender, execution_receipt_receiver) =
		tracing_unbounded("execution_receipt_stream");

	let executor = Executor::new(
		primary_chain_client,
		primary_network,
		&spawn_essential,
		select_chain,
		imported_block_notification_stream,
		new_slot_notification_stream,
		client.clone(),
		Box::new(task_manager.spawn_handle()),
		transaction_pool,
		Arc::new(bundle_sender),
		Arc::new(execution_receipt_sender),
		backend.clone(),
		code_executor.clone(),
		validator,
		params.keystore_container.sync_keystore(),
	)
	.await?;

	let executor_gossip =
		cirrus_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
			network: network.clone(),
			executor: executor.clone(),
			bundle_receiver,
			execution_receipt_receiver,
		});
	spawn_essential.spawn_essential_blocking("cirrus-gossip", None, Box::pin(executor_gossip));

	let new_full = NewFull {
		task_manager,
		client,
		backend,
		code_executor,
		network,
		rpc_handlers,
		network_starter,
		executor,
	};

	Ok(new_full)
}
