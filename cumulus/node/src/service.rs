//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use cirrus_client_executor::{Executor, ExecutorSlotInfo};
use cirrus_client_executor_gossip::ExecutorGossipParams;
use cirrus_runtime::{opaque::Block, RuntimeApi};
use futures::{Stream, StreamExt};
use sc_client_api::{BlockBackend, StateBackendFor};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_service::{
	BuildNetworkParams, Configuration, NetworkStarter, PartialComponents, Role, SpawnTasksParams,
	TFullBackend, TFullClient, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryWorkerHandle};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_executor::ExecutorApi;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_core_primitives::Tag;

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

/// Full node along with some other components.
pub struct NewFull<C> {
	/// Task manager.
	pub task_manager: TaskManager,
	/// Full client.
	pub client: C,
	/// Network starter.
	pub network_starter: NetworkStarter,
}

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[sc_tracing::logging::prefix_logs_with("Secondarychain")]
pub async fn new_full<PBlock, PClient, SC, IBNS, NSNS>(
	mut parachain_config: Configuration,
	primary_chain_client: Arc<PClient>,
	select_chain: &SC,
	imported_block_notification_stream: IBNS,
	new_slot_notification_stream: NSNS,
) -> sc_service::error::Result<NewFull<Arc<FullClient<RuntimeApi, CirrusRuntimeExecutor>>>>
where
	PBlock: BlockT,
	PClient: HeaderBackend<PBlock>
		+ BlockBackend<PBlock>
		+ ProvideRuntimeApi<PBlock>
		+ Send
		+ 'static
		+ Sync,
	PClient::Api: ExecutorApi<PBlock>,
	SC: SelectChain<PBlock>,
	IBNS: Stream<Item = NumberFor<PBlock>> + Send + 'static,
	NSNS: Stream<Item = (Slot, Tag)> + Send + 'static,
{
	if matches!(parachain_config.role, Role::Light) {
		return Err("Light client not supported!".into())
	}

	// TODO: Do we even need block announcement on secondary node?
	// parachain_config.announce_block = false;

	parachain_config
		.network
		.extra_sets
		.push(cirrus_client_executor_gossip::executor_gossip_peers_set_config());

	let params = new_partial(&parachain_config)?;

	let (mut telemetry, _telemetry_worker_handle, code_executor) = params.other;

	let client = params.client.clone();
	let backend = params.backend.clone();

	let validator = parachain_config.role.is_authority();
	let transaction_pool = params.transaction_pool.clone();
	let mut task_manager = params.task_manager;
	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(BuildNetworkParams {
			config: &parachain_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue: params.import_queue,
			// TODO: we might want to re-enable this some day.
			block_announce_validator_builder: None,
			warp_sync: None,
		})?;

	let rpc_extensions_builder = {
		let client = client.clone();
		let transaction_pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, _| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: transaction_pool.clone(),
				deny_unsafe,
			};

			Ok(crate::rpc::create_full(deps))
		})
	};

	sc_service::spawn_tasks(SpawnTasksParams {
		rpc_extensions_builder,
		client: client.clone(),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		config: parachain_config,
		keystore: params.keystore_container.sync_keystore(),
		backend: backend.clone(),
		network: network.clone(),
		system_rpc_tx,
		telemetry: telemetry.as_mut(),
	})?;

	{
		let spawn_essential = task_manager.spawn_essential_handle();
		let (bundle_sender, bundle_receiver) = tracing_unbounded("transaction_bundle_stream");
		let (execution_receipt_sender, execution_receipt_receiver) =
			tracing_unbounded("execution_receipt_stream");

		let executor = Executor::new(
			primary_chain_client,
			&spawn_essential,
			select_chain,
			imported_block_notification_stream,
			new_slot_notification_stream.then(|(slot, global_challenge)| async move {
				ExecutorSlotInfo { slot, global_challenge }
			}),
			client.clone(),
			Box::new(task_manager.spawn_handle()),
			transaction_pool,
			Arc::new(bundle_sender),
			Arc::new(execution_receipt_sender),
			backend,
			Arc::new(code_executor),
			validator,
		)
		.await?;

		let executor_gossip =
			cirrus_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
				network,
				executor,
				bundle_receiver,
				execution_receipt_receiver,
			});
		spawn_essential.spawn_essential_blocking("cirrus-gossip", None, Box::pin(executor_gossip));
	}

	Ok(NewFull { task_manager, client, network_starter })
}
