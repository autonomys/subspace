//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

// std
use std::sync::Arc;

// Local Runtime Types
use cirrus_runtime::{opaque::Block, AccountId, Balance, Index as Nonce, RuntimeApi};

// Substrate Imports
use cirrus_client_executor::ExecutorSlotInfo;
use cirrus_client_service::StartExecutorParams;
use futures::StreamExt;
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_service::{Configuration, PartialComponents, Role, TFullBackend, TFullClient, TaskManager};
use sc_telemetry::{Telemetry, TelemetryHandle, TelemetryWorker, TelemetryWorkerHandle};
use sc_tracing::tracing;
use sp_api::ConstructRuntimeApi;
use sp_runtime::traits::BlakeTwo256;

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

/// Starts a `ServiceBuilder` for a full service.
///
/// Use this macro if you don't actually need the full service, but just the builder in order to
/// be able to perform chain operations.
#[allow(clippy::type_complexity)]
pub fn new_partial<RuntimeApi, Executor, BIQ>(
	config: &Configuration,
	build_import_queue: BIQ,
) -> Result<
	PartialComponents<
		TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>,
		TFullBackend<Block>,
		(),
		sc_consensus::DefaultImportQueue<
			Block,
			TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>,
		>,
		sc_transaction_pool::FullPool<
			Block,
			TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>,
		>,
		(Option<Telemetry>, Option<TelemetryWorkerHandle>, NativeElseWasmExecutor<Executor>),
	>,
	sc_service::Error,
>
where
	RuntimeApi: ConstructRuntimeApi<Block, TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi: sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
		+ sp_api::Metadata<Block>
		+ sp_session::SessionKeys<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::StateBackendFor<TFullBackend<Block>, Block>,
		> + sp_offchain::OffchainWorkerApi<Block>
		+ sp_block_builder::BlockBuilder<Block>,
	sc_client_api::StateBackendFor<TFullBackend<Block>, Block>: sp_api::StateBackend<BlakeTwo256>,
	Executor: sc_executor::NativeExecutionDispatch + 'static,
	BIQ: FnOnce(
		Arc<TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>>,
		&Configuration,
		Option<TelemetryHandle>,
		&TaskManager,
	) -> Result<
		sc_consensus::DefaultImportQueue<
			Block,
			TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>,
		>,
		sc_service::Error,
	>,
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

	let executor = NativeElseWasmExecutor::<Executor>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
		config.runtime_cache_size,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
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

	let import_queue = build_import_queue(
		client.clone(),
		config,
		telemetry.as_ref().map(|telemetry| telemetry.handle()),
		&task_manager,
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

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[sc_tracing::logging::prefix_logs_with("Secondarychain")]
async fn start_node_impl<RuntimeApi, Executor, RB, BIQ>(
	mut parachain_config: Configuration,
	polkadot_config: Configuration,
	_rpc_ext_builder: RB,
	build_import_queue: BIQ,
) -> sc_service::error::Result<(
	TaskManager,
	Arc<TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>>,
)>
where
	RuntimeApi: ConstructRuntimeApi<Block, TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi: sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
		+ sp_api::Metadata<Block>
		+ sp_session::SessionKeys<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::StateBackendFor<TFullBackend<Block>, Block>,
		> + sp_offchain::OffchainWorkerApi<Block>
		+ sp_block_builder::BlockBuilder<Block>
		+ pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
		+ substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
		+ cirrus_primitives::SecondaryApi<Block, AccountId>,
	sc_client_api::StateBackendFor<TFullBackend<Block>, Block>: sp_api::StateBackend<BlakeTwo256>,
	Executor: sc_executor::NativeExecutionDispatch + 'static,
	RB: Fn(
			Arc<TFullClient<Block, RuntimeApi, Executor>>,
		) -> Result<jsonrpc_core::IoHandler<sc_rpc::Metadata>, sc_service::Error>
		+ Send
		+ 'static,
	BIQ: FnOnce(
			Arc<TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>>,
			&Configuration,
			Option<TelemetryHandle>,
			&TaskManager,
		) -> Result<
			sc_consensus::DefaultImportQueue<
				Block,
				TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>,
			>,
			sc_service::Error,
		> + 'static,
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

	let params = new_partial::<RuntimeApi, Executor, BIQ>(&parachain_config, build_import_queue)?;

	let (mut telemetry, _telemetry_worker_handle, code_executor) = params.other;

	let primary_chain_full_node = {
		let span = tracing::info_span!(sc_tracing::logging::PREFIX_LOG_SPAN, name = "Primarychain");
		let _enter = span.enter();

		subspace_service::new_full::<subspace_runtime::RuntimeApi, subspace_node::ExecutorDispatch>(
			polkadot_config,
			false,
		)
		.map_err(|_| sc_service::Error::Other("Failed to build a full subspace node".into()))?
	};

	let client = params.client.clone();
	let backend = params.backend.clone();

	let validator = parachain_config.role.is_authority();
	let transaction_pool = params.transaction_pool.clone();
	let mut task_manager = params.task_manager;
	let (network, system_rpc_tx, start_network) =
		sc_service::build_network(sc_service::BuildNetworkParams {
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

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
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

	let spawner = task_manager.spawn_handle();

	let params = StartExecutorParams {
		primary_chain_client: primary_chain_full_node.client.clone(),
		spawn_essential: &task_manager.spawn_essential_handle(),
		select_chain: &primary_chain_full_node.select_chain,
		imported_block_notification_stream: primary_chain_full_node
			.imported_block_notification_stream
			.subscribe()
			.then(|(block_number, _)| async move { block_number }),
		new_slot_notification_stream: primary_chain_full_node
			.new_slot_notification_stream
			.subscribe()
			.then(|slot_notification| async move {
				let slot_info = slot_notification.new_slot_info;
				ExecutorSlotInfo {
					slot: slot_info.slot,
					global_challenge: slot_info.global_challenge,
				}
			}),
		client: client.clone(),
		spawner: Box::new(spawner),
		transaction_pool,
		network,
		backend,
		code_executor: Arc::new(code_executor),
		is_authority: validator,
	};

	cirrus_client_service::start_executor(params).await?;

	task_manager.add_child(primary_chain_full_node.task_manager);

	start_network.start_network();

	Ok((task_manager, client))
}

/// Build the import queue for the parachain runtime.
#[allow(clippy::type_complexity)]
pub fn parachain_build_import_queue(
	client: Arc<TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<CirrusRuntimeExecutor>>>,
	_config: &Configuration,
	_telemetry: Option<TelemetryHandle>,
	task_manager: &TaskManager,
) -> Result<
	sc_consensus::DefaultImportQueue<
		Block,
		TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<CirrusRuntimeExecutor>>,
	>,
	sc_service::Error,
> {
	cumulus_client_consensus_relay_chain::import_queue(
		client,
		&task_manager.spawn_essential_handle(),
		None,
	)
	.map_err(Into::into)
}

/// Start a parachain node.
pub async fn start_parachain_node(
	parachain_config: Configuration,
	polkadot_config: Configuration,
) -> sc_service::error::Result<(
	TaskManager,
	Arc<TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<CirrusRuntimeExecutor>>>,
)> {
	start_node_impl::<RuntimeApi, CirrusRuntimeExecutor, _, _>(
		parachain_config,
		polkadot_config,
		|_| Ok(Default::default()),
		parachain_build_import_queue,
	)
	.await
}
