use crate::system_domain_tx_pre_validator::SystemDomainTxPreValidator;
use crate::{DomainConfiguration, FullBackend, FullClient};
use cross_domain_message_gossip::DomainTxPoolSink;
use domain_client_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_client_executor::{
    EssentialExecutorParams, ExecutorStreams, SystemDomainParentChain, SystemExecutor,
};
use domain_client_executor_gossip::ExecutorGossipParams;
use domain_client_message_relayer::GossipMessageSink;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi, Hash};
use futures::channel::mpsc;
use futures::Stream;
use jsonrpsee::tracing;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{BlockBackend, BlockImportNotification, BlockchainEvents, StateBackendFor};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_rpc_api::DenyUnsafe;
use sc_service::{
    BuildNetworkParams, Configuration as ServiceConfiguration, NetworkStarter, PartialComponents,
    SpawnTasksParams, TFullBackend, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryWorkerHandle};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::transaction::PreValidationObjectApi;
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_session::SessionKeys;
use sp_settlement::SettlementApi;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::Index as Nonce;
use substrate_frame_rpc_system::AccountNonceApi;
use system_runtime_primitives::SystemDomainApi;

type SystemDomainExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch> = SystemExecutor<
    Block,
    PBlock,
    FullClient<Block, RuntimeApi, ExecutorDispatch>,
    PClient,
    FullPool<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
    FullBackend<Block>,
    NativeElseWasmExecutor<ExecutorDispatch>,
>;

type SystemGossipMessageValidator<PBlock, PClient, RuntimeApi, ExecutorDispatch> =
    domain_client_executor::SystemGossipMessageValidator<
        Block,
        PBlock,
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
        PClient,
        FullPool<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
        FullBackend<Block>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        SystemDomainParentChain<Block, PBlock, PClient>,
    >;

/// System domain full node along with some other components.
pub struct NewFullSystem<C, CodeExecutor, PBlock, PClient, RuntimeApi, ExecutorDispatch>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    PBlock::Hash: From<Hash>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Hash> + SettlementApi<PBlock, Hash>,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, <Block as BlockT>::Hash>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, AccountId, NumberFor<Block>>
        + SettlementApi<Block, Hash>
        + PreValidationObjectApi<Block, Hash>,
{
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: C,
    /// Backend.
    pub backend: Arc<FullBackend<Block>>,
    /// Code executor.
    pub code_executor: Arc<CodeExecutor>,
    /// Network service.
    pub network_service: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Executor.
    pub executor: SystemDomainExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
    pub gossip_message_validator:
        SystemGossipMessageValidator<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
    /// Transaction pool sink
    pub tx_pool_sink: DomainTxPoolSink,
}

pub type FullPool<PBlock, PClient, RuntimeApi, Executor> = subspace_transaction_pool::FullPool<
    Block,
    FullClient<Block, RuntimeApi, Executor>,
    SystemDomainTxPreValidator<
        Block,
        PBlock,
        FullClient<Block, RuntimeApi, Executor>,
        PClient,
        RuntimeApiFull<FullClient<Block, RuntimeApi, Executor>>,
    >,
>;

/// Constructs a partial system domain node.
#[allow(clippy::type_complexity)]
fn new_partial<RuntimeApi, ExecutionDispatch, PBlock, PClient>(
    config: &ServiceConfiguration,
    primary_chain_client: Arc<PClient>,
) -> Result<
    PartialComponents<
        FullClient<Block, RuntimeApi, ExecutionDispatch>,
        FullBackend<Block>,
        (),
        sc_consensus::DefaultImportQueue<Block, FullClient<Block, RuntimeApi, ExecutionDispatch>>,
        FullPool<PBlock, PClient, RuntimeApi, ExecutionDispatch>,
        (
            Option<Telemetry>,
            Option<TelemetryWorkerHandle>,
            NativeElseWasmExecutor<ExecutionDispatch>,
            Arc<FullClient<Block, RuntimeApi, ExecutionDispatch>>,
        ),
    >,
    sc_service::Error,
>
where
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    PBlock::Hash: From<Hash>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Hash> + SettlementApi<PBlock, Hash>,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutionDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, <Block as BlockT>::Hash>
        + MessengerApi<Block, NumberFor<Block>>
        + ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + SettlementApi<Block, Hash>
        + PreValidationObjectApi<Block, Hash>,
    ExecutionDispatch: NativeExecutionDispatch + 'static,
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

    let executor = sc_service::new_native_or_wasm_executor(config);

    let (client, backend, keystore_container, task_manager) = sc_service::new_full_parts(
        config,
        telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        executor.clone(),
    )?;
    let client = Arc::new(client);

    let telemetry_worker_handle = telemetry.as_ref().map(|(worker, _)| worker.handle());

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let system_domain_tx_pre_validator = SystemDomainTxPreValidator::new(
        client.clone(),
        Box::new(task_manager.spawn_handle()),
        primary_chain_client,
        RuntimeApiFull::new(client.clone()),
    );

    let transaction_pool = subspace_transaction_pool::new_full(
        config,
        &task_manager,
        client.clone(),
        system_domain_tx_pre_validator,
    );

    let block_import = client.clone();
    let import_queue = domain_client_consensus_relay_chain::import_queue(
        block_import.clone(),
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
        other: (telemetry, telemetry_worker_handle, executor, block_import),
    };

    Ok(params)
}

/// Start a node with the given system domain `Configuration` and consensus chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
pub async fn new_full_system<PBlock, PClient, SC, IBNS, CIBNS, NSNS, RuntimeApi, ExecutorDispatch>(
    system_domain_config: DomainConfiguration<AccountId>,
    primary_chain_client: Arc<PClient>,
    primary_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    select_chain: &SC,
    executor_streams: ExecutorStreams<PBlock, IBNS, CIBNS, NSNS>,
    gossip_message_sink: GossipMessageSink,
) -> sc_service::error::Result<
    NewFullSystem<
        Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        PBlock,
        PClient,
        RuntimeApi,
        ExecutorDispatch,
    >,
>
where
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>> + Into<u32>,
    <Block as BlockT>::Hash: From<Hash>,
    PBlock::Hash: From<Hash>,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + BlockchainEvents<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Hash> + SettlementApi<PBlock, Hash>,
    SC: SelectChain<PBlock>,
    IBNS: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<PBlock>> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> + Send + 'static,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + DomainCoreApi<Block>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, <Block as BlockT>::Hash>
        + MessengerApi<Block, NumberFor<Block>>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, AccountId, NumberFor<Block>>
        + SettlementApi<Block, Hash>
        + PreValidationObjectApi<Block, Hash>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    // TODO: Do we even need block announcement on system domain node?
    // system_domain_config.announce_block = false;

    let params = new_partial(
        &system_domain_config.service_config,
        primary_chain_client.clone(),
    )?;

    let (mut telemetry, _telemetry_worker_handle, code_executor, block_import) = params.other;

    let client = params.client.clone();
    let backend = params.backend.clone();

    let transaction_pool = params.transaction_pool.clone();
    let mut task_manager = params.task_manager;
    let mut net_config = sc_network::config::FullNetworkConfiguration::new(
        &system_domain_config.service_config.network,
    );

    net_config.add_notification_protocol(
        domain_client_executor_gossip::executor_gossip_peers_set_config(),
    );

    let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        crate::build_network(BuildNetworkParams {
            config: &system_domain_config.service_config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue: params.import_queue,
            // TODO: we might want to re-enable this some day.
            block_announce_validator_builder: None,
            warp_sync_params: None,
            block_relay: None,
        })?;

    let is_authority = system_domain_config.service_config.role.is_authority();
    let rpc_builder = {
        let deps = crate::rpc::FullDeps {
            client: client.clone(),
            pool: transaction_pool.clone(),
            graph: transaction_pool.pool().clone(),
            chain_spec: system_domain_config.service_config.chain_spec.cloned_box(),
            deny_unsafe: DenyUnsafe::Yes,
            network: network_service.clone(),
            sync: sync_service.clone(),
            is_authority,
            prometheus_registry: system_domain_config
                .service_config
                .prometheus_registry()
                .cloned(),
            database_source: system_domain_config.service_config.database.clone(),
            task_spawner: task_manager.spawn_handle(),
            backend: backend.clone(),
        };

        Box::new(move |_, _| crate::rpc::create_full(deps.clone()).map_err(Into::into))
    };

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool: transaction_pool.clone(),
        task_manager: &mut task_manager,
        config: system_domain_config.service_config,
        keystore: params.keystore_container.keystore(),
        backend: backend.clone(),
        network: network_service.clone(),
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        telemetry: telemetry.as_mut(),
    })?;

    let code_executor = Arc::new(code_executor);

    let spawn_essential = task_manager.spawn_essential_handle();
    let (bundle_sender, bundle_receiver) = tracing_unbounded("system_domain_bundle_stream", 100);

    let domain_confirmation_depth = primary_chain_client
        .runtime_api()
        .receipts_pruning_depth(primary_chain_client.info().best_hash)
        .map_err(|err| sc_service::error::Error::Application(Box::new(err)))?
        .into();

    let executor = SystemExecutor::new(
        Box::new(task_manager.spawn_essential_handle()),
        select_chain,
        EssentialExecutorParams {
            primary_chain_client: primary_chain_client.clone(),
            primary_network_sync_oracle,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            backend: backend.clone(),
            code_executor: code_executor.clone(),
            is_authority,
            keystore: params.keystore_container.keystore(),
            bundle_sender: Arc::new(bundle_sender),
            executor_streams,
            domain_confirmation_depth,
            block_import,
        },
    )
    .await?;

    let gossip_message_validator = SystemGossipMessageValidator::new(
        SystemDomainParentChain::<Block, PBlock, _>::new(primary_chain_client),
        client.clone(),
        Box::new(task_manager.spawn_handle()),
        transaction_pool.clone(),
        executor.fraud_proof_generator(),
    );
    let executor_gossip =
        domain_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
            network: network_service.clone(),
            sync: sync_service.clone(),
            executor: gossip_message_validator.clone(),
            bundle_receiver,
        });
    spawn_essential.spawn_essential_blocking(
        "system-domain-gossip",
        None,
        Box::pin(executor_gossip),
    );

    if let Some(relayer_id) = system_domain_config.maybe_relayer_id {
        tracing::info!(
            "Starting system domain relayer with relayer_id[{:?}]",
            relayer_id
        );
        let relayer_worker = domain_client_message_relayer::worker::relay_system_domain_messages(
            relayer_id,
            client.clone(),
            sync_service.clone(),
            gossip_message_sink.clone(),
        );

        spawn_essential.spawn_essential_blocking(
            "system-domain-relayer",
            None,
            Box::pin(relayer_worker),
        );
    }

    let (msg_sender, msg_receiver) = tracing_unbounded("system_domain_message_channel", 100);

    // start cross domain message listener for system domain
    let system_domain_listener = cross_domain_message_gossip::start_domain_message_listener(
        DomainId::SYSTEM,
        client.clone(),
        params.transaction_pool.clone(),
        msg_receiver,
    );

    spawn_essential.spawn_essential_blocking(
        "system-domain-message-listener",
        None,
        Box::pin(system_domain_listener),
    );

    let new_full = NewFullSystem {
        task_manager,
        client,
        backend,
        code_executor,
        network_service,
        sync_service,
        rpc_handlers,
        network_starter,
        executor,
        gossip_message_validator,
        tx_pool_sink: msg_sender,
    };

    Ok(new_full)
}
