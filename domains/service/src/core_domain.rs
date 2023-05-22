use crate::core_domain_tx_pre_validator::CoreDomainTxPreValidator;
use crate::providers::{BlockImportProvider, RpcProvider};
use crate::{DomainConfiguration, FullBackend, FullClient};
use cross_domain_message_gossip::{DomainTxPoolSink, Message as GossipMessage};
use domain_client_consensus_relay_chain::DomainBlockImport;
use domain_client_executor::{
    CoreDomainParentChain, CoreExecutor, CoreGossipMessageValidator, EssentialExecutorParams,
    ExecutorStreams,
};
use domain_client_executor_gossip::ExecutorGossipParams;
use domain_client_message_relayer::GossipMessageSink;
use domain_runtime_primitives::{Balance, DomainCoreApi, InherentExtrinsicApi};
use frame_benchmarking::frame_support::codec::FullCodec;
use frame_benchmarking::frame_support::dispatch::TypeInfo;
use futures::channel::mpsc;
use futures::{Stream, StreamExt};
use jsonrpsee::tracing;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{
    BlockBackend, BlockImportNotification, BlockchainEvents, ProofProvider, StateBackendFor,
};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_network::NetworkService;
use sc_network_sync::SyncingService;
use sc_rpc_api::DenyUnsafe;
use sc_service::{
    BuildNetworkParams, Configuration as ServiceConfiguration, NetworkStarter, PartialComponents,
    SpawnTasksParams, TFullBackend, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryWorkerHandle};
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool};
use sc_utils::mpsc::tracing_unbounded;
use serde::de::DeserializeOwned;
use sp_api::{
    ApiExt, BlockT, CallApiAt, ConstructRuntimeApi, Decode, Metadata, NumberFor, ProvideRuntimeApi,
};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_core::Encode;
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_receipts::ReceiptsApi;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::Index as Nonce;
use subspace_transaction_pool::{FullChainApiWrapper, FullPool};
use substrate_frame_rpc_system::AccountNonceApi;
use system_runtime_primitives::SystemDomainApi;

type BlockImportOf<Block, Client, Provider> = <Provider as BlockImportProvider<Block, Client>>::BI;

pub type CoreDomainExecutor<
    Block,
    SBlock,
    PBlock,
    SClient,
    PClient,
    RuntimeApi,
    ExecutorDispatch,
    BI,
> = CoreExecutor<
    Block,
    SBlock,
    PBlock,
    FullClient<Block, RuntimeApi, ExecutorDispatch>,
    SClient,
    PClient,
    FullPool<
        Block,
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
        CoreDomainTxPreValidator<
            Block,
            SBlock,
            PBlock,
            FullClient<Block, RuntimeApi, ExecutorDispatch>,
            SClient,
        >,
    >,
    FullBackend<Block>,
    NativeElseWasmExecutor<ExecutorDispatch>,
    DomainBlockImport<BI>,
>;

/// Core domain full node along with some other components.
pub struct NewFullCore<
    C,
    CodeExecutor,
    Block,
    SBlock,
    PBlock,
    SClient,
    PClient,
    RuntimeApi,
    ExecutorDispatch,
    AccountId,
    BI,
> where
    SBlock: BlockT,
    PBlock: BlockT,
    Block: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: From<Block::Hash>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
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
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>>
        + RelayerApi<Block, AccountId, NumberFor<Block>>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    AccountId: Encode + Decode,
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
    pub network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    /// Sync service.
    pub sync_service: Arc<SyncingService<Block>>,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Executor.
    pub executor: CoreDomainExecutor<
        Block,
        SBlock,
        PBlock,
        SClient,
        PClient,
        RuntimeApi,
        ExecutorDispatch,
        BI,
    >,
    /// Transaction pool sink
    pub tx_pool_sink: DomainTxPoolSink,
    _data: PhantomData<AccountId>,
}

/// Constructs a partial core domain node.
#[allow(clippy::type_complexity)]
fn new_partial<RuntimeApi, Executor, SDC, Block, SBlock, PBlock, BIMP>(
    config: &ServiceConfiguration,
    system_domain_client: Arc<SDC>,
    block_import_provider: &BIMP,
) -> Result<
    PartialComponents<
        FullClient<Block, RuntimeApi, Executor>,
        TFullBackend<Block>,
        (),
        sc_consensus::DefaultImportQueue<Block, FullClient<Block, RuntimeApi, Executor>>,
        FullPool<
            Block,
            FullClient<Block, RuntimeApi, Executor>,
            CoreDomainTxPreValidator<
                Block,
                SBlock,
                PBlock,
                FullClient<Block, RuntimeApi, Executor>,
                SDC,
            >,
        >,
        (
            Option<Telemetry>,
            Option<TelemetryWorkerHandle>,
            NativeElseWasmExecutor<Executor>,
            Arc<DomainBlockImport<BIMP::BI>>,
        ),
    >,
    sc_service::Error,
>
where
    RuntimeApi:
        ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, Executor>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + MessengerApi<Block, NumberFor<Block>>,
    Executor: NativeExecutionDispatch + 'static,
    Block: BlockT,
    SBlock: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: From<Block::Hash>,
    PBlock: BlockT,
    SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SDC::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    BIMP: BlockImportProvider<Block, FullClient<Block, RuntimeApi, Executor>>,
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
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let core_domain_tx_pre_validator =
        CoreDomainTxPreValidator::new(client.clone(), system_domain_client);
    let transaction_pool = subspace_transaction_pool::new_full(
        config,
        &task_manager,
        client.clone(),
        core_domain_tx_pre_validator,
    );
    let block_import = Arc::new(DomainBlockImport::new(BlockImportProvider::block_import(
        block_import_provider,
        client.clone(),
    )));
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

pub struct CoreDomainParams<
    SBlock,
    PBlock,
    SClient,
    PClient,
    SC,
    IBNS,
    CIBNS,
    NSNS,
    AccountId,
    Provider,
> where
    SBlock: BlockT,
    PBlock: BlockT,
{
    pub domain_id: DomainId,
    pub core_domain_config: DomainConfiguration<AccountId>,
    pub system_domain_client: Arc<SClient>,
    pub system_domain_sync_service: Arc<SyncingService<SBlock>>,
    pub primary_chain_client: Arc<PClient>,
    pub primary_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    pub select_chain: SC,
    pub executor_streams: ExecutorStreams<PBlock, IBNS, CIBNS, NSNS>,
    pub gossip_message_sink: GossipMessageSink,
    pub provider: Provider,
}

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[allow(clippy::too_many_arguments)]
pub async fn new_full_core<
    Block,
    SBlock,
    PBlock,
    SClient,
    PClient,
    SC,
    IBNS,
    CIBNS,
    NSNS,
    RuntimeApi,
    ExecutorDispatch,
    AccountId,
    Provider,
>(
    core_domain_params: CoreDomainParams<
        SBlock,
        PBlock,
        SClient,
        PClient,
        SC,
        IBNS,
        CIBNS,
        NSNS,
        AccountId,
        Provider,
    >,
) -> sc_service::error::Result<
    NewFullCore<
        Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        Block,
        SBlock,
        PBlock,
        SClient,
        PClient,
        RuntimeApi,
        ExecutorDispatch,
        AccountId,
        BlockImportOf<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>, Provider>,
    >,
>
where
    Block: BlockT,
    PBlock: BlockT,
    SBlock: BlockT,
    SBlock::Hash: Into<Block::Hash> + From<Block::Hash>,
    Block::Hash: FullCodec + TypeInfo + Unpin,
    NumberFor<SBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    <Block as BlockT>::Header: Unpin,
    NumberFor<Block>: FullCodec + TypeInfo,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock> + 'static,
    SClient::Api: DomainCoreApi<SBlock>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>
        + RelayerApi<SBlock, domain_runtime_primitives::AccountId, NumberFor<SBlock>>
        + ReceiptsApi<SBlock, <Block as BlockT>::Hash>,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + CallApiAt<PBlock>
        + BlockchainEvents<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
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
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + RelayerApi<Block, AccountId, NumberFor<Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
    AccountId: DeserializeOwned
        + Encode
        + Decode
        + Clone
        + Debug
        + Display
        + FromStr
        + Sync
        + Send
        + 'static,
    Provider: RpcProvider<
            Block,
            FullClient<Block, RuntimeApi, ExecutorDispatch>,
            FullPool<
                Block,
                FullClient<Block, RuntimeApi, ExecutorDispatch>,
                CoreDomainTxPreValidator<
                    Block,
                    SBlock,
                    PBlock,
                    FullClient<Block, RuntimeApi, ExecutorDispatch>,
                    SClient,
                >,
            >,
            FullChainApiWrapper<
                Block,
                FullClient<Block, RuntimeApi, ExecutorDispatch>,
                CoreDomainTxPreValidator<
                    Block,
                    SBlock,
                    PBlock,
                    FullClient<Block, RuntimeApi, ExecutorDispatch>,
                    SClient,
                >,
            >,
            TFullBackend<Block>,
            AccountId,
        > + BlockImportProvider<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + 'static,
{
    let CoreDomainParams {
        domain_id,
        mut core_domain_config,
        system_domain_client,
        system_domain_sync_service,
        primary_chain_client,
        primary_network_sync_oracle,
        select_chain,
        executor_streams,
        gossip_message_sink,
        provider,
    } = core_domain_params;

    // TODO: Do we even need block announcement on core domain node?
    // core_domain_config.announce_block = false;

    core_domain_config
        .service_config
        .network
        .extra_sets
        .push(domain_client_executor_gossip::executor_gossip_peers_set_config());

    let params = new_partial::<_, _, _, Block, SBlock, PBlock, Provider>(
        &core_domain_config.service_config,
        system_domain_client.clone(),
        &provider,
    )?;

    let (mut telemetry, _telemetry_worker_handle, code_executor, block_import) = params.other;

    let client = params.client.clone();
    let backend = params.backend.clone();

    let transaction_pool = params.transaction_pool.clone();
    let mut task_manager = params.task_manager;
    let import_queue = params.import_queue;

    let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(BuildNetworkParams {
            config: &core_domain_config.service_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            // TODO: we might want to re-enable this some day.
            block_announce_validator_builder: None,
            warp_sync_params: None,
        })?;

    let is_authority = core_domain_config.service_config.role.is_authority();
    core_domain_config.service_config.rpc_id_provider = provider.rpc_id();

    let rpc_builder = {
        let deps = crate::rpc::FullDeps {
            client: client.clone(),
            pool: transaction_pool.clone(),
            graph: transaction_pool.pool().clone(),
            chain_spec: core_domain_config.service_config.chain_spec.cloned_box(),
            deny_unsafe: DenyUnsafe::Yes,
            network: network_service.clone(),
            sync: sync_service.clone(),
            is_authority,
            prometheus_registry: core_domain_config
                .service_config
                .prometheus_registry()
                .cloned(),
            database_source: core_domain_config.service_config.database.clone(),
            task_spawner: task_manager.spawn_handle(),
            backend: backend.clone(),
        };

        let spawn_essential = task_manager.spawn_essential_handle();
        let rpc_deps = provider.deps(deps)?;
        Box::new(move |_, subscription_task_executor| {
            let spawn_essential = spawn_essential.clone();
            provider
                .rpc_builder(
                    rpc_deps.clone(),
                    subscription_task_executor,
                    spawn_essential,
                )
                .map_err(Into::into)
        })
    };

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool: transaction_pool.clone(),
        task_manager: &mut task_manager,
        config: core_domain_config.service_config,
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
    let (bundle_sender, bundle_receiver) = tracing_unbounded("core_domain_bundle_stream", 100);

    let system_domain_best_hash = system_domain_client.info().best_hash;
    let receipts_api_version = system_domain_client
        .runtime_api()
        .api_version::<dyn ReceiptsApi<SBlock, Block::Hash>>(system_domain_best_hash)
        .ok()
        .flatten()
        .ok_or_else(|| {
            sp_blockchain::Error::RuntimeApiError(sp_api::ApiError::Application(
                format!("Could not find `ReceiptsApi` api version at {system_domain_best_hash}.",)
                    .into(),
            ))
        })?;

    let domain_confirmation_depth = if receipts_api_version >= 2 {
        system_domain_client
            .runtime_api()
            .receipts_pruning_depth(system_domain_best_hash)
            .map_err(|err| sc_service::error::Error::Application(Box::new(err)))?
            .into()
    } else {
        // TODO: Remove the api version check once gemini-3d is retired.
        256u32.into()
    };

    let executor = CoreExecutor::new(
        domain_id,
        system_domain_client.clone(),
        Box::new(task_manager.spawn_essential_handle()),
        &select_chain,
        EssentialExecutorParams::<
            Block,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            DomainBlockImport<Provider::BI>,
        > {
            primary_chain_client: primary_chain_client.clone(),
            primary_network_sync_oracle,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            backend: backend.clone(),
            code_executor: code_executor.clone(),
            is_authority,
            keystore: params.keystore_container.keystore(),
            spawner: Box::new(task_manager.spawn_handle()),
            bundle_sender: Arc::new(bundle_sender),
            executor_streams,
            domain_confirmation_depth,
            block_import,
        },
    )
    .await?;

    let gossip_message_validator =
        CoreGossipMessageValidator::<_, SBlock, PBlock, _, SClient, _, _, _, _, _>::new(
            CoreDomainParentChain::<_, SBlock, PBlock>::new(
                system_domain_client.clone(),
                domain_id,
            ),
            client.clone(),
            Box::new(task_manager.spawn_handle()),
            transaction_pool.clone(),
            executor.fraud_proof_generator(),
        );

    let executor_gossip =
        domain_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
            network: network_service.clone(),
            sync: sync_service.clone(),
            executor: gossip_message_validator,
            bundle_receiver,
        });
    spawn_essential.spawn_essential_blocking("core-domain-gossip", None, Box::pin(executor_gossip));

    if let Some(relayer_id) = core_domain_config.maybe_relayer_id {
        tracing::info!(
            "Starting core domain relayer with relayer_id[{:?}]",
            relayer_id
        );
        let relayer_worker = domain_client_message_relayer::worker::relay_core_domain_messages::<
            _,
            _,
            PBlock,
            _,
            _,
            _,
            _,
            _,
        >(
            relayer_id,
            client.clone(),
            system_domain_client,
            system_domain_sync_service,
            sync_service.clone(),
            gossip_message_sink.clone(),
        );

        spawn_essential.spawn_essential_blocking(
            "core-domain-relayer",
            None,
            Box::pin(relayer_worker),
        );
    }

    let (msg_sender, msg_receiver) = tracing_unbounded("core_domain_message_channel", 100);

    // start cross domain message listener for system domain
    let core_domain_listener = cross_domain_message_gossip::start_domain_message_listener(
        domain_id,
        client.clone(),
        params.transaction_pool.clone(),
        msg_receiver,
    );

    spawn_essential.spawn_essential_blocking(
        "core-domain-message-listener",
        None,
        Box::pin(core_domain_listener),
    );

    spawn_essential.spawn_blocking("core-domain-transaction-gossip", None, {
        Box::pin(async move {
            while let Some(hash) = transaction_pool.import_notification_stream().next().await {
                let maybe_transaction = transaction_pool.ready_transaction(&hash).and_then(
                    // Only propagable transactions should be resolved for network service.
                    |tx| {
                        if tx.is_propagable() {
                            Some(tx.data().clone())
                        } else {
                            None
                        }
                    },
                );
                if let Some(tx) = maybe_transaction {
                    let msg = GossipMessage {
                        domain_id,
                        encoded_data: tx.encode(),
                    };
                    if let Err(_e) = gossip_message_sink.unbounded_send(msg) {
                        return;
                    }
                }
            }
        })
    });

    let new_full = NewFullCore {
        task_manager,
        client,
        backend,
        code_executor,
        network_service,
        sync_service,
        rpc_handlers,
        network_starter,
        executor,
        tx_pool_sink: msg_sender,
        _data: Default::default(),
    };

    Ok(new_full)
}
