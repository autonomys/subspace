use crate::providers::{BlockImportProvider, RpcProvider};
use crate::{DomainConfiguration, FullBackend, FullClient};
use cross_domain_message_gossip::DomainTxPoolSink;
use domain_client_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_client_consensus_relay_chain::DomainBlockImport;
use domain_client_message_relayer::GossipMessageSink;
use domain_client_operator::{Operator, OperatorParams, OperatorStreams};
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{Balance, BlockNumber, DomainCoreApi, Hash, InherentExtrinsicApi};
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
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_core::{Decode, Encode};
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::Index as Nonce;
use subspace_transaction_pool::FullChainApiWrapper;
use substrate_frame_rpc_system::AccountNonceApi;

type BlockImportOf<Block, Client, Provider> = <Provider as BlockImportProvider<Block, Client>>::BI;

pub type DomainOperator<Block, CBlock, CClient, RuntimeApi, ExecutorDispatch, BI> = Operator<
    Block,
    CBlock,
    FullClient<Block, RuntimeApi, ExecutorDispatch>,
    CClient,
    FullPool<CBlock, CClient, RuntimeApi, ExecutorDispatch>,
    FullBackend<Block>,
    NativeElseWasmExecutor<ExecutorDispatch>,
    DomainBlockImport<BI>,
>;

/// Domain full node along with some other components.
pub struct NewFull<C, CodeExecutor, CBlock, CClient, RuntimeApi, ExecutorDispatch, AccountId, BI>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Hash>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, BlockNumber, Hash>,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + Metadata<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + TaggedTransactionQueue<Block>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + RelayerApi<Block, AccountId, NumberFor<Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
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
    pub network_service: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Operator.
    pub operator: DomainOperator<Block, CBlock, CClient, RuntimeApi, ExecutorDispatch, BI>,
    /// Transaction pool sink
    pub tx_pool_sink: DomainTxPoolSink,
    _phantom_data: PhantomData<AccountId>,
}

type DomainTxPreValidator<CBlock, CClient, RuntimeApi, ExecutorDispatch> =
    crate::domain_tx_pre_validator::DomainTxPreValidator<
        Block,
        CBlock,
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
        CClient,
        RuntimeApiFull<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
    >;

pub type FullPool<CBlock, CClient, RuntimeApi, ExecutorDispatch> =
    subspace_transaction_pool::FullPool<
        Block,
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
        DomainTxPreValidator<CBlock, CClient, RuntimeApi, ExecutorDispatch>,
    >;

/// Constructs a partial domain node.
#[allow(clippy::type_complexity)]
fn new_partial<RuntimeApi, ExecutorDispatch, CBlock, CClient, BIMP>(
    config: &ServiceConfiguration,
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    block_import_provider: &BIMP,
) -> Result<
    PartialComponents<
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
        FullBackend<Block>,
        (),
        sc_consensus::DefaultImportQueue<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>,
        FullPool<CBlock, CClient, RuntimeApi, ExecutorDispatch>,
        (
            Option<Telemetry>,
            Option<TelemetryWorkerHandle>,
            NativeElseWasmExecutor<ExecutorDispatch>,
            Arc<DomainBlockImport<BIMP::BI>>,
        ),
    >,
    sc_service::Error,
>
where
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Hash>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, BlockNumber, Hash>,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
    BIMP: BlockImportProvider<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>,
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

    let domain_tx_pre_validator = DomainTxPreValidator::new(
        domain_id,
        client.clone(),
        Box::new(task_manager.spawn_handle()),
        consensus_client,
        RuntimeApiFull::new(client.clone()),
    );

    let transaction_pool = subspace_transaction_pool::new_full(
        config,
        &task_manager,
        client.clone(),
        domain_tx_pre_validator,
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

pub struct DomainParams<CBlock, CClient, SC, IBNS, CIBNS, NSNS, AccountId, Provider>
where
    CBlock: BlockT,
{
    pub domain_id: DomainId,
    pub domain_config: DomainConfiguration<AccountId>,
    pub consensus_client: Arc<CClient>,
    pub consensus_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    pub select_chain: SC,
    pub operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS>,
    pub gossip_message_sink: GossipMessageSink,
    pub provider: Provider,
}

/// Builds service for a domain full node.
pub async fn new_full<
    CBlock,
    CClient,
    SC,
    IBNS,
    CIBNS,
    NSNS,
    RuntimeApi,
    ExecutorDispatch,
    AccountId,
    Provider,
>(
    domain_params: DomainParams<CBlock, CClient, SC, IBNS, CIBNS, NSNS, AccountId, Provider>,
) -> sc_service::error::Result<
    NewFull<
        Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        CBlock,
        CClient,
        RuntimeApi,
        ExecutorDispatch,
        AccountId,
        BlockImportOf<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>, Provider>,
    >,
>
where
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>> + Into<u32>,
    <Block as BlockT>::Hash: From<Hash>,
    CBlock::Hash: From<Hash>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, BlockNumber, Hash>,
    SC: SelectChain<CBlock>,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
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
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
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
            FullPool<CBlock, CClient, RuntimeApi, ExecutorDispatch>,
            FullChainApiWrapper<
                Block,
                FullClient<Block, RuntimeApi, ExecutorDispatch>,
                DomainTxPreValidator<CBlock, CClient, RuntimeApi, ExecutorDispatch>,
            >,
            TFullBackend<Block>,
            AccountId,
        > + BlockImportProvider<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + 'static,
{
    let DomainParams {
        domain_id,
        domain_config,
        consensus_client,
        consensus_network_sync_oracle,
        select_chain,
        operator_streams,
        gossip_message_sink,
        provider,
    } = domain_params;

    // TODO: Do we even need block announcement on domain node?
    // domain_config.announce_block = false;

    let params = new_partial(
        &domain_config.service_config,
        domain_id,
        consensus_client.clone(),
        &provider,
    )?;

    let (mut telemetry, _telemetry_worker_handle, code_executor, block_import) = params.other;

    let client = params.client.clone();
    let backend = params.backend.clone();

    let transaction_pool = params.transaction_pool.clone();
    let mut task_manager = params.task_manager;
    let mut net_config =
        sc_network::config::FullNetworkConfiguration::new(&domain_config.service_config.network);

    net_config.add_notification_protocol(
        domain_client_subnet_gossip::domain_subnet_gossip_peers_set_config(),
    );

    let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        crate::build_network(BuildNetworkParams {
            config: &domain_config.service_config,
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

    let is_authority = domain_config.service_config.role.is_authority();
    let rpc_builder = {
        let deps = crate::rpc::FullDeps {
            client: client.clone(),
            pool: transaction_pool.clone(),
            graph: transaction_pool.pool().clone(),
            chain_spec: domain_config.service_config.chain_spec.cloned_box(),
            deny_unsafe: DenyUnsafe::Yes,
            network: network_service.clone(),
            sync: sync_service.clone(),
            is_authority,
            prometheus_registry: domain_config.service_config.prometheus_registry().cloned(),
            database_source: domain_config.service_config.database.clone(),
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
        config: domain_config.service_config,
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
    let (bundle_sender, _bundle_receiver) = tracing_unbounded("domain_bundle_stream", 100);

    // let domain_confirmation_depth = consensus_client
    // .runtime_api()
    // .receipts_pruning_depth(consensus_client.info().best_hash)
    // .map_err(|err| sc_service::error::Error::Application(Box::new(err)))?
    // .into();
    // TODO: Implement when block tree is ready.
    let domain_confirmation_depth = 256u32;

    let operator = Operator::new(
        Box::new(task_manager.spawn_essential_handle()),
        &select_chain,
        OperatorParams {
            domain_id,
            consensus_client: consensus_client.clone(),
            consensus_network_sync_oracle,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            backend: backend.clone(),
            code_executor: code_executor.clone(),
            is_authority,
            keystore: params.keystore_container.keystore(),
            bundle_sender: Arc::new(bundle_sender),
            operator_streams,
            domain_confirmation_depth,
            block_import,
        },
    )
    .await?;

    if let Some(relayer_id) = domain_config.maybe_relayer_id {
        tracing::info!(?domain_id, ?relayer_id, "Starting domain relayer");
        let relayer_worker = domain_client_message_relayer::worker::relay_system_domain_messages(
            relayer_id,
            client.clone(),
            sync_service.clone(),
            gossip_message_sink,
        );

        spawn_essential.spawn_essential_blocking("domain-relayer", None, Box::pin(relayer_worker));
    }

    let (msg_sender, msg_receiver) = tracing_unbounded("domain_message_channel", 100);

    // Start cross domain message listener for domain
    let domain_listener = cross_domain_message_gossip::start_domain_message_listener(
        domain_id,
        client.clone(),
        params.transaction_pool.clone(),
        msg_receiver,
    );

    spawn_essential.spawn_essential_blocking(
        "domain-message-listener",
        None,
        Box::pin(domain_listener),
    );

    let new_full = NewFull {
        task_manager,
        client,
        backend,
        code_executor,
        network_service,
        sync_service,
        rpc_handlers,
        network_starter,
        operator,
        tx_pool_sink: msg_sender,
        _phantom_data: Default::default(),
    };

    Ok(new_full)
}
