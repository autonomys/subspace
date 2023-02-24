use crate::{DomainConfiguration, FullBackend, FullClient};
use cross_domain_message_gossip::{DomainTxPoolSink, Message as GossipMessage};
use domain_client_executor::xdm_validator::CoreDomainXDMValidator;
use domain_client_executor::{CoreExecutor, CoreGossipMessageValidator, EssentialExecutorParams};
use domain_client_executor_gossip::ExecutorGossipParams;
use domain_client_message_relayer::GossipMessageSink;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi, Hash, RelayerId};
use futures::channel::mpsc;
use futures::{Stream, StreamExt};
use jsonrpsee::tracing;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{BlockBackend, ProofProvider, StateBackendFor};
use sc_consensus::ForkChoiceStrategy;
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_network::NetworkService;
use sc_service::{
    BuildNetworkParams, Configuration as ServiceConfiguration, NetworkStarter, PartialComponents,
    SpawnTasksParams, TFullBackend, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker, TelemetryWorkerHandle};
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_core::Encode;
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};
use subspace_runtime_primitives::Index as Nonce;
use substrate_frame_rpc_system::AccountNonceApi;
use system_runtime_primitives::SystemDomainApi;

type CoreDomainExecutor<SBlock, PBlock, SClient, PClient, RuntimeApi, ExecutorDispatch> =
    CoreExecutor<
        Block,
        SBlock,
        PBlock,
        FullClient<RuntimeApi, ExecutorDispatch>,
        SClient,
        PClient,
        FullPool<RuntimeApi, ExecutorDispatch, CoreDomainXDMValidator<SClient, PBlock, SBlock>>,
        FullBackend,
        NativeElseWasmExecutor<ExecutorDispatch>,
    >;

/// Core domain full node along with some other components.
pub struct NewFullCore<
    C,
    CodeExecutor,
    SBlock,
    PBlock,
    SClient,
    PClient,
    RuntimeApi,
    ExecutorDispatch,
> where
    SBlock: BlockT,
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
        + DomainCoreApi<Block, AccountId>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, RelayerId, NumberFor<Block>>,
    <Block as BlockT>::Extrinsic: Into<SBlock::Extrinsic>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
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
    pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Executor.
    pub executor:
        CoreDomainExecutor<SBlock, PBlock, SClient, PClient, RuntimeApi, ExecutorDispatch>,
    /// Transaction pool sink
    pub tx_pool_sink: DomainTxPoolSink,
}

pub type FullPool<RuntimeApi, ExecutorDispatch, Verifier> =
    subspace_transaction_pool::FullPoolWithChainVerifier<
        Block,
        FullClient<RuntimeApi, ExecutorDispatch>,
        Verifier,
    >;

/// Constructs a partial core domain node.
#[allow(clippy::type_complexity)]
fn new_partial<RuntimeApi, Executor, SDC, SBlock, PBlock>(
    config: &ServiceConfiguration,
    system_domain_client: Arc<SDC>,
) -> Result<
    PartialComponents<
        FullClient<RuntimeApi, Executor>,
        TFullBackend<Block>,
        (),
        sc_consensus::DefaultImportQueue<Block, FullClient<RuntimeApi, Executor>>,
        subspace_transaction_pool::FullPoolWithChainVerifier<
            Block,
            FullClient<RuntimeApi, Executor>,
            CoreDomainXDMValidator<SDC, PBlock, SBlock>,
        >,
        (
            Option<Telemetry>,
            Option<TelemetryWorkerHandle>,
            NativeElseWasmExecutor<Executor>,
        ),
    >,
    sc_service::Error,
>
where
    RuntimeApi:
        ConstructRuntimeApi<Block, FullClient<RuntimeApi, Executor>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>,
    Executor: NativeExecutionDispatch + 'static,
    SBlock: BlockT,
    PBlock: BlockT,
    <Block as BlockT>::Extrinsic: Into<SBlock::Extrinsic>,
    SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SDC::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
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

    let core_domain_xdm_verifier =
        CoreDomainXDMValidator::<SDC, PBlock, SBlock>::new(system_domain_client);
    let transaction_pool = subspace_transaction_pool::new_full_with_verifier(
        config,
        &task_manager,
        client.clone(),
        core_domain_xdm_verifier,
    );

    let import_queue = domain_client_consensus_relay_chain::import_queue(
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

pub struct CoreDomainParams<SBlock, PBlock, SClient, PClient, SC, IBNS, NSNS>
where
    SBlock: BlockT,
    PBlock: BlockT,
{
    pub domain_id: DomainId,
    pub core_domain_config: DomainConfiguration,
    pub system_domain_client: Arc<SClient>,
    pub system_domain_network: Arc<NetworkService<SBlock, SBlock::Hash>>,
    pub primary_chain_client: Arc<PClient>,
    pub primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    pub select_chain: SC,
    pub imported_block_notification_stream: IBNS,
    pub new_slot_notification_stream: NSNS,
    pub block_import_throttling_buffer_size: u32,
    pub gossip_message_sink: GossipMessageSink,
}

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[allow(clippy::too_many_arguments)]
pub async fn new_full_core<
    SBlock,
    PBlock,
    SClient,
    PClient,
    SC,
    IBNS,
    NSNS,
    RuntimeApi,
    ExecutorDispatch,
>(
    core_domain_params: CoreDomainParams<SBlock, PBlock, SClient, PClient, SC, IBNS, NSNS>,
) -> sc_service::error::Result<
    NewFullCore<
        Arc<FullClient<RuntimeApi, ExecutorDispatch>>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        SBlock,
        PBlock,
        SClient,
        PClient,
        RuntimeApi,
        ExecutorDispatch,
    >,
>
where
    PBlock: BlockT,
    SBlock: BlockT,
    SBlock::Hash: Into<Hash>,
    NumberFor<SBlock>: Into<BlockNumber>,
    <Block as BlockT>::Extrinsic: Into<SBlock::Extrinsic>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock> + 'static,
    SClient::Api: DomainCoreApi<SBlock, AccountId>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>
        + RelayerApi<SBlock, RelayerId, NumberFor<SBlock>>,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Hash>,
    SC: SelectChain<PBlock>,
    IBNS: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash)> + Send + 'static,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + DomainCoreApi<Block, AccountId>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, RelayerId, NumberFor<Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    let CoreDomainParams {
        domain_id,
        mut core_domain_config,
        system_domain_client,
        system_domain_network,
        primary_chain_client,
        primary_network,
        select_chain,
        imported_block_notification_stream,
        new_slot_notification_stream,
        block_import_throttling_buffer_size,
        gossip_message_sink,
    } = core_domain_params;

    // TODO: Do we even need block announcement on core domain node?
    // core_domain_config.announce_block = false;

    core_domain_config
        .service_config
        .network
        .extra_sets
        .push(domain_client_executor_gossip::executor_gossip_peers_set_config());

    let params = new_partial::<_, _, _, SBlock, PBlock>(
        &core_domain_config.service_config,
        system_domain_client.clone(),
    )?;

    let (mut telemetry, _telemetry_worker_handle, code_executor) = params.other;

    let client = params.client.clone();
    let backend = params.backend.clone();

    let transaction_pool = params.transaction_pool.clone();
    let mut task_manager = params.task_manager;
    let (network, system_rpc_tx, tx_handler_controller, network_starter) =
        sc_service::build_network(BuildNetworkParams {
            config: &core_domain_config.service_config,
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
        let chain_spec = core_domain_config.service_config.chain_spec.cloned_box();

        Box::new(move |deny_unsafe, _| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: transaction_pool.clone(),
                chain_spec: chain_spec.cloned_box(),
                deny_unsafe,
            };

            crate::rpc::create_full(deps).map_err(Into::into)
        })
    };

    let is_authority = core_domain_config.service_config.role.is_authority();

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool: transaction_pool.clone(),
        task_manager: &mut task_manager,
        config: core_domain_config.service_config,
        keystore: params.keystore_container.sync_keystore(),
        backend: backend.clone(),
        network: network.clone(),
        system_rpc_tx,
        tx_handler_controller,
        telemetry: telemetry.as_mut(),
    })?;

    let code_executor = Arc::new(code_executor);

    let spawn_essential = task_manager.spawn_essential_handle();
    let (bundle_sender, bundle_receiver) = tracing_unbounded("core_domain_bundle_stream", 100);

    let executor = CoreExecutor::new(
        domain_id,
        system_domain_client.clone(),
        &spawn_essential,
        &select_chain,
        EssentialExecutorParams {
            primary_chain_client: primary_chain_client.clone(),
            primary_network,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            backend: backend.clone(),
            code_executor: code_executor.clone(),
            is_authority,
            keystore: params.keystore_container.sync_keystore(),
            spawner: Box::new(task_manager.spawn_handle()),
            bundle_sender: Arc::new(bundle_sender),
            block_import_throttling_buffer_size,
            imported_block_notification_stream,
            new_slot_notification_stream,
        },
    )
    .await?;

    let gossip_message_validator =
        CoreGossipMessageValidator::<_, SBlock, PBlock, _, SClient, PClient, _, _, _>::new(
            primary_chain_client,
            client.clone(),
            Box::new(task_manager.spawn_handle()),
            transaction_pool.clone(),
            executor.fraud_proof_generator(),
        );

    let executor_gossip =
        domain_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
            network: network.clone(),
            executor: gossip_message_validator,
            bundle_receiver,
        });
    spawn_essential.spawn_essential_blocking("core-domain-gossip", None, Box::pin(executor_gossip));

    if let Some(relayer_id) = core_domain_config.maybe_relayer_id {
        tracing::info!(
            "Starting core domain relayer with relayer_id[{:?}]",
            relayer_id
        );
        let relayer_worker = domain_client_message_relayer::worker::relay_core_domain_messages(
            relayer_id,
            client.clone(),
            system_domain_client,
            system_domain_network,
            network.clone(),
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
        network,
        rpc_handlers,
        network_starter,
        executor,
        tx_pool_sink: msg_sender,
    };

    Ok(new_full)
}
