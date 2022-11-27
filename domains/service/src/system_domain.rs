use crate::{new_partial, Configuration, FullBackend, FullClient, FullPool};
use domain_client_executor::{
    EssentialExecutorParams, SystemExecutor, SystemGossipMessageValidator,
};
use domain_client_executor_gossip::ExecutorGossipParams;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi, Hash, RelayerId};
use futures::channel::mpsc;
use futures::Stream;
use jsonrpsee::tracing;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{BlockBackend, StateBackendFor};
use sc_consensus::ForkChoiceStrategy;
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_network::NetworkService;
use sc_service::{BuildNetworkParams, NetworkStarter, SpawnTasksParams, TFullBackend, TaskManager};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, BlockT, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::ExecutorApi;
use sp_messenger::RelayerApi;
use sp_offchain::OffchainWorkerApi;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::Index as Nonce;
use substrate_frame_rpc_system::AccountNonceApi;
use system_runtime_primitives::SystemDomainApi;

type SystemDomainExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch> = SystemExecutor<
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
        + DomainCoreApi<Block, AccountId>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, RelayerId, NumberFor<Block>>,
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
    pub executor: SystemDomainExecutor<PBlock, PClient, RuntimeApi, ExecutorDispatch>,
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
    block_import_throttling_buffer_size: u32,
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
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, RelayerId, NumberFor<Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    // TODO: Do we even need block announcement on secondary node?
    // secondary_chain_config.announce_block = false;

    secondary_chain_config
        .service_config
        .network
        .extra_sets
        .push(domain_client_executor_gossip::executor_gossip_peers_set_config());

    let params = new_partial(&secondary_chain_config.service_config)?;

    let (mut telemetry, _telemetry_worker_handle, code_executor, import_block_notification_stream) =
        params.other;

    let client = params.client.clone();
    let backend = params.backend.clone();

    let validator = secondary_chain_config.service_config.role.is_authority();
    let transaction_pool = params.transaction_pool.clone();
    let mut task_manager = params.task_manager;
    let (network, system_rpc_tx, tx_handler_controller, network_starter) =
        sc_service::build_network(BuildNetworkParams {
            config: &secondary_chain_config.service_config,
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
        let chain_spec = secondary_chain_config
            .service_config
            .chain_spec
            .cloned_box();

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

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool: transaction_pool.clone(),
        task_manager: &mut task_manager,
        config: secondary_chain_config.service_config,
        keystore: params.keystore_container.sync_keystore(),
        backend: backend.clone(),
        network: network.clone(),
        system_rpc_tx,
        tx_handler_controller,
        telemetry: telemetry.as_mut(),
    })?;

    let code_executor = Arc::new(code_executor);

    let spawn_essential = task_manager.spawn_essential_handle();
    let (bundle_sender, bundle_receiver) = tracing_unbounded("system_domain_bundle_stream");

    let executor = SystemExecutor::new(
        &spawn_essential,
        select_chain,
        EssentialExecutorParams {
            primary_chain_client: primary_chain_client.clone(),
            primary_network,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            backend: backend.clone(),
            code_executor: code_executor.clone(),
            is_authority: validator,
            keystore: params.keystore_container.sync_keystore(),
            spawner: Box::new(task_manager.spawn_handle()),
            bundle_sender: Arc::new(bundle_sender),
            block_import_throttling_buffer_size,
            imported_block_notification_stream,
            new_slot_notification_stream,
        },
    )
    .await?;

    let gossip_message_validator = SystemGossipMessageValidator::new(
        primary_chain_client,
        client.clone(),
        Box::new(task_manager.spawn_handle()),
        transaction_pool,
        executor.fraud_proof_generator(),
    );
    let executor_gossip =
        domain_client_executor_gossip::start_gossip_worker(ExecutorGossipParams {
            network: network.clone(),
            executor: gossip_message_validator,
            bundle_receiver,
        });
    spawn_essential.spawn_essential_blocking(
        "system-domain-gossip",
        None,
        Box::pin(executor_gossip),
    );

    if let Some(relayer_id) = secondary_chain_config.maybe_relayer_id {
        tracing::info!(
            "Starting system domain relayer with relayer_id[{:?}]",
            relayer_id
        );
        let relayer_worker = domain_client_message_relayer::worker::relay_system_domain_messages(
            relayer_id,
            client.clone(),
            import_block_notification_stream.subscribe(),
            network.clone(),
        );

        spawn_essential.spawn_essential_blocking(
            "system-domain-relayer",
            None,
            Box::pin(relayer_worker),
        );
    }

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
