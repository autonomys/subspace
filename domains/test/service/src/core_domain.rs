//! Utilities used for testing with the system domain.
#![warn(missing_docs)]
use crate::system_domain::SClient;
use crate::{
    construct_extrinsic_generic, node_config, Backend, SystemDomainNode, UncheckedExtrinsicFor,
};
use domain_client_executor::ExecutorStreams;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi};
use domain_service::providers::DefaultProvider;
use domain_service::FullClient;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::{BlockchainEvents, HeaderBackend, StateBackendFor};
use sc_executor::NativeExecutionDispatch;
use sc_network::{NetworkService, NetworkStateInfo};
use sc_network_sync::SyncingService;
use sc_service::config::MultiaddrWithPeerId;
use sc_service::{BasePath, Role, RpcHandlers, TFullBackend, TaskManager};
use sp_api::{ApiExt, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_core::H256;
use sp_domains::DomainId;
use sp_keyring::Sr25519Keyring;
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::Dispatchable;
use sp_runtime::OpaqueExtrinsic;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_runtime_primitives::opaque::Block as PBlock;
use subspace_runtime_primitives::Index as Nonce;
use subspace_test_service::mock::MockPrimaryNode;
use substrate_frame_rpc_system::AccountNonceApi;
use substrate_test_client::{
    BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};
use system_domain_test_runtime;
use system_domain_test_runtime::opaque::Block as SBlock;

/// Core domain executor for the test service.
pub type CoreDomainExecutor<RuntimeApi, Executor> = domain_service::CoreDomainExecutor<
    Block,
    SBlock,
    PBlock,
    SClient,
    subspace_test_client::Client,
    RuntimeApi,
    Executor,
    Arc<FullClient<Block, RuntimeApi, Executor>>,
>;

/// A core domain node instance used for testing.
pub struct CoreDomainNode<Runtime, RuntimeApi, Executor>
where
    RuntimeApi:
        ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, Executor>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block> + MessengerApi<Block, NumberFor<Block>>,
    Executor: NativeExecutionDispatch + Send + Sync + 'static,
{
    /// The domain id
    pub domain_id: DomainId,
    /// The node's account key
    pub key: Sr25519Keyring,
    /// TaskManager's instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<FullClient<Block, RuntimeApi, Executor>>,
    /// Client backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub code_executor: Arc<sc_executor::NativeElseWasmExecutor<Executor>>,
    /// Network service.
    pub network_service: Arc<NetworkService<Block, H256>>,
    /// Sync service.
    pub sync_service: Arc<SyncingService<Block>>,
    /// The `MultiaddrWithPeerId` to this node. This is useful if you want to pass it as "boot node"
    /// to other nodes.
    pub addr: MultiaddrWithPeerId,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: RpcHandlers,
    /// System domain executor.
    pub executor: CoreDomainExecutor<RuntimeApi, Executor>,
    _phantom_data: PhantomData<Runtime>,
}

impl<Runtime, RuntimeApi, Executor> CoreDomainNode<Runtime, RuntimeApi, Executor>
where
    Runtime: frame_system::Config<Hash = H256, BlockNumber = u32>
        + pallet_transaction_payment::Config
        + Send
        + Sync,
    Runtime::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + Send + Sync,
    crate::BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
    RuntimeApi:
        ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, Executor>> + Send + Sync + 'static,
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
    Executor: NativeExecutionDispatch + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    async fn build(
        domain_id: DomainId,
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
        core_domain_nodes: Vec<MultiaddrWithPeerId>,
        core_domain_nodes_exclusive: bool,
        role: Role,
        mock_primary_node: &mut MockPrimaryNode,
        system_domain_node: &SystemDomainNode,
    ) -> Self {
        let service_config = node_config(
            domain_id,
            tokio_handle.clone(),
            key,
            core_domain_nodes,
            core_domain_nodes_exclusive,
            role,
            BasePath::new(base_path.path().join(format!("core-{domain_id:?}"))),
        )
        .expect("could not generate core domain node Configuration");

        let span = sc_tracing::tracing::info_span!(
            sc_tracing::logging::PREFIX_LOG_SPAN,
            name = service_config.network.node_name.as_str()
        );
        let _enter = span.enter();

        let multiaddr = service_config.network.listen_addresses[0].clone();

        let core_domain_config = domain_service::DomainConfiguration {
            service_config,
            maybe_relayer_id: None,
        };
        let executor_streams = ExecutorStreams {
            // Set `primary_block_import_throttling_buffer_size` to 0 to ensure the primary chain will not be
            // ahead of the execution chain by more than one block, thus slot will not be skipped in test.
            primary_block_import_throttling_buffer_size: 0,
            block_importing_notification_stream: mock_primary_node
                .block_importing_notification_stream(),
            imported_block_notification_stream: mock_primary_node
                .client
                .every_import_notification_stream(),
            new_slot_notification_stream: mock_primary_node.new_slot_notification_stream(),
            _phantom: Default::default(),
        };
        let (dummy_gossip_msg_sink, _) =
            sc_utils::mpsc::tracing_unbounded("cross_domain_gossip_messages", 100);
        let core_domain_params = domain_service::CoreDomainParams {
            domain_id,
            core_domain_config,
            system_domain_client: system_domain_node.client.clone(),
            system_domain_sync_service: system_domain_node.sync_service.clone(),
            primary_chain_client: mock_primary_node.client.clone(),
            primary_network_sync_oracle: MockPrimaryNode::sync_oracle(),
            select_chain: mock_primary_node.select_chain.clone(),
            executor_streams,
            gossip_message_sink: dummy_gossip_msg_sink,
            provider: DefaultProvider,
        };
        let core_domain_node =
            domain_service::new_full_core::<_, _, _, _, _, _, _, _, _, RuntimeApi, Executor, _, _>(
                core_domain_params,
            )
            .await
            .expect("Should be able to start core domain node");

        let domain_service::NewFullCore {
            task_manager,
            client,
            backend,
            code_executor,
            network_service,
            sync_service,
            network_starter,
            rpc_handlers,
            executor,
            ..
        } = core_domain_node;

        let addr = MultiaddrWithPeerId {
            multiaddr,
            peer_id: network_service.local_peer_id(),
        };

        network_starter.start_network();

        CoreDomainNode {
            domain_id,
            key,
            task_manager,
            client,
            backend,
            code_executor,
            network_service,
            sync_service,
            addr,
            rpc_handlers,
            executor,
            _phantom_data: Default::default(),
        }
    }

    /// Wait for `count` blocks to be imported in the node and then exit. This function will not
    /// return if no blocks are ever created, thus you should restrict the maximum amount of time of
    /// the test execution.
    pub fn wait_for_blocks(&self, count: usize) -> impl Future<Output = ()> {
        self.client.wait_for_blocks(count)
    }

    /// Get the nonce of the node account
    pub fn account_nonce(&self) -> u32 {
        self.client
            .runtime_api()
            .account_nonce(self.client.info().best_hash, self.key.into())
            .expect("Fail to get account nonce")
    }

    /// Construct an extrinsic with the current nonce of the node account and send it to this node.
    pub async fn construct_and_send_extrinsic(
        &mut self,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        let extrinsic = construct_extrinsic_generic::<Runtime, _>(
            &self.client,
            function,
            self.key,
            false,
            self.account_nonce(),
        );
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }

    /// Construct an extrinsic.
    pub fn construct_extrinsic(
        &mut self,
        nonce: u32,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> UncheckedExtrinsicFor<Runtime> {
        construct_extrinsic_generic::<Runtime, _>(&self.client, function, self.key, false, nonce)
    }

    /// Send an extrinsic to this node.
    pub async fn send_extrinsic(
        &self,
        extrinsic: impl Into<OpaqueExtrinsic>,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }
}

/// A builder to create a [`SystemDomainNode`].
pub struct CoreDomainNodeBuilder {
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    core_domain_nodes: Vec<MultiaddrWithPeerId>,
    core_domain_nodes_exclusive: bool,
    base_path: BasePath,
}

impl CoreDomainNodeBuilder {
    /// Create a new instance of `Self`.
    ///
    /// `tokio_handle` - The tokio handler to use.
    /// `key` - The key that will be used to generate the name.
    /// `base_path` - Where databases will be stored.
    pub fn new(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> Self {
        CoreDomainNodeBuilder {
            key,
            tokio_handle,
            core_domain_nodes: Vec::new(),
            core_domain_nodes_exclusive: false,
            base_path,
        }
    }

    /// Instruct the node to exclusively connect to registered parachain nodes.
    ///
    /// Core domain nodes can be registered using [`Self::connect_to_core_domain_node`].
    pub fn exclusively_connect_to_registered_parachain_nodes(mut self) -> Self {
        self.core_domain_nodes_exclusive = true;
        self
    }

    /// Make the node connect to the given core domain node.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_core_domain_node(mut self, node: &SystemDomainNode) -> Self {
        self.core_domain_nodes.push(node.addr.clone());
        self
    }

    /// Build a core payments domain node
    pub async fn build_core_payments_node(
        self,
        role: Role,
        mock_primary_node: &mut MockPrimaryNode,
        system_domain_node: &SystemDomainNode,
    ) -> CorePaymentsDomainNode {
        CoreDomainNode::build(
            DomainId::CORE_PAYMENTS,
            self.tokio_handle,
            self.key,
            self.base_path,
            self.core_domain_nodes,
            self.core_domain_nodes_exclusive,
            role,
            mock_primary_node,
            system_domain_node,
        )
        .await
    }
}

/// Core payments domain executor instance.
pub struct CorePaymentsDomainExecutorDispatch;

impl NativeExecutionDispatch for CorePaymentsDomainExecutorDispatch {
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        core_payments_domain_test_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        core_payments_domain_test_runtime::native_version()
    }
}

/// The core paymants domain node
pub type CorePaymentsDomainNode = CoreDomainNode<
    core_payments_domain_test_runtime::Runtime,
    core_payments_domain_test_runtime::RuntimeApi,
    CorePaymentsDomainExecutorDispatch,
>;
