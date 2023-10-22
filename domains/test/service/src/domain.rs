//! Utilities used for testing with the domain.
#![warn(missing_docs)]

use crate::chain_spec::create_domain_spec;
use crate::{construct_extrinsic_generic, node_config, EcdsaKeyring, UncheckedExtrinsicFor};
use domain_client_operator::{BootstrapResult, Bootstrapper, OperatorStreams};
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{Balance, DomainCoreApi};
use domain_service::providers::DefaultProvider;
use domain_service::FullClient;
use domain_test_primitives::OnchainStateApi;
use evm_domain_test_runtime;
use evm_domain_test_runtime::AccountId as AccountId20;
use fp_rpc::EthereumRuntimeRPCApi;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::pallet_prelude::BlockNumberFor;
use pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi;
use sc_client_api::HeaderBackend;
use sc_executor::NativeExecutionDispatch;
use sc_network::{NetworkService, NetworkStateInfo};
use sc_network_sync::SyncingService;
use sc_service::config::MultiaddrWithPeerId;
use sc_service::{BasePath, Role, RpcHandlers, TFullBackend, TaskManager};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, ConstructRuntimeApi, Metadata, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_core::{Decode, Encode, H256};
use sp_domains::DomainId;
use sp_messenger::messages::ChainId;
use sp_messenger::{MessengerApi, RelayerApi};
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::Dispatchable;
use sp_runtime::OpaqueExtrinsic;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::Nonce;
use subspace_test_service::MockConsensusNode;
use substrate_frame_rpc_system::AccountNonceApi;
use substrate_test_client::{
    BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};

/// Trait for convert keyring to account id
pub trait FromKeyring {
    /// Convert keyring to account id
    fn from_keyring(key: EcdsaKeyring) -> Self;
}

impl FromKeyring for AccountId20 {
    fn from_keyring(key: EcdsaKeyring) -> Self {
        key.to_account_id()
    }
}

/// The backend type used by the test service.
pub type Backend = TFullBackend<Block>;

type Client<RuntimeApi, ExecutorDispatch> = FullClient<Block, RuntimeApi, ExecutorDispatch>;

/// Domain executor for the test service.
pub type DomainOperator<RuntimeApi, ExecutorDispatch> = domain_service::DomainOperator<
    Block,
    CBlock,
    subspace_test_client::Client,
    RuntimeApi,
    ExecutorDispatch,
>;

/// A generic domain node instance used for testing.
pub struct DomainNode<Runtime, RuntimeApi, ExecutorDispatch, AccountId>
where
    RuntimeApi:
        ConstructRuntimeApi<Block, Client<RuntimeApi, ExecutorDispatch>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + RelayerApi<Block, NumberFor<Block>>,
    ExecutorDispatch: NativeExecutionDispatch + Send + Sync + 'static,
    AccountId: Encode + Decode + FromKeyring,
{
    /// The domain id
    pub domain_id: DomainId,
    // TODO: Make the signing scheme generic over domains, because Ecdsa only used in the EVM domain,
    // other (incoming) domains may use Sr25519
    /// The node's account key
    pub key: EcdsaKeyring,
    /// TaskManager's instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<Client<RuntimeApi, ExecutorDispatch>>,
    /// Client backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub code_executor: Arc<sc_executor::NativeElseWasmExecutor<ExecutorDispatch>>,
    /// Network service.
    pub network_service: Arc<NetworkService<Block, H256>>,
    /// Sync service.
    pub sync_service: Arc<SyncingService<Block>>,
    /// The `MultiaddrWithPeerId` to this node. This is useful if you want to pass it as "boot node"
    /// to other nodes.
    pub addr: MultiaddrWithPeerId,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: RpcHandlers,
    /// Domain oeprator.
    pub operator: DomainOperator<RuntimeApi, ExecutorDispatch>,
    /// Sink to the node's tx pool
    pub tx_pool_sink: TracingUnboundedSender<Vec<u8>>,
    _phantom_data: PhantomData<(Runtime, AccountId)>,
}

impl<Runtime, RuntimeApi, ExecutorDispatch, AccountId>
    DomainNode<Runtime, RuntimeApi, ExecutorDispatch, AccountId>
where
    Runtime: frame_system::Config<Hash = H256> + pallet_transaction_payment::Config + Send + Sync,
    Runtime::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + Send + Sync,
    crate::BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
    u64: From<BlockNumberFor<Runtime>>,
    RuntimeApi:
        ConstructRuntimeApi<Block, Client<RuntimeApi, ExecutorDispatch>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + DomainCoreApi<Block>
        + TaggedTransactionQueue<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + TransactionPaymentRuntimeApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>>
        + RelayerApi<Block, NumberFor<Block>>
        + OnchainStateApi<Block, AccountId, Balance>
        + EthereumRuntimeRPCApi<Block>,
    ExecutorDispatch: NativeExecutionDispatch + Send + Sync + 'static,
    AccountId: DeserializeOwned
        + Encode
        + Decode
        + Clone
        + Debug
        + Display
        + FromStr
        + Sync
        + Send
        + FromKeyring
        + 'static,
{
    #[allow(clippy::too_many_arguments)]
    async fn build(
        domain_id: DomainId,
        tokio_handle: tokio::runtime::Handle,
        key: EcdsaKeyring,
        base_path: BasePath,
        domain_nodes: Vec<MultiaddrWithPeerId>,
        domain_nodes_exclusive: bool,
        role: Role,
        mock_consensus_node: &mut MockConsensusNode,
    ) -> Self {
        let BootstrapResult {
            domain_instance_data,
            domain_created_at,
            imported_block_notification_stream,
        } = {
            let bootstrapper = Bootstrapper::<Block, _, _>::new(mock_consensus_node.client.clone());
            bootstrapper
                .fetch_domain_bootstrap_info(domain_id)
                .await
                .expect("Failed to get domain instance data")
        };
        let chain_spec = create_domain_spec(domain_instance_data.raw_genesis);
        let domain_config = node_config(
            domain_id,
            tokio_handle.clone(),
            key,
            domain_nodes,
            domain_nodes_exclusive,
            role.clone(),
            BasePath::new(base_path.path().join(format!("domain-{domain_id:?}"))),
            chain_spec,
        )
        .expect("could not generate domain node Configuration");

        let span = sc_tracing::tracing::info_span!(
            sc_tracing::logging::PREFIX_LOG_SPAN,
            name = domain_config.network.node_name.as_str()
        );
        let _enter = span.enter();

        let multiaddr = domain_config.network.listen_addresses[0].clone();

        let operator_streams = OperatorStreams {
            // Set `consensus_block_import_throttling_buffer_size` to 0 to ensure the primary chain will not be
            // ahead of the execution chain by more than one block, thus slot will not be skipped in test.
            consensus_block_import_throttling_buffer_size: 0,
            block_importing_notification_stream: mock_consensus_node
                .block_importing_notification_stream(),
            imported_block_notification_stream,
            new_slot_notification_stream: mock_consensus_node.new_slot_notification_stream(),
            acknowledgement_sender_stream: mock_consensus_node.new_acknowledgement_sender_stream(),
            _phantom: Default::default(),
        };

        let (domain_message_sink, domain_message_receiver) =
            tracing_unbounded("domain_message_channel", 100);
        let gossip_msg_sink = mock_consensus_node
            .xdm_gossip_worker_builder()
            .gossip_msg_sink();

        let domain_params = domain_service::DomainParams {
            domain_id,
            domain_config,
            domain_created_at,
            consensus_client: mock_consensus_node.client.clone(),
            consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(
                mock_consensus_node.transaction_pool.clone(),
            ),
            consensus_network_sync_oracle: mock_consensus_node.sync_service.clone(),
            operator_streams,
            gossip_message_sink: gossip_msg_sink,
            domain_message_receiver,
            provider: DefaultProvider,
        };

        let domain_node = domain_service::new_full::<
            _,
            _,
            _,
            _,
            _,
            _,
            RuntimeApi,
            ExecutorDispatch,
            AccountId,
            _,
        >(domain_params)
        .await
        .expect("failed to build domain node");

        let domain_service::NewFull {
            task_manager,
            client,
            backend,
            code_executor,
            network_service,
            sync_service,
            network_starter,
            rpc_handlers,
            operator,
            ..
        } = domain_node;

        if role.is_authority() {
            mock_consensus_node
                .xdm_gossip_worker_builder()
                .push_chain_tx_pool_sink(ChainId::Domain(domain_id), domain_message_sink.clone());
        }

        let addr = MultiaddrWithPeerId {
            multiaddr,
            peer_id: network_service.local_peer_id(),
        };

        network_starter.start_network();

        DomainNode {
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
            operator,
            tx_pool_sink: domain_message_sink,
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
            .account_nonce(
                self.client.info().best_hash,
                <AccountId as FromKeyring>::from_keyring(self.key),
            )
            .expect("Fail to get account nonce")
    }

    /// Sends an system.remark extrinsic to the pool.
    pub async fn send_system_remark(&mut self) {
        let nonce = self.account_nonce();
        let _ = self
            .construct_and_send_extrinsic(frame_system::Call::remark {
                remark: nonce.encode(),
            })
            .await
            .map(|_| ());
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
            0,
        );
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }

    /// Construct an extrinsic.
    pub fn construct_extrinsic(
        &mut self,
        nonce: u32,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> UncheckedExtrinsicFor<Runtime> {
        construct_extrinsic_generic::<Runtime, _>(&self.client, function, self.key, false, nonce, 0)
    }

    /// Construct an extrinsic with the given transaction tip.
    pub fn construct_extrinsic_with_tip(
        &mut self,
        nonce: u32,
        tip: u32,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> UncheckedExtrinsicFor<Runtime> {
        construct_extrinsic_generic::<Runtime, _>(
            &self.client,
            function,
            self.key,
            false,
            nonce,
            tip,
        )
    }

    /// Send an extrinsic to this node.
    pub async fn send_extrinsic(
        &self,
        extrinsic: impl Into<OpaqueExtrinsic>,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }

    /// Get the free balance of the given account
    pub fn free_balance(&self, account_id: AccountId) -> Balance {
        self.client
            .runtime_api()
            .free_balance(self.client.info().best_hash, account_id)
            .expect("Fail to get account free balance")
    }
}

/// A builder to create a [`DomainNode`].
pub struct DomainNodeBuilder {
    tokio_handle: tokio::runtime::Handle,
    key: EcdsaKeyring,
    domain_nodes: Vec<MultiaddrWithPeerId>,
    domain_nodes_exclusive: bool,
    base_path: BasePath,
}

impl DomainNodeBuilder {
    /// Create a new instance of `Self`.
    ///
    /// `tokio_handle` - The tokio handler to use.
    /// `key` - The key that will be used to generate the name.
    /// `base_path` - Where databases will be stored.
    pub fn new(
        tokio_handle: tokio::runtime::Handle,
        key: EcdsaKeyring,
        base_path: BasePath,
    ) -> Self {
        DomainNodeBuilder {
            key,
            tokio_handle,
            domain_nodes: Vec::new(),
            domain_nodes_exclusive: false,
            base_path,
        }
    }

    /// Instruct the node to exclusively connect to registered parachain nodes.
    ///
    /// Domain nodes can be registered using [`Self::connect_to_domain_node`].
    pub fn exclusively_connect_to_registered_parachain_nodes(mut self) -> Self {
        self.domain_nodes_exclusive = true;
        self
    }

    /// Make the node connect to the given domain node.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_domain_node(mut self, addr: MultiaddrWithPeerId) -> Self {
        self.domain_nodes.push(addr);
        self
    }

    /// Build a evm domain node
    pub async fn build_evm_node(
        self,
        role: Role,
        domain_id: DomainId,
        mock_consensus_node: &mut MockConsensusNode,
    ) -> EvmDomainNode {
        DomainNode::build(
            domain_id,
            self.tokio_handle,
            self.key,
            self.base_path,
            self.domain_nodes,
            self.domain_nodes_exclusive,
            role,
            mock_consensus_node,
        )
        .await
    }
}

/// Evm domain executor instance.
pub struct EVMDomainExecutorDispatch;

impl NativeExecutionDispatch for EVMDomainExecutorDispatch {
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        evm_domain_test_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        evm_domain_test_runtime::native_version()
    }
}

/// The evm domain node
pub type EvmDomainNode = DomainNode<
    evm_domain_test_runtime::Runtime,
    evm_domain_test_runtime::RuntimeApi,
    EVMDomainExecutorDispatch,
    AccountId20,
>;

/// The evm domain client
pub type EvmDomainClient = Client<evm_domain_test_runtime::RuntimeApi, EVMDomainExecutorDispatch>;
