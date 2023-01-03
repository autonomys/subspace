// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Crate used for testing with Domain.

#![warn(missing_docs)]

pub mod chain_spec;

use domain_test_runtime::opaque::Block;
use domain_test_runtime::Hash;
use futures::StreamExt;
use sc_client_api::execution_extensions::ExecutionStrategies;
use sc_consensus_slots::SlotProportion;
use sc_network::{multiaddr, NetworkService, NetworkStateInfo};
use sc_network_common::config::{NonReservedPeerMode, TransportConfig};
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, NetworkConfiguration,
    OffchainWorkerConfig, PruningMode, WasmExecutionMethod,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration as ServiceConfiguration, Error as ServiceError,
    NetworkStarter, Role, RpcHandlers, TFullBackend, TFullClient, TaskManager,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnEssentialNamed;
use sp_core::H256;
use sp_keyring::Sr25519Keyring;
use sp_runtime::codec::Encode;
use sp_runtime::{generic, OpaqueExtrinsic};
use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_networking::libp2p::identity;
use subspace_runtime_primitives::opaque::Block as PBlock;
use subspace_service::{DsnConfig, SubspaceNetworking};
use substrate_test_client::{
    BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};

use cross_domain_message_gossip::GossipWorker;
use domain_service::{DomainConfiguration, FullPool};
pub use domain_test_runtime as runtime;
use sp_domains::DomainId;
pub use sp_keyring::Sr25519Keyring as Keyring;

/// The signature of the announce block fn.
pub type WrapAnnounceBlockFn = Arc<dyn Fn(Hash, Option<Vec<u8>>) + Send + Sync>;

/// The backend type used by the test service.
pub type Backend = TFullBackend<Block>;

/// Code executor for the test service.
pub type CodeExecutor = sc_executor::NativeElseWasmExecutor<RuntimeExecutor>;

/// Secondary executor for the test service.
pub type Executor = domain_client_executor::SystemExecutor<
    Block,
    PBlock,
    Client,
    subspace_test_client::Client,
    FullPool<PBlock, subspace_test_client::Client, runtime::RuntimeApi, RuntimeExecutor>,
    Backend,
    CodeExecutor,
>;

/// Native executor instance.
pub struct RuntimeExecutor;

impl sc_executor::NativeExecutionDispatch for RuntimeExecutor {
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        domain_test_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        domain_test_runtime::native_version()
    }
}

/// The client type being used by the test service.
pub type Client =
    TFullClient<Block, runtime::RuntimeApi, sc_executor::NativeElseWasmExecutor<RuntimeExecutor>>;

/// Start an executor with the given secondary chain `Configuration` and primary chain `Configuration`.
///
/// A primary chain full node and secondary chain node will be started, similar to the behaviour in
/// the production.
#[sc_tracing::logging::prefix_logs_with(secondary_chain_config.network.node_name.as_str())]
async fn run_executor(
    secondary_chain_config: ServiceConfiguration,
    primary_chain_config: ServiceConfiguration,
) -> sc_service::error::Result<(
    TaskManager,
    Arc<Client>,
    Arc<Backend>,
    Arc<CodeExecutor>,
    Arc<NetworkService<Block, H256>>,
    RpcHandlers,
    Executor,
)> {
    let primary_chain_full_node = {
        let span = tracing::info_span!(
            sc_tracing::logging::PREFIX_LOG_SPAN,
            name = primary_chain_config.network.node_name.as_str()
        );
        let _enter = span.enter();

        let primary_chain_config = subspace_service::SubspaceConfiguration {
            base: primary_chain_config,
            // Always enable the slot notification.
            force_new_slot_notifications: true,
            subspace_networking: SubspaceNetworking::Create {
                config: DsnConfig {
                    listen_on: vec!["/ip4/127.0.0.1/tcp/0"
                        .parse()
                        .expect("Correct multiaddr; qed")],
                    bootstrap_nodes: vec![],
                    reserved_peers: vec![],
                    keypair: identity::Keypair::generate_ed25519(),
                    allow_non_global_addresses_in_dht: true,
                },
                piece_cache_size: 1024 * 1024 * 1024,
            },
            segment_publish_concurrency: NonZeroUsize::new(10).unwrap(),
        };

        let partial_components = subspace_service::new_partial::<
            subspace_test_runtime::RuntimeApi,
            subspace_test_client::TestExecutorDispatch,
        >(&primary_chain_config)
        .map_err(|e| {
            sc_service::Error::Other(format!("Failed to build a full subspace node: {e:?}"))
        })?;

        subspace_service::new_full(
            primary_chain_config,
            partial_components,
            false,
            SlotProportion::new(98f32 / 100f32),
        )
        .await
        .map_err(|e| {
            sc_service::Error::Other(format!("Failed to build a full subspace node: {e:?}"))
        })?
    };

    let (gossip_msg_sink, gossip_msg_stream) =
        sc_utils::mpsc::tracing_unbounded("Cross domain gossip messages");
    let secondary_chain_config = DomainConfiguration {
        service_config: secondary_chain_config,
        maybe_relayer_id: None,
    };
    let block_import_throttling_buffer_size = 10;
    let secondary_chain_node = domain_service::new_full::<
        _,
        _,
        _,
        _,
        _,
        domain_test_runtime::RuntimeApi,
        RuntimeExecutor,
    >(
        secondary_chain_config,
        primary_chain_full_node.client.clone(),
        primary_chain_full_node.backend.clone(),
        primary_chain_full_node.network.clone(),
        &primary_chain_full_node.select_chain,
        primary_chain_full_node
            .imported_block_notification_stream
            .subscribe()
            .then(|imported_block_notification| async move {
                (
                    imported_block_notification.block_number,
                    imported_block_notification.fork_choice,
                    imported_block_notification.block_import_acknowledgement_sender,
                )
            }),
        primary_chain_full_node
            .new_slot_notification_stream
            .subscribe()
            .then(|slot_notification| async move {
                (
                    slot_notification.new_slot_info.slot,
                    slot_notification.new_slot_info.global_challenge,
                )
            }),
        block_import_throttling_buffer_size,
        gossip_msg_sink,
    )
    .await?;

    let domain_service::NewFull {
        mut task_manager,
        client,
        backend,
        code_executor,
        network,
        network_starter,
        rpc_handlers,
        executor,
        tx_pool_sink,
    } = secondary_chain_node;

    let mut domain_tx_pool_sinks = BTreeMap::new();
    domain_tx_pool_sinks.insert(DomainId::SYSTEM, tx_pool_sink);
    let cross_domain_message_gossip_worker =
        GossipWorker::<Block>::new(network.clone(), domain_tx_pool_sinks);

    task_manager
        .spawn_essential_handle()
        .spawn_essential_blocking(
            "cross-domain-gossip-message-worker",
            None,
            Box::pin(cross_domain_message_gossip_worker.run(gossip_msg_stream)),
        );

    task_manager.add_child(primary_chain_full_node.task_manager);

    network_starter.start_network();

    primary_chain_full_node.network_starter.start_network();

    Ok((
        task_manager,
        client,
        backend,
        code_executor,
        network,
        rpc_handlers,
        executor,
    ))
}

/// A Cumulus test node instance used for testing.
pub struct TestNode {
    /// TaskManager's instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<Client>,
    /// Client backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub code_executor: Arc<CodeExecutor>,
    /// Node's network.
    pub network: Arc<NetworkService<Block, H256>>,
    /// The `MultiaddrWithPeerId` to this node. This is useful if you want to pass it as "boot node"
    /// to other nodes.
    pub addr: MultiaddrWithPeerId,
    /// RPCHandlers to make RPC queries.
    pub rpc_handlers: RpcHandlers,
    /// Secondary executor.
    pub executor: Executor,
}

/// A builder to create a [`TestNode`].
pub struct TestNodeBuilder {
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    secondary_nodes: Vec<MultiaddrWithPeerId>,
    secondary_nodes_exclusive: bool,
    primary_nodes: Vec<MultiaddrWithPeerId>,
    base_path: BasePath,
}

impl TestNodeBuilder {
    /// Create a new instance of `Self`.
    ///
    /// `para_id` - The parachain id this node is running for.
    /// `tokio_handle` - The tokio handler to use.
    /// `key` - The key that will be used to generate the name.
    /// `base_path` - Where databases will be stored.
    pub fn new(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> Self {
        TestNodeBuilder {
            key,
            tokio_handle,
            secondary_nodes: Vec::new(),
            secondary_nodes_exclusive: false,
            primary_nodes: Vec::new(),
            base_path,
        }
    }

    /// Instruct the node to exclusively connect to registered parachain nodes.
    ///
    /// Parachain nodes can be registered using [`Self::connect_to_secondary_chain_node`] and
    /// [`Self::connect_to_secondary_chain_nodes`].
    pub fn exclusively_connect_to_registered_parachain_nodes(mut self) -> Self {
        self.secondary_nodes_exclusive = true;
        self
    }

    /// Make the node connect to the given secondary chain node.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_secondary_chain_node(mut self, node: &TestNode) -> Self {
        self.secondary_nodes.push(node.addr.clone());
        self
    }

    /// Make the node connect to the given secondary chain nodes.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_secondary_chain_nodes<'a>(
        mut self,
        nodes: impl Iterator<Item = &'a TestNode>,
    ) -> Self {
        self.secondary_nodes.extend(nodes.map(|n| n.addr.clone()));
        self
    }

    /// Make the node connect to the given primary chain node.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_primary_chain_node(
        mut self,
        node: &subspace_test_service::PrimaryTestNode,
    ) -> Self {
        self.primary_nodes.push(node.addr.clone());
        self
    }

    /// Make the node connect to the given primary chain nodes.
    ///
    /// By default the node will not be connected to any node or will be able to discover any other
    /// node.
    pub fn connect_to_primary_chain_nodes<'a>(
        mut self,
        nodes: impl IntoIterator<Item = &'a subspace_test_service::PrimaryTestNode>,
    ) -> Self {
        self.primary_nodes
            .extend(nodes.into_iter().map(|n| n.addr.clone()));
        self
    }

    /// Build the [`TestNode`].
    pub async fn build(
        self,
        role: Role,
        primary_force_authoring: bool,
        primary_force_synced: bool,
    ) -> TestNode {
        let secondary_chain_config = node_config(
            self.tokio_handle.clone(),
            self.key,
            self.secondary_nodes,
            self.secondary_nodes_exclusive,
            role,
            BasePath::new(self.base_path.path().join("secondary")),
        )
        .expect("could not generate secondary chain node Configuration");

        let mut primary_chain_config = subspace_test_service::node_config(
            self.tokio_handle,
            self.key,
            self.primary_nodes,
            false,
            primary_force_authoring,
            primary_force_synced,
            BasePath::new(self.base_path.path().join("primary")),
        );

        primary_chain_config.network.node_name =
            format!("{} (PrimaryChain)", primary_chain_config.network.node_name);

        let multiaddr = secondary_chain_config.network.listen_addresses[0].clone();
        let (task_manager, client, backend, code_executor, network, rpc_handlers, executor) =
            run_executor(secondary_chain_config, primary_chain_config)
                .await
                .expect("could not start secondary chain node");

        let peer_id = network.local_peer_id();
        let addr = MultiaddrWithPeerId { multiaddr, peer_id };

        TestNode {
            task_manager,
            client,
            backend,
            code_executor,
            network,
            addr,
            rpc_handlers,
            executor,
        }
    }
}

/// Create a secondary chain node `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide nodes if you want the
/// node to be connected to other nodes. If `nodes_exclusive` is `true`, the node will only connect
/// to the given `nodes` and not to any other node.
pub fn node_config(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    nodes: Vec<MultiaddrWithPeerId>,
    nodes_exclusive: bool,
    role: Role,
    base_path: BasePath,
) -> Result<ServiceConfiguration, ServiceError> {
    let root = base_path.path().to_path_buf();
    let key_seed = key.to_seed();

    let spec = Box::new(chain_spec::get_chain_spec());

    let mut network_config = NetworkConfiguration::new(
        format!("{} (SecondaryChain)", key_seed),
        "network/test/0.1",
        Default::default(),
        None,
    );

    if nodes_exclusive {
        network_config.default_peers_set.reserved_nodes = nodes;
        network_config.default_peers_set.non_reserved_mode = NonReservedPeerMode::Deny;
    } else {
        network_config.boot_nodes = nodes;
    }

    network_config.allow_non_globals_in_dht = true;

    network_config
        .listen_addresses
        .push(multiaddr::Protocol::Memory(rand::random()).into());

    network_config.transport = TransportConfig::MemoryOnly;

    Ok(ServiceConfiguration {
        impl_name: "domain-test-node".to_string(),
        impl_version: "0.1".to_string(),
        role,
        tokio_handle,
        transaction_pool: Default::default(),
        network: network_config,
        keystore: KeystoreConfig::InMemory,
        keystore_remote: Default::default(),
        database: DatabaseSource::ParityDb {
            path: root.join("paritydb"),
        },
        trie_cache_maximum_size: Some(16 * 1024 * 1024),
        state_pruning: Some(PruningMode::ArchiveAll),
        blocks_pruning: BlocksPruning::KeepAll,
        chain_spec: spec,
        wasm_method: WasmExecutionMethod::Interpreted,
        // NOTE: we enforce the use of the native runtime to make the errors more debuggable
        execution_strategies: ExecutionStrategies {
            syncing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            importing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            block_construction: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            offchain_worker: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            other: sc_client_api::ExecutionStrategy::NativeWhenPossible,
        },
        rpc_http: None,
        rpc_ws: None,
        rpc_ipc: None,
        rpc_ws_max_connections: None,
        rpc_cors: None,
        rpc_methods: Default::default(),
        rpc_max_payload: None,
        rpc_max_request_size: None,
        rpc_max_response_size: None,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: None,
        ws_max_out_buffer_capacity: None,
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: OffchainWorkerConfig {
            enabled: true,
            indexing_enabled: false,
        },
        force_authoring: false,
        disable_grandpa: false,
        dev_key_seed: Some(key_seed),
        tracing_targets: None,
        tracing_receiver: Default::default(),
        max_runtime_instances: 8,
        announce_block: true,
        base_path: Some(base_path),
        informant_output_format: Default::default(),
        wasm_runtime_overrides: None,
        runtime_cache_size: 2,
    })
}

impl TestNode {
    /// Wait for `count` blocks to be imported in the node and then exit. This function will not
    /// return if no blocks are ever created, thus you should restrict the maximum amount of time of
    /// the test execution.
    pub fn wait_for_blocks(&self, count: usize) -> impl Future<Output = ()> {
        self.client.wait_for_blocks(count)
    }

    /// Construct and send an extrinsic to this node.
    pub async fn construct_and_send_extrinsic(
        &self,
        function: impl Into<runtime::RuntimeCall>,
        caller: Sr25519Keyring,
        immortal: bool,
        nonce: u32,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        let extrinsic = construct_extrinsic(&self.client, function, caller, immortal, nonce);

        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }

    /// Send an extrinsic to this node.
    pub async fn send_extrinsic(
        &self,
        extrinsic: impl Into<OpaqueExtrinsic>,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }
}

/// Construct an extrinsic that can be applied to the test runtime.
pub fn construct_extrinsic(
    client: &Client,
    function: impl Into<runtime::RuntimeCall>,
    caller: Sr25519Keyring,
    immortal: bool,
    nonce: u32,
) -> runtime::UncheckedExtrinsic {
    let function = function.into();
    let current_block_hash = client.info().best_hash;
    let current_block = client.info().best_number.saturated_into();
    let genesis_block = client.hash(0).unwrap().unwrap();
    let period = runtime::BlockHashCount::get()
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2) as u64;
    let tip = 0;
    let extra: runtime::SignedExtra = (
        frame_system::CheckNonZeroSender::<runtime::Runtime>::new(),
        frame_system::CheckSpecVersion::<runtime::Runtime>::new(),
        frame_system::CheckTxVersion::<runtime::Runtime>::new(),
        frame_system::CheckGenesis::<runtime::Runtime>::new(),
        frame_system::CheckMortality::<runtime::Runtime>::from(if immortal {
            generic::Era::Immortal
        } else {
            generic::Era::mortal(period, current_block)
        }),
        frame_system::CheckNonce::<runtime::Runtime>::from(nonce),
        frame_system::CheckWeight::<runtime::Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<runtime::Runtime>::from(tip),
    );
    let raw_payload = runtime::SignedPayload::from_raw(
        function.clone(),
        extra.clone(),
        (
            (),
            runtime::VERSION.spec_version,
            runtime::VERSION.transaction_version,
            genesis_block,
            current_block_hash,
            (),
            (),
            (),
        ),
    );
    let signature = raw_payload.using_encoded(|e| caller.sign(e));
    runtime::UncheckedExtrinsic::new_signed(
        function,
        subspace_test_runtime::Address::Id(caller.public().into()),
        runtime::Signature::Sr25519(signature),
        extra,
    )
}

/// Run a primary-chain validator node without the executor functionality.
///
/// This is essentially a wrapper around
/// [`run_validator_node`](subspace_test_service::run_validator_node).
pub async fn run_primary_chain_validator_node(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    base_path: BasePath,
) -> (subspace_test_service::PrimaryTestNode, NetworkStarter) {
    subspace_test_service::run_validator_node(
        tokio_handle,
        key,
        boot_nodes,
        true,
        true,
        true,
        base_path,
    )
    .await
}
