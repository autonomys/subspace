use sc_chain_spec::ChainSpec;
use sc_network::config::{
    MultiaddrWithPeerId, NetworkConfiguration, NodeKeyConfig, SetConfig, SyncMode, TransportConfig,
    DEFAULT_KADEMLIA_REPLICATION_FACTOR,
};
use sc_service::config::{KeystoreConfig, OffchainWorkerConfig, PrometheusConfig};
use sc_service::{
    BasePath, BlocksPruning, Configuration, DatabaseSource, PruningMode, RpcMethods,
    TransactionPoolOptions,
};
use sc_telemetry::TelemetryEndpoints;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::runtime::Handle;

/// The default max request size in MB, copied from Substrate
pub const RPC_DEFAULT_MAX_REQUEST_SIZE_MB: u32 = 15;
/// The default max response size in MB, copied from Substrate
pub const RPC_DEFAULT_MAX_RESPONSE_SIZE_MB: u32 = 15;

/// Simplified RPC configuration used in Substrate
#[derive(Debug)]
pub struct SubstrateRpcConfiguration {
    /// IP and port (TCP) on which to listen for RPC requests.
    pub listen_on: SocketAddr,
    /// Maximum number of connections for JSON-RPC server.
    pub max_connections: u32,
    /// CORS settings for HTTP & WS servers. `None` if all origins are allowed.
    pub cors: Option<Vec<String>>,
    /// RPC methods to expose (by default only a safe subset or all of them).
    pub methods: RpcMethods,
    /// Maximum allowed subscriptions per rpc connection
    pub max_subscriptions_per_connection: u32,
}

/// Simplified network used in Substrate
#[derive(Debug)]
pub struct SubstrateNetworkConfiguration {
    /// Multiaddresses to listen for incoming connections.
    pub listen_on: Vec<sc_network::Multiaddr>,
    /// Multiaddresses to advertise. Detected automatically if empty.
    pub public_addresses: Vec<sc_network::Multiaddr>,
    /// List of initial node addresses
    pub bootstrap_nodes: Vec<MultiaddrWithPeerId>,
    /// The node key configuration, which determines the node's network identity keypair.
    pub node_key: NodeKeyConfig,
    /// Configuration for the default set of nodes used for block syncing and transactions.
    pub default_peers_set: SetConfig,
    /// Name of the node. Sent over the wire for debugging purposes.
    pub node_name: String,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses
    /// in Kademlia DHT.
    pub allow_private_ips: bool,
    /// Parameter that allows node to forcefully assume it is synced, needed for network
    /// bootstrapping only, as long as two synced nodes remain on the network at any time, this
    /// doesn't need to be used.
    pub force_synced: bool,
}

/// Simplified Substrate configuration that can be converted into [`Configuration`] using
/// [`From`]/[`Into`].
#[derive(Debug)]
pub struct SubstrateConfiguration {
    /// Implementation name
    pub impl_name: String,
    /// Implementation version
    pub impl_version: String,
    /// Operator
    pub operator: bool,
    /// Base path for node data
    pub base_path: PathBuf,
    /// Extrinsic pool configuration
    pub transaction_pool: TransactionPoolOptions,
    /// Network configuration
    pub network: SubstrateNetworkConfiguration,
    /// Keystore configuration
    pub keystore: KeystoreConfig,
    /// State pruning settings
    pub state_pruning: Option<PruningMode>,
    /// Number of blocks to keep in the db.
    ///
    /// NOTE: only finalized blocks are subject for removal!
    pub blocks_pruning: BlocksPruning,
    /// RPC configuration
    pub rpc_options: SubstrateRpcConfiguration,
    /// IP and port (TCP) to start Prometheus exporter on
    pub prometheus_listen_on: Option<SocketAddr>,
    /// Telemetry service URL. `None` if disabled.
    pub telemetry_endpoints: Option<TelemetryEndpoints>,
    /// Enable authoring even when offline
    pub force_authoring: bool,
    /// Chain specification
    pub chain_spec: Box<dyn ChainSpec>,
    /// Configuration of the output format that the informant uses.
    pub informant_output_format: sc_informant::OutputFormat,
}

impl From<SubstrateConfiguration> for Configuration {
    fn from(configuration: SubstrateConfiguration) -> Self {
        let default_peers_set_num_full = configuration.network.default_peers_set.in_peers
            + configuration.network.default_peers_set.out_peers;
        let client_version = format!("{}/{}", configuration.impl_name, configuration.impl_version);

        Self {
            impl_name: configuration.impl_name,
            impl_version: configuration.impl_version,
            tokio_handle: Handle::current(),
            transaction_pool: configuration.transaction_pool,
            network: NetworkConfiguration {
                net_config_path: None,
                listen_addresses: configuration.network.listen_on,
                public_addresses: configuration.network.public_addresses,
                boot_nodes: if !configuration.network.bootstrap_nodes.is_empty() {
                    configuration.network.bootstrap_nodes
                } else {
                    configuration.chain_spec.boot_nodes().to_vec()
                },
                node_key: configuration.network.node_key,
                default_peers_set: configuration.network.default_peers_set,
                default_peers_set_num_full,
                client_version,
                node_name: configuration.network.node_name,
                transport: TransportConfig::Normal {
                    enable_mdns: false,
                    allow_private_ip: configuration.network.allow_private_ips,
                },
                // Substrate's default
                max_parallel_downloads: 5,
                // Substrate's default
                max_blocks_per_request: 64,
                // Substrate's default, full mode
                sync_mode: SyncMode::Full,
                pause_sync: Arc::new(AtomicBool::new(false)),
                // Substrate's default
                enable_dht_random_walk: true,
                // Substrate's default
                allow_non_globals_in_dht: configuration.network.allow_private_ips,
                // Substrate's default
                kademlia_disjoint_query_paths: false,
                kademlia_replication_factor: NonZeroUsize::new(DEFAULT_KADEMLIA_REPLICATION_FACTOR)
                    .expect("value is a constant; constant is non-zero; qed"),
                ipfs_server: false,
                yamux_window_size: None,
                force_synced: configuration.network.force_synced,
            },
            // Not used on consensus chain
            keystore: configuration.keystore,
            database: DatabaseSource::ParityDb {
                path: configuration.base_path.join("db"),
            },
            data_path: configuration.base_path.clone(),
            // Substrate's default
            trie_cache_maximum_size: Some(64 * 1024 * 1024),
            state_pruning: configuration.state_pruning,
            blocks_pruning: configuration.blocks_pruning,
            wasm_method: Default::default(),
            wasm_runtime_overrides: None,
            rpc_addr: Some(configuration.rpc_options.listen_on),
            rpc_methods: configuration.rpc_options.methods,
            rpc_max_connections: configuration.rpc_options.max_connections,
            rpc_cors: configuration.rpc_options.cors,
            rpc_max_request_size: RPC_DEFAULT_MAX_REQUEST_SIZE_MB,
            rpc_max_response_size: RPC_DEFAULT_MAX_RESPONSE_SIZE_MB,
            rpc_id_provider: None,
            rpc_max_subs_per_conn: configuration.rpc_options.max_subscriptions_per_connection,
            // Doesn't matter since we have specified address above
            rpc_port: 0,
            prometheus_config: configuration
                .prometheus_listen_on
                .map(|prometheus_listen_on| {
                    PrometheusConfig::new_with_default_registry(
                        prometheus_listen_on,
                        configuration.chain_spec.id().to_string(),
                    )
                }),
            telemetry_endpoints: configuration.telemetry_endpoints,
            default_heap_pages: None,
            // Offchain worker is not used in Subspace
            offchain_worker: OffchainWorkerConfig {
                enabled: false,
                indexing_enabled: false,
            },
            force_authoring: configuration.force_authoring,
            disable_grandpa: true,
            dev_key_seed: None,
            tracing_targets: None,
            tracing_receiver: Default::default(),
            chain_spec: configuration.chain_spec,
            // Substrate's default
            max_runtime_instances: 8,
            // Substrate's default
            announce_block: true,
            role: if configuration.operator {
                sc_service::Role::Authority
            } else {
                sc_service::Role::Full
            },
            base_path: BasePath::new(configuration.base_path),
            informant_output_format: configuration.informant_output_format,
            // Substrate's default
            runtime_cache_size: 2,
        }
    }
}
