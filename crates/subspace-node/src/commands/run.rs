mod substrate;

use crate::cli::SubspaceCliPlaceholder;
use crate::commands::run::substrate::{parse_cors, Cors};
use crate::domain::{DomainCli, DomainInstanceStarter};
use crate::{chain_spec, derive_pot_external_entropy, set_default_ss58_version, Error, PosTable};
use clap::Parser;
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_client_operator::Bootstrapper;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use futures::FutureExt;
use sc_cli::{
    generate_node_name, print_node_infos, NodeKeyParams, NodeKeyType, PruningParams, RpcMethods,
    Signals, TelemetryParams, TransactionPoolParams, RPC_DEFAULT_MAX_CONNECTIONS,
    RPC_DEFAULT_MAX_REQUEST_SIZE_MB, RPC_DEFAULT_MAX_RESPONSE_SIZE_MB,
    RPC_DEFAULT_MAX_SUBS_PER_CONN, RPC_DEFAULT_PORT,
};
use sc_consensus_slots::SlotProportion;
use sc_informant::OutputFormat;
use sc_network::config::{
    MultiaddrWithPeerId, NetworkConfiguration, NonReservedPeerMode, SetConfig, TransportConfig,
    DEFAULT_KADEMLIA_REPLICATION_FACTOR,
};
use sc_service::config::{KeystoreConfig, OffchainWorkerConfig, PrometheusConfig};
use sc_service::{BasePath, Configuration, DatabaseSource};
use sc_storage_monitor::{StorageMonitorParams, StorageMonitorService};
use sc_subspace_chain_specs::ConsensusChainSpec;
use sc_telemetry::TelemetryEndpoints;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_core::traits::SpawnEssentialNamed;
use sp_messenger::messages::ChainId;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_networking::libp2p::Multiaddr;
use subspace_runtime::{Block, ExecutorDispatch, RuntimeApi};
use subspace_service::{DsnConfig, SubspaceConfiguration, SubspaceNetworking};
use tokio::runtime::Handle;
use tracing::{debug, error, info_span, warn, Span};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

fn parse_pot_external_entropy(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

fn parse_timekeeper_cpu_cores(
    s: &str,
) -> Result<HashSet<usize>, Box<dyn std::error::Error + Send + Sync>> {
    if s.is_empty() {
        return Ok(HashSet::new());
    }

    let mut cpu_cores = HashSet::new();
    for s in s.split(',') {
        let mut parts = s.split('-');
        let range_start = parts
            .next()
            .ok_or("Bad string format, must be comma separated list of CPU cores or ranges")?
            .parse()?;
        if let Some(range_end) = parts.next() {
            let range_end = range_end.parse()?;

            cpu_cores.extend(range_start..=range_end);
        } else {
            cpu_cores.insert(range_start);
        }
    }

    Ok(cpu_cores)
}

/// Options for running a node
#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Base path where to store node files.
    ///
    /// Required unless --dev mode is used.
    #[arg(long)]
    base_path: Option<PathBuf>,

    /// Specify the chain specification.
    ///
    /// It can be one of the predefined ones (dev) or it can be a path to a file with the chainspec
    /// (such as one exported by the `build-spec` subcommand).
    #[arg(long)]
    chain: Option<String>,

    /// Enable farmer mode.
    ///
    /// Node will support farmer connections for block and vote production, implies
    /// `--rpc-listen-on 127.0.0.1:9944` unless `--rpc-listen-on` is specified explicitly.
    #[arg(long)]
    farmer: bool,

    /// Enable development mode.
    ///
    /// Implies following flags (unless customized):
    /// * `--chain dev` (unless specified explicitly)
    /// * `--farmer`
    /// * `--tmp` (unless `--base-path` specified explicitly)
    /// * `--force-synced`
    /// * `--force-authoring`
    /// * `--allow-private-ips`
    /// * `--rpc-cors all` (unless specified explicitly)
    /// * `--dsn-disable-bootstrap-on-start`
    /// * `--timekeeper`
    #[arg(long, verbatim_doc_comment)]
    dev: bool,

    /// Run a temporary node.
    ///
    /// This will create a temporary directory for storing node data that will be deleted at the
    /// end of the process.
    #[arg(long)]
    tmp: bool,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions,

    /// The human-readable name for this node.
    ///
    /// It's used as network node name and in telemetry. Auto-generated if not specified explicitly.
    #[arg(long)]
    name: Option<String>,

    /// Options for telemetry
    #[clap(flatten)]
    telemetry_params: TelemetryParams,

    /// IP and port (TCP) to start Prometheus exporter on
    #[clap(long)]
    prometheus_listen_on: Option<SocketAddr>,

    /// Options for chain database pruning
    #[clap(flatten)]
    pruning_params: PruningParams,

    /// Options for Substrate networking
    #[clap(flatten)]
    network_options: SubstrateNetworkOptions,

    /// Options for transaction pool
    #[clap(flatten)]
    pool_config: TransactionPoolParams,

    /// Parameter that allows node to forcefully assume it is synced, needed for network
    /// bootstrapping only, as long as two synced nodes remain on the network at any time, this
    /// doesn't need to be used.
    ///
    /// --dev mode enables this option automatically.
    #[clap(long)]
    force_synced: bool,

    /// Enable authoring even when offline, needed for network bootstrapping only.
    #[arg(long)]
    force_authoring: bool,

    /// External entropy, used initially when PoT chain starts to derive the first seed
    #[arg(long, value_parser = parse_pot_external_entropy)]
    pot_external_entropy: Option<Vec<u8>>,

    /// Options for DSN
    #[clap(flatten)]
    dsn_options: DsnOptions,

    /// Enables DSN-sync on startup.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    sync_from_dsn: bool,

    /// Parameters used to create the storage monitor.
    #[clap(flatten)]
    storage_monitor: StorageMonitorParams,

    #[clap(flatten)]
    timekeeper_options: TimekeeperOptions,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    domain_args: Vec<String>,
}

/// Options for RPC
#[derive(Debug, Parser)]
struct RpcOptions {
    /// IP and port (TCP) on which to listen for RPC requests, if not specified RPC server isn't running.
    ///
    /// Note: not all RPC methods are safe to be exposed publicly. Use an RPC proxy server to filter out
    /// dangerous methods.
    /// More details: <https://docs.substrate.io/main-docs/build/custom-rpc/#public-rpcs>.
    #[arg(long, default_value_t = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        RPC_DEFAULT_PORT,
    ))]
    rpc_listen_on: SocketAddr,

    /// RPC methods to expose.
    /// - `unsafe`: Exposes every RPC method.
    /// - `safe`: Exposes only a safe subset of RPC methods, denying unsafe RPC methods.
    /// - `auto`: Acts as `safe` if non-localhost `--rpc-listen-on` is passed, otherwise
    ///           acts as `unsafe`.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        default_value_t = RpcMethods::Auto,
        verbatim_doc_comment
    )]
    rpc_methods: RpcMethods,

    /// Set the the maximum concurrent subscriptions per connection.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_SUBS_PER_CONN)]
    rpc_max_subscriptions_per_connection: u32,

    /// Maximum number of RPC server connections.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_CONNECTIONS)]
    rpc_max_connections: u32,

    /// Specify browser Origins allowed to access the HTTP & WS RPC servers.
    /// A comma-separated list of origins (protocol://domain or special `null`
    /// value). Value of `all` will disable origin validation. Default is to
    /// allow localhost and <https://polkadot.js.org> origins. When running in
    /// --dev mode the default is to allow all origins.
    #[arg(long, value_parser = parse_cors)]
    rpc_cors: Option<Cors>,
}

/// Options for Substrate networking
#[derive(Debug, Parser)]
struct SubstrateNetworkOptions {
    /// Specify a list of bootstrap nodes for Substrate networking stack.
    #[arg(long)]
    bootstrap_nodes: Vec<MultiaddrWithPeerId>,

    /// Specify a list of reserved node addresses.
    #[arg(long)]
    reserved_nodes: Vec<MultiaddrWithPeerId>,

    /// Whether to only synchronize the chain with reserved nodes.
    ///
    /// TCP connections might still be established with non-reserved nodes.
    /// In particular, if you are a farmer your node might still connect to other farmer nodes
    /// regardless of whether they are defined as reserved nodes.
    #[arg(long)]
    reserved_only: bool,

    /// The public address that other nodes will use to connect to it.
    ///
    /// This can be used if there's a proxy in front of this node or if address is known beforehand
    /// and less reliable auto-discovery can be avoided.
    #[arg(long)]
    public_addr: Vec<sc_network::Multiaddr>,

    /// Listen on this multiaddress
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30333")]
    listen_on: Vec<sc_network::Multiaddr>,

    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses
    /// in Kademlia DHT.
    #[arg(long, default_value_t = false)]
    allow_private_ips: bool,

    /// Specify the number of outgoing connections we're trying to maintain.
    #[arg(long, default_value_t = 8)]
    out_peers: u32,

    /// Maximum number of inbound full nodes peers.
    #[arg(long, default_value_t = 32)]
    in_peers: u32,

    /// The secret key to use for Substrate networking.
    ///
    /// The value is parsed as a hex-encoded Ed25519 32 byte secret key, i.e. 64 hex characters.
    ///
    /// This will override previously generated node key if there was any.
    /// Use of this option should be limited to development and testing, otherwise generate and use
    /// `network/secret_ed25519` file in node directory.
    #[arg(long, value_name = "KEY")]
    node_key: Option<String>,
}

/// Options for DSN
#[derive(Debug, Parser)]
struct DsnOptions {
    /// Where local DSN node will listen for incoming connections.
    // TODO: Add more DSN-related parameters
    #[arg(long, default_values_t = [
        "/ip4/0.0.0.0/udp/30433/quic-v1".parse::<Multiaddr>().expect("Statically correct; qed"),
        "/ip4/0.0.0.0/tcp/30433".parse::<Multiaddr>().expect("Statically correct; qed"),
    ])]
    dsn_listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    #[arg(long)]
    dsn_bootstrap_nodes: Vec<Multiaddr>,

    /// Reserved peers for DSN.
    #[arg(long)]
    dsn_reserved_peers: Vec<Multiaddr>,

    /// Defines max established incoming connection limit for DSN.
    #[arg(long, default_value_t = 50)]
    dsn_in_connections: u32,

    /// Defines max established outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    dsn_out_connections: u32,

    /// Defines max pending incoming connection limit for DSN.
    #[arg(long, default_value_t = 100)]
    dsn_pending_in_connections: u32,

    /// Defines max pending outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    dsn_pending_out_connections: u32,

    /// Defines whether we should run blocking Kademlia bootstrap() operation before other requests.
    #[arg(long, default_value_t = false)]
    dsn_disable_bootstrap_on_start: bool,

    /// Known external addresses
    #[arg(long, alias = "dsn-external-address")]
    dsn_external_addresses: Vec<Multiaddr>,
}

/// Options for timekeeper
#[derive(Debug, Parser)]
struct TimekeeperOptions {
    /// Assigned PoT role for this node.
    #[arg(long)]
    timekeeper: bool,

    /// CPU cores that timekeeper can use.
    ///
    /// At least 2 cores should be provided, if more cores than necessary are provided, random cores
    /// out of provided will be utilized, if not enough cores are provided timekeeper may occupy
    /// random CPU cores.
    ///
    /// Comma separated list of individual cores or ranges of cores.
    ///
    /// Examples:
    /// * `0,1` - use cores 0 and 1
    /// * `0-3` - use cores 0, 1, 2 and 3
    /// * `0,1,6-7` - use cores 0, 1, 6 and 7
    #[arg(long, default_value = "", value_parser = parse_timekeeper_cpu_cores, verbatim_doc_comment)]
    timekeeper_cpu_cores: HashSet<usize>,
}

fn raise_fd_limit() {
    match fdlimit::raise_fd_limit() {
        Ok(fdlimit::Outcome::LimitRaised { from, to }) => {
            debug!(
                "Increased file descriptor limit from previous (most likely soft) limit {} to \
                new (most likely hard) limit {}",
                from, to
            );
        }
        Ok(fdlimit::Outcome::Unsupported) => {
            // Unsupported platform (non-Linux)
        }
        Err(error) => {
            warn!(
                "Failed to increase file descriptor limit for the process due to an error: {}.",
                error
            );
        }
    }
}

/// Default run command for node
#[tokio::main]
pub async fn run(run_options: RunOptions) -> Result<(), Error> {
    // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214, also on
    //  Windows terminal doesn't support the same colors as bash does
    let enable_color = if cfg!(windows) {
        false
    } else {
        supports_color::on(supports_color::Stream::Stderr).is_some()
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer().with_ansi(enable_color).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .init();
    raise_fd_limit();

    let signals = Signals::capture()?;

    let RunOptions {
        base_path,
        mut chain,
        mut farmer,
        dev,
        mut tmp,
        rpc_options,
        name,
        telemetry_params,
        prometheus_listen_on,
        pruning_params,
        mut network_options,
        pool_config,
        mut force_synced,
        mut force_authoring,
        pot_external_entropy,
        mut dsn_options,
        sync_from_dsn,
        storage_monitor,
        mut timekeeper_options,
        domain_args,
    } = run_options;

    let transaction_pool;
    let rpc_cors;
    // Development mode handling is limited to this section
    {
        if dev {
            if chain.is_none() {
                chain = Some("dev".to_string());
            }
            farmer = true;
            tmp = true;
            force_synced = true;
            force_authoring = true;
            network_options.allow_private_ips = true;
            dsn_options.dsn_disable_bootstrap_on_start = true;
            timekeeper_options.timekeeper = true;
        }

        transaction_pool = pool_config.transaction_pool(dev);
        rpc_cors = rpc_options.rpc_cors.unwrap_or_else(|| {
            if dev {
                warn!("Running in --dev mode, RPC CORS has been disabled.");
                Cors::All
            } else {
                Cors::List(vec![
                    "http://localhost:*".into(),
                    "http://127.0.0.1:*".into(),
                    "https://localhost:*".into(),
                    "https://127.0.0.1:*".into(),
                    "https://polkadot.js.org".into(),
                ])
            }
        });
    }

    let chain_spec = match chain.as_deref() {
        Some("gemini-3g-compiled") => chain_spec::gemini_3g_compiled()?,
        Some("gemini-3g") => chain_spec::gemini_3g_config()?,
        Some("devnet") => chain_spec::devnet_config()?,
        Some("devnet-compiled") => chain_spec::devnet_config_compiled()?,
        Some("dev") => chain_spec::dev_config()?,
        Some(path) => ConsensusChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        None => {
            return Err(Error::Other(
                "Chain must be provided unless --dev mode is used".to_string(),
            ));
        }
    };
    let mut maybe_tmp_dir = None;
    let base_path = match base_path {
        Some(base_path) => base_path,
        None => {
            if tmp {
                let tmp = tempfile::Builder::new()
                    .prefix("subspace-node-")
                    .tempdir()
                    .map_err(|error| {
                        Error::Other(format!(
                            "Failed to create temporary directory for node: {error}"
                        ))
                    })?;

                maybe_tmp_dir.insert(tmp).path().to_path_buf()
            } else {
                return Err(Error::Other("--base-path is required".to_string()));
            }
        }
    };
    let net_config_path = base_path.join("network");

    let consensus_chain_config = Configuration {
        impl_name: env!("CARGO_PKG_NAME").to_string(),
        impl_version: env!("CARGO_PKG_VERSION").to_string(),
        tokio_handle: Handle::current(),
        transaction_pool,
        network: NetworkConfiguration {
            net_config_path: Some(net_config_path.clone()),
            listen_addresses: network_options.listen_on,
            public_addresses: network_options.public_addr,
            boot_nodes: if !network_options.bootstrap_nodes.is_empty() {
                network_options.bootstrap_nodes
            } else {
                chain_spec.boot_nodes().to_vec()
            },
            node_key: {
                let node_key_params = NodeKeyParams {
                    node_key: network_options.node_key,
                    node_key_type: NodeKeyType::Ed25519,
                    node_key_file: None,
                };

                node_key_params.node_key(&net_config_path)?
            },
            default_peers_set: SetConfig {
                in_peers: network_options.in_peers,
                out_peers: network_options.out_peers,
                reserved_nodes: network_options.reserved_nodes,
                non_reserved_mode: if network_options.reserved_only {
                    NonReservedPeerMode::Deny
                } else {
                    NonReservedPeerMode::Accept
                },
            },
            default_peers_set_num_full: network_options.in_peers + network_options.out_peers,
            client_version: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            node_name: name.unwrap_or_else(generate_node_name),
            transport: TransportConfig::Normal {
                enable_mdns: false,
                allow_private_ip: network_options.allow_private_ips,
            },
            // Substrate's default
            max_parallel_downloads: 5,
            // Substrate's default
            max_blocks_per_request: 64,
            // Substrate's default, full mode
            sync_mode: Arc::default(),
            // Substrate's default
            enable_dht_random_walk: true,
            // Substrate's default
            allow_non_globals_in_dht: network_options.allow_private_ips,
            // Substrate's default
            kademlia_disjoint_query_paths: false,
            kademlia_replication_factor: NonZeroUsize::new(DEFAULT_KADEMLIA_REPLICATION_FACTOR)
                .expect("value is a constant; constant is non-zero; qed"),
            ipfs_server: false,
            yamux_window_size: None,
            force_synced,
        },
        // Not used on consensus chain
        keystore: KeystoreConfig::InMemory,
        database: DatabaseSource::ParityDb {
            path: base_path.join("db"),
        },
        data_path: base_path.clone(),
        // Substrate's default
        trie_cache_maximum_size: Some(64 * 1024 * 1024),
        state_pruning: pruning_params.state_pruning()?,
        blocks_pruning: pruning_params.blocks_pruning()?,
        wasm_method: Default::default(),
        wasm_runtime_overrides: None,
        rpc_addr: Some(rpc_options.rpc_listen_on),
        rpc_methods: match rpc_options.rpc_methods {
            RpcMethods::Auto => {
                if rpc_options.rpc_listen_on.ip().is_loopback() {
                    sc_service::RpcMethods::Unsafe
                } else {
                    sc_service::RpcMethods::Safe
                }
            }
            RpcMethods::Safe => sc_service::RpcMethods::Safe,
            RpcMethods::Unsafe => sc_service::RpcMethods::Unsafe,
        },
        rpc_max_connections: rpc_options.rpc_max_connections,
        rpc_cors: rpc_cors.into(),
        rpc_max_request_size: RPC_DEFAULT_MAX_REQUEST_SIZE_MB,
        rpc_max_response_size: RPC_DEFAULT_MAX_RESPONSE_SIZE_MB,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: rpc_options.rpc_max_subscriptions_per_connection,
        // Doesn't matter since we have specified address above
        rpc_port: 0,
        prometheus_config: prometheus_listen_on.map(|prometheus_listen_on| {
            PrometheusConfig::new_with_default_registry(
                prometheus_listen_on,
                chain_spec.id().to_string(),
            )
        }),
        telemetry_endpoints: if telemetry_params.no_telemetry {
            None
        } else if !telemetry_params.telemetry_endpoints.is_empty() {
            Some(
                TelemetryEndpoints::new(telemetry_params.telemetry_endpoints)
                    .map_err(|error| Error::Other(error.to_string()))?,
            )
        } else {
            chain_spec.telemetry_endpoints().clone()
        },
        default_heap_pages: None,
        // Offchain worker is not used in Subspace
        offchain_worker: OffchainWorkerConfig {
            enabled: false,
            indexing_enabled: false,
        },
        force_authoring,
        disable_grandpa: true,
        dev_key_seed: None,
        tracing_targets: None,
        tracing_receiver: Default::default(),
        chain_spec: Box::new(chain_spec),
        // Substrate's default
        max_runtime_instances: 8,
        // Substrate's default
        announce_block: true,
        role: if farmer {
            sc_service::Role::Authority
        } else {
            sc_service::Role::Full
        },
        base_path: BasePath::new(base_path),
        informant_output_format: OutputFormat { enable_color },
        // Substrate's default
        runtime_cache_size: 2,
    };

    set_default_ss58_version(&consensus_chain_config.chain_spec);

    print_node_infos::<SubspaceCliPlaceholder>(&consensus_chain_config);

    let root_span = Span::current();

    let mut task_manager = {
        let tokio_handle = consensus_chain_config.tokio_handle.clone();
        let base_path = consensus_chain_config.base_path.path().to_path_buf();
        let database_source = consensus_chain_config.database.clone();

        let domains_bootstrap_nodes: serde_json::map::Map<String, serde_json::Value> =
            consensus_chain_config
                .chain_spec
                .properties()
                .get("domainsBootstrapNodes")
                .map(|d| serde_json::from_value(d.clone()))
                .transpose()
                .map_err(|error| {
                    sc_service::Error::Other(format!(
                        "Failed to decode Domains bootstrap nodes: {error:?}"
                    ))
                })?
                .unwrap_or_default();

        let consensus_state_pruning_mode = consensus_chain_config
            .state_pruning
            .clone()
            .unwrap_or_default();
        let consensus_chain_node = {
            let span = info_span!("Consensus");
            let _enter = span.enter();

            let pot_external_entropy =
                derive_pot_external_entropy(&consensus_chain_config, pot_external_entropy)?;

            let dsn_config = {
                let network_keypair = consensus_chain_config
                    .network
                    .node_key
                    .clone()
                    .into_keypair()
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to convert network keypair: {error:?}"
                        ))
                    })?;

                let dsn_bootstrap_nodes = if dsn_options.dsn_bootstrap_nodes.is_empty() {
                    consensus_chain_config
                        .chain_spec
                        .properties()
                        .get("dsnBootstrapNodes")
                        .map(|d| serde_json::from_value(d.clone()))
                        .transpose()
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to decode DSN bootstrap nodes: {error:?}"
                            ))
                        })?
                        .unwrap_or_default()
                } else {
                    dsn_options.dsn_bootstrap_nodes
                };

                // TODO: Libp2p versions for Substrate and Subspace diverged.
                // We get type compatibility by encoding and decoding the original keypair.
                let encoded_keypair = network_keypair
                    .to_protobuf_encoding()
                    .expect("Keypair-to-protobuf encoding should succeed.");
                let keypair =
                    subspace_networking::libp2p::identity::Keypair::from_protobuf_encoding(
                        &encoded_keypair,
                    )
                    .expect("Keypair-from-protobuf decoding should succeed.");

                DsnConfig {
                    keypair,
                    base_path: base_path.clone(),
                    listen_on: dsn_options.dsn_listen_on,
                    bootstrap_nodes: dsn_bootstrap_nodes,
                    reserved_peers: dsn_options.dsn_reserved_peers,
                    allow_non_global_addresses_in_dht: network_options.allow_private_ips,
                    max_in_connections: dsn_options.dsn_in_connections,
                    max_out_connections: dsn_options.dsn_out_connections,
                    max_pending_in_connections: dsn_options.dsn_pending_in_connections,
                    max_pending_out_connections: dsn_options.dsn_pending_out_connections,
                    external_addresses: dsn_options.dsn_external_addresses,
                    disable_bootstrap_on_start: dsn_options.dsn_disable_bootstrap_on_start,
                }
            };

            let consensus_chain_config = SubspaceConfiguration {
                base: consensus_chain_config,
                // Domain node needs slots notifications for bundle production.
                force_new_slot_notifications: !domain_args.is_empty(),
                subspace_networking: SubspaceNetworking::Create { config: dsn_config },
                sync_from_dsn,
                is_timekeeper: timekeeper_options.timekeeper,
                timekeeper_cpu_cores: timekeeper_options.timekeeper_cpu_cores,
            };

            let partial_components = subspace_service::new_partial::<
                PosTable,
                RuntimeApi,
                ExecutorDispatch,
            >(
                &consensus_chain_config.base, &pot_external_entropy
            )
            .map_err(|error| {
                sc_service::Error::Other(format!("Failed to build a full subspace node: {error:?}"))
            })?;

            subspace_service::new_full::<PosTable, _, _>(
                consensus_chain_config,
                partial_components,
                true,
                SlotProportion::new(3f32 / 4f32),
            )
            .await
            .map_err(|error| {
                sc_service::Error::Other(format!("Failed to build a full subspace node: {error:?}"))
            })?
        };

        StorageMonitorService::try_spawn(
            storage_monitor,
            database_source,
            &consensus_chain_node.task_manager.spawn_essential_handle(),
        )
        .map_err(|error| {
            sc_service::Error::Other(format!("Failed to start storage monitor: {error:?}"))
        })?;

        // Run a domain node.
        if !domain_args.is_empty() {
            let span = info_span!(parent: &root_span, "Domain");
            let _enter = span.enter();

            let mut domain_cli = DomainCli::new(domain_args.into_iter());

            let domain_id = domain_cli.domain_id;

            if domain_cli.run.network_params.bootnodes.is_empty() {
                domain_cli.run.network_params.bootnodes = domains_bootstrap_nodes
                    .get(&format!("{}", domain_id))
                    .map(|d| serde_json::from_value(d.clone()))
                    .transpose()
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to decode Domain: {} bootstrap nodes: {error:?}",
                            domain_id
                        ))
                    })?
                    .unwrap_or_default();
            }

            // start relayer for consensus chain
            let mut xdm_gossip_worker_builder = GossipWorkerBuilder::new();
            {
                let span = info_span!(parent: &root_span, "Consensus");
                let _enter = span.enter();

                let relayer_worker =
                    domain_client_message_relayer::worker::relay_consensus_chain_messages(
                        consensus_chain_node.client.clone(),
                        consensus_state_pruning_mode,
                        consensus_chain_node.sync_service.clone(),
                        xdm_gossip_worker_builder.gossip_msg_sink(),
                    );

                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-chain-relayer",
                        None,
                        Box::pin(relayer_worker),
                    );

                let (consensus_msg_sink, consensus_msg_receiver) =
                    tracing_unbounded("consensus_message_channel", 100);

                // Start cross domain message listener for Consensus chain to receive messages from domains in the network
                let consensus_listener =
                    cross_domain_message_gossip::start_cross_chain_message_listener(
                        ChainId::Consensus,
                        consensus_chain_node.client.clone(),
                        consensus_chain_node.transaction_pool.clone(),
                        consensus_chain_node.network_service.clone(),
                        consensus_msg_receiver,
                    );

                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-message-listener",
                        None,
                        Box::pin(consensus_listener),
                    );

                xdm_gossip_worker_builder
                    .push_chain_tx_pool_sink(ChainId::Consensus, consensus_msg_sink);
            }

            let bootstrapper =
                Bootstrapper::<DomainBlock, _, _>::new(consensus_chain_node.client.clone());

            let (domain_message_sink, domain_message_receiver) =
                tracing_unbounded("domain_message_channel", 100);

            xdm_gossip_worker_builder
                .push_chain_tx_pool_sink(ChainId::Domain(domain_id), domain_message_sink);

            let domain_starter = DomainInstanceStarter {
                domain_cli,
                base_path,
                tokio_handle,
                consensus_client: consensus_chain_node.client.clone(),
                consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(
                    consensus_chain_node.transaction_pool.clone(),
                ),
                consensus_network: consensus_chain_node.network_service.clone(),
                block_importing_notification_stream: consensus_chain_node
                    .block_importing_notification_stream
                    .clone(),
                new_slot_notification_stream: consensus_chain_node
                    .new_slot_notification_stream
                    .clone(),
                consensus_sync_service: consensus_chain_node.sync_service.clone(),
                domain_message_receiver,
                gossip_message_sink: xdm_gossip_worker_builder.gossip_msg_sink(),
            };

            consensus_chain_node
                .task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking(
                    "domain",
                    None,
                    Box::pin(async move {
                        let bootstrap_result =
                            match bootstrapper.fetch_domain_bootstrap_info(domain_id).await {
                                Err(error) => {
                                    error!(%error, "Domain bootstrapper exited with an error");
                                    return;
                                }
                                Ok(res) => res,
                            };
                        if let Err(error) = domain_starter.start(bootstrap_result).await {
                            error!(%error, "Domain starter exited with an error");
                        }
                    }),
                );

            let cross_domain_message_gossip_worker = xdm_gossip_worker_builder
                .build::<Block, _, _>(
                    consensus_chain_node.network_service.clone(),
                    consensus_chain_node.sync_service.clone(),
                );

            consensus_chain_node
                .task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking(
                    "cross-domain-gossip-message-worker",
                    None,
                    Box::pin(cross_domain_message_gossip_worker.run()),
                );
        };

        consensus_chain_node.network_starter.start_network();

        consensus_chain_node.task_manager
    };

    signals
        .run_until_signal(task_manager.future().fuse())
        .await
        .map_err(Into::into)
}
