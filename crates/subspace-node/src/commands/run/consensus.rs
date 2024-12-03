use crate::commands::run::shared::RpcOptions;
use crate::{chain_spec, derive_pot_external_entropy, Error};
use clap::Parser;
use prometheus_client::registry::Registry;
use sc_chain_spec::GenericChainSpec;
use sc_cli::{
    generate_node_name, Cors, NodeKeyParams, NodeKeyType, RpcMethods, TelemetryParams,
    TransactionPoolParams, RPC_DEFAULT_PORT,
};
use sc_consensus_subspace::archiver::CreateObjectMappings;
use sc_network::config::{MultiaddrWithPeerId, NonReservedPeerMode, Role, SetConfig};
use sc_service::{BlocksPruning, Configuration, PruningMode};
use sc_storage_monitor::StorageMonitorParams;
use sc_telemetry::TelemetryEndpoints;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::str::FromStr;
use subspace_core_primitives::BlockNumber;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::Multiaddr;
use subspace_service::config::{
    ChainSyncMode, SubspaceConfiguration, SubspaceNetworking, SubstrateConfiguration,
    SubstrateNetworkConfiguration, SubstrateRpcConfiguration,
};
use subspace_service::dsn::DsnConfig;
use tempfile::TempDir;
use tracing::{error, warn};

/// Roughly 138k empty blocks can fit into one archived segment, hence we need to not allow to prune
/// more blocks that this
const MIN_STATE_PRUNING: BlockNumber = 140_000;

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

/// Options for Substrate networking
#[derive(Debug, Parser)]
struct SubstrateNetworkOptions {
    /// A list of bootstrap nodes for the Substrate networking stack.
    #[arg(long = "bootstrap-node")]
    bootstrap_nodes: Vec<MultiaddrWithPeerId>,

    /// A list of reserved node addresses, which are prioritised for connections.
    #[arg(long = "reserved-peer")]
    reserved_peers: Vec<MultiaddrWithPeerId>,

    /// Only synchronize the chain with reserved nodes.
    ///
    /// TCP connections might still be established with non-reserved nodes.
    /// In particular, if you are a farmer your node might still connect to other farmer nodes
    /// regardless of whether they are defined as reserved nodes.
    #[arg(long)]
    reserved_only: bool,

    /// The public address that other nodes will use to connect to this node.
    ///
    /// This can be used if there's a proxy in front of this node or if address is known beforehand
    /// and less reliable auto-discovery can be avoided.
    #[arg(long = "external-address")]
    external_addresses: Vec<sc_network::Multiaddr>,

    /// Listen for incoming Substrate connections on these multiaddresses.
    #[arg(long, default_values_t = [
        sc_network::Multiaddr::from(sc_network::multiaddr::Protocol::Ip4(Ipv4Addr::UNSPECIFIED))
            .with(sc_network::multiaddr::Protocol::Tcp(30333)),
        sc_network::Multiaddr::from(sc_network::multiaddr::Protocol::Ip6(Ipv6Addr::UNSPECIFIED))
            .with(sc_network::multiaddr::Protocol::Tcp(30333))
    ])]
    listen_on: Vec<sc_network::Multiaddr>,

    /// Enable non-global (private, shared, loopback..) addresses in the Kademlia DHT.
    /// By default, these addresses are excluded from the DHT.
    #[arg(long, default_value_t = false)]
    allow_private_ips: bool,

    /// The number of outgoing connections we will try to maintain.
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
    /// Listen for incoming DSN connections on these multiaddresses.
    #[arg(long, default_values_t = [
        Multiaddr::from(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Tcp(30433)),
        Multiaddr::from(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
            .with(Protocol::Tcp(30433))
    ])]
    dsn_listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    #[arg(long = "dsn-bootstrap-node")]
    dsn_bootstrap_nodes: Vec<Multiaddr>,

    /// Reserved peers for DSN.
    #[arg(long = "dsn-reserved-peer")]
    dsn_reserved_peers: Vec<Multiaddr>,

    /// Maximum established incoming connection limit for DSN.
    #[arg(long, default_value_t = 50)]
    dsn_in_connections: u32,

    /// Maximum established outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    dsn_out_connections: u32,

    /// Maximum pending incoming connection limit for DSN.
    #[arg(long, default_value_t = 100)]
    dsn_pending_in_connections: u32,

    /// Maximum pending outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    dsn_pending_out_connections: u32,

    /// Known external addresses.
    #[arg(long = "dsn-external-address")]
    dsn_external_addresses: Vec<Multiaddr>,
}

/// This mode specifies when the block's state (ie, storage) should be pruned (ie, removed) from
/// the database.
#[derive(Debug, Clone, Copy, PartialEq)]
enum StatePruningMode {
    /// Keep the data of all blocks.
    Archive,
    /// Keep only the data of finalized blocks.
    ArchiveCanonical,
    /// Keep the data of the last number of finalized blocks.
    Number(u32),
}

impl FromStr for StatePruningMode {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "archive" => Ok(Self::Archive),
            "archive-canonical" => Ok(Self::ArchiveCanonical),
            n => n
                .parse()
                .map_err(|_| "Invalid state pruning mode specified".to_string())
                .map(Self::Number),
        }
    }
}

impl fmt::Display for StatePruningMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive => f.write_str("archive"),
            Self::ArchiveCanonical => f.write_str("archive-canonical"),
            Self::Number(n) => f.write_str(n.to_string().as_str()),
        }
    }
}

/// This mode specifies when the block's body (including justifications) should be pruned (ie,
/// removed) from the database.
#[derive(Debug, Clone, Copy, PartialEq)]
enum BlocksPruningMode {
    /// Keep the data of all blocks.
    Archive,
    /// Keep only the data of finalized blocks.
    ArchiveCanonical,
    /// Keep the data of the last number of finalized blocks.
    Number(u32),
}

impl FromStr for BlocksPruningMode {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "archive" => Ok(Self::Archive),
            "archive-canonical" => Ok(Self::ArchiveCanonical),
            n => n
                .parse()
                .map_err(|_| "Invalid block pruning mode specified".to_string())
                .map(Self::Number),
        }
    }
}

impl fmt::Display for BlocksPruningMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive => f.write_str("archive"),
            Self::ArchiveCanonical => f.write_str("archive-canonical"),
            Self::Number(n) => f.write_str(n.to_string().as_str()),
        }
    }
}

/// Parameters to define the pruning mode
#[derive(Debug, Clone, Parser)]
struct PruningOptions {
    /// The state pruning mode.
    ///
    /// This mode specifies when the block's state (ie, storage) should be pruned (ie, removed)
    /// from the database.
    /// This setting can only be set on the first creation of the database. Every subsequent run
    /// will load the pruning mode from the database and will error if the stored mode doesn't
    /// match this CLI value. It is fine to drop this CLI flag for subsequent runs.
    /// Possible values:
    ///  - archive: Keep the state of all blocks.
    ///  - archive-canonical: Keep only the state of finalized blocks.
    #[arg(long, default_value_t = StatePruningMode::Number(MIN_STATE_PRUNING))]
    state_pruning: StatePruningMode,

    /// The blocks pruning mode.
    ///
    /// This mode specifies when the block's body (including justifications)
    /// should be pruned (ie, removed) from the database.
    /// Possible values:
    ///  - archive Keep all blocks.
    ///  - archive-canonical Keep only finalized blocks.
    ///  - number: Keep the last `number` of finalized blocks.
    #[arg(long, default_value_t = BlocksPruningMode::Number(256))]
    blocks_pruning: BlocksPruningMode,
}

impl PruningOptions {
    /// Get the pruning value from the parameters
    fn state_pruning(&self) -> PruningMode {
        match self.state_pruning {
            StatePruningMode::Archive => PruningMode::ArchiveAll,
            StatePruningMode::ArchiveCanonical => PruningMode::ArchiveCanonical,
            StatePruningMode::Number(num) => PruningMode::blocks_pruning(num),
        }
    }

    /// Get the block pruning value from the parameters
    fn blocks_pruning(&self) -> BlocksPruning {
        match self.blocks_pruning {
            BlocksPruningMode::Archive => BlocksPruning::KeepAll,
            BlocksPruningMode::ArchiveCanonical => BlocksPruning::KeepFinalized,
            BlocksPruningMode::Number(n) => BlocksPruning::Some(n),
        }
    }
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

/// Whether to create object mappings.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum CreateObjectMappingConfig {
    /// Start creating object mappings from this block number.
    ///
    /// This can be lower than the latest archived block, but must be greater than genesis.
    ///
    /// The genesis block doesn't have mappings, so starting mappings at genesis is pointless.
    /// The archiver will fail if it can't get the data for this block, and snap sync doesn't store
    /// the genesis data on disk. So avoiding genesis also avoids this error.
    /// <https://github.com/paritytech/polkadot-sdk/issues/5366>
    Block(NonZeroU32),

    /// Create object mappings as archiving is happening.
    /// This continues from the last archived segment, but mappings that were in the channel or RPC
    /// segment when the node shut down can be lost.
    Yes,

    /// Don't create object mappings.
    #[default]
    No,
}

impl From<CreateObjectMappingConfig> for CreateObjectMappings {
    fn from(config: CreateObjectMappingConfig) -> Self {
        match config {
            CreateObjectMappingConfig::Block(block) => CreateObjectMappings::Block(block),
            CreateObjectMappingConfig::Yes => CreateObjectMappings::Yes,
            CreateObjectMappingConfig::No => CreateObjectMappings::No,
        }
    }
}

impl FromStr for CreateObjectMappingConfig {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "no" => Ok(Self::No),
            "yes" => Ok(Self::Yes),
            block => block.parse().map(Self::Block).map_err(|_| {
                "Unsupported create object mappings setting: use `yes`, `no` or a non-zero block number"
                    .to_string()
            }),
        }
    }
}

impl fmt::Display for CreateObjectMappingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(block) => write!(f, "{}", block),
            Self::Yes => f.write_str("yes"),
            Self::No => f.write_str("no"),
        }
    }
}

/// Options for running a node
#[derive(Debug, Parser)]
pub(super) struct ConsensusChainOptions {
    /// Base path to store node files.
    ///
    /// Required unless --dev mode is used.
    #[arg(long)]
    base_path: Option<PathBuf>,

    /// The chain specification.
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
    /// * `--create-object-mappings`
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
    rpc_options: RpcOptions<{ RPC_DEFAULT_PORT }>,

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
    pruning_params: PruningOptions,

    /// Options for Substrate networking
    #[clap(flatten)]
    network_options: SubstrateNetworkOptions,

    /// Options for transaction pool
    #[clap(flatten)]
    pool_config: TransactionPoolParams,

    /// Make the node forcefully assume it is synced, needed for network bootstrapping only. As
    /// long as two synced nodes remain on the network at any time, this doesn't need to be used.
    ///
    /// --dev mode enables this option automatically.
    #[clap(long)]
    force_synced: bool,

    /// Enable authoring even when offline, needed for network bootstrapping only.
    #[arg(long)]
    force_authoring: bool,

    /// Create object mappings during archiving.
    ///
    /// Can be set to `no` (default), `yes` (creates object mappings as archiving is happening), or
    /// a non-zero block number where the node starts creating object mappings.
    ///
    /// --dev mode enables mappings from the first block automatically, unless a value is supplied
    /// explicitly.
    /// Use `no` to disable mappings in --dev mode.
    #[arg(long)]
    create_object_mappings: Option<CreateObjectMappingConfig>,

    /// External entropy, used initially when PoT chain starts to derive the first seed
    #[arg(long)]
    pot_external_entropy: Option<String>,

    /// Options for DSN
    #[clap(flatten)]
    dsn_options: DsnOptions,

    /// Parameters used to create the storage monitor.
    #[clap(flatten)]
    storage_monitor: StorageMonitorParams,

    #[clap(flatten)]
    timekeeper_options: TimekeeperOptions,

    /// Sync mode
    ///
    /// Examples: `snap`, `full`
    #[arg(long, default_value = None)]
    sync: Option<ChainSyncMode>,
}

pub(super) struct PrometheusConfiguration {
    pub(super) listen_on: SocketAddr,
    pub(super) prometheus_registry: Registry,
    pub(super) substrate_registry: substrate_prometheus_endpoint::Registry,
}

pub(super) struct ConsensusChainConfiguration {
    pub(super) maybe_tmp_dir: Option<TempDir>,
    pub(super) subspace_configuration: SubspaceConfiguration,
    pub(super) dev: bool,
    /// External entropy, used initially when PoT chain starts to derive the first seed
    pub(super) pot_external_entropy: Vec<u8>,
    pub(super) storage_monitor: StorageMonitorParams,
    pub(super) prometheus_configuration: Option<PrometheusConfiguration>,
}

pub(super) fn create_consensus_chain_configuration(
    consensus_node_options: ConsensusChainOptions,
    domains_enabled: bool,
) -> Result<ConsensusChainConfiguration, Error> {
    let ConsensusChainOptions {
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
        mut create_object_mappings,
        pot_external_entropy,
        dsn_options,
        storage_monitor,
        mut timekeeper_options,
        mut sync,
    } = consensus_node_options;

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
            timekeeper_options.timekeeper = true;

            if create_object_mappings.is_none() {
                create_object_mappings = Some(CreateObjectMappingConfig::Block(NonZeroU32::MIN));
            }

            if sync.is_none() {
                sync.replace(ChainSyncMode::Full);
            }
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
                    "http://[::1]:*".into(),
                    "https://localhost:*".into(),
                    "https://127.0.0.1:*".into(),
                    "https://[::1]:*".into(),
                    "https://polkadot.js.org".into(),
                ])
            }
        });
    }

    // Snap sync is the default mode.
    let sync = sync.unwrap_or(ChainSyncMode::Snap);

    let chain_spec = match chain.as_deref() {
        Some("mainnet-compiled") => chain_spec::mainnet_compiled()?,
        Some("mainnet") => chain_spec::mainnet_config()?,
        Some("taurus") => chain_spec::taurus_config()?,
        Some("devnet") => chain_spec::devnet_config()?,
        Some("devnet-compiled") => chain_spec::devnet_config_compiled()?,
        Some("dev") => chain_spec::dev_config()?,
        Some(path) => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
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

    let node_name = name.unwrap_or_else(generate_node_name);

    if let StatePruningMode::Number(number) = pruning_params.state_pruning {
        if number < MIN_STATE_PRUNING {
            // Do not return error because some users may in fact use lower values and we don't want
            // to break their setups, at least for now
            error!(
                "Do not set state pruning number below {MIN_STATE_PRUNING} for safety reasons, \
                node can break any time!"
            );
        }
    }

    let consensus_chain_config = SubstrateConfiguration {
        impl_name: env!("CARGO_PKG_NAME").to_string(),
        impl_version: env!("SUBSTRATE_CLI_IMPL_VERSION").into(),
        farmer,
        base_path: base_path.clone(),
        transaction_pool,
        network: SubstrateNetworkConfiguration {
            listen_on: network_options.listen_on,
            public_addresses: network_options.external_addresses,
            bootstrap_nodes: network_options.bootstrap_nodes,
            node_key: {
                let node_key_params = NodeKeyParams {
                    node_key: network_options.node_key,
                    node_key_type: NodeKeyType::Ed25519,
                    node_key_file: None,
                    unsafe_force_node_key_generation: false,
                };

                node_key_params.node_key(&net_config_path, Role::Full, dev)?
            },
            default_peers_set: SetConfig {
                in_peers: network_options.in_peers,
                out_peers: network_options.out_peers,
                reserved_nodes: network_options.reserved_peers,
                non_reserved_mode: if network_options.reserved_only {
                    NonReservedPeerMode::Deny
                } else {
                    NonReservedPeerMode::Accept
                },
            },
            node_name,
            allow_private_ips: network_options.allow_private_ips,
            sync_mode: sync,
            force_synced,
        },
        state_pruning: pruning_params.state_pruning(),
        blocks_pruning: pruning_params.blocks_pruning(),
        rpc_options: SubstrateRpcConfiguration {
            listen_on: Some(rpc_options.rpc_listen_on),
            max_connections: rpc_options.rpc_max_connections,
            cors: rpc_cors.into(),
            methods: match rpc_options.rpc_methods {
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
            rate_limit: rpc_options.rpc_rate_limit,
            rate_limit_whitelisted_ips: rpc_options.rpc_rate_limit_whitelisted_ips,
            rate_limit_trust_proxy_headers: rpc_options.rpc_rate_limit_trust_proxy_headers,
            max_subscriptions_per_connection: rpc_options.rpc_max_subscriptions_per_connection,
            message_buffer_capacity_per_connection: rpc_options
                .rpc_message_buffer_capacity_per_connection,
            disable_batch_requests: rpc_options.rpc_disable_batch_requests,
            max_batch_request_len: rpc_options.rpc_max_batch_request_len,
        },
        prometheus_listen_on,
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
        force_authoring,
        chain_spec: Box::new(chain_spec),
    };
    let consensus_chain_config = Configuration::from(consensus_chain_config);

    let pot_external_entropy =
        derive_pot_external_entropy(&consensus_chain_config, pot_external_entropy)?;

    let dsn_config = {
        let network_keypair = consensus_chain_config
            .network
            .node_key
            .clone()
            .into_keypair()
            .map_err(|error| {
                sc_service::Error::Other(format!("Failed to convert network keypair: {error:?}"))
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

        // Convert keypair from Substrate to libp2p type
        let keypair = subspace_networking::libp2p::identity::Keypair::ed25519_from_bytes(
            network_keypair.secret().to_bytes(),
        )
        .expect("Keypair-from-protobuf decoding should succeed.");

        DsnConfig {
            keypair,
            network_path: base_path.join("network"),
            listen_on: dsn_options.dsn_listen_on,
            bootstrap_nodes: dsn_bootstrap_nodes,
            reserved_peers: dsn_options.dsn_reserved_peers,
            allow_non_global_addresses_in_dht: network_options.allow_private_ips,
            max_in_connections: dsn_options.dsn_in_connections,
            max_out_connections: dsn_options.dsn_out_connections,
            max_pending_in_connections: dsn_options.dsn_pending_in_connections,
            max_pending_out_connections: dsn_options.dsn_pending_out_connections,
            external_addresses: dsn_options.dsn_external_addresses,
        }
    };

    let substrate_registry = consensus_chain_config.prometheus_registry().cloned();
    Ok(ConsensusChainConfiguration {
        maybe_tmp_dir,
        subspace_configuration: SubspaceConfiguration {
            base: consensus_chain_config,
            // Domain node needs slots notifications for bundle production.
            force_new_slot_notifications: domains_enabled,
            create_object_mappings: create_object_mappings.unwrap_or_default().into(),
            subspace_networking: SubspaceNetworking::Create { config: dsn_config },
            sync,
            is_timekeeper: timekeeper_options.timekeeper,
            timekeeper_cpu_cores: timekeeper_options.timekeeper_cpu_cores,
        },
        dev,
        pot_external_entropy,
        storage_monitor,
        prometheus_configuration: prometheus_listen_on.zip(substrate_registry).map(
            |(listen_on, substrate_registry)| PrometheusConfiguration {
                listen_on,
                prometheus_registry: Registry::default(),
                substrate_registry,
            },
        ),
    })
}
