//! Subspace malicious operator library.

mod chain_spec;
mod malicious_bundle_producer;
mod malicious_bundle_tamper;
pub mod malicious_domain_instance_starter;

use clap::Parser;
use sc_chain_spec::GenericChainSpec;
use sc_cli::{
    generate_node_name, ChainSpec, CliConfiguration, Role, RunCmd as SubstrateRunCmd, RunCmd,
    SubstrateCli,
};
use sc_service::config::{
    ExecutorConfiguration, KeystoreConfig, NetworkConfiguration, RpcConfiguration,
};
use sc_service::{BasePath, BlocksPruning, Configuration, DatabaseSource};
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_domains::DomainId;

/// Subspace Cli.
#[derive(Debug, Parser)]
#[clap(
    propagate_version = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Run a node.
    #[clap(flatten)]
    pub run: RunCmd,

    /// Sudo account to use for malicious operator
    /// If not passed, dev sudo account is used instead.
    #[arg(long)]
    pub sudo_account: Option<String>,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    pub domain_args: Vec<String>,
}

impl Cli {
    pub fn sudo_account(&self) -> AccountId32 {
        self.sudo_account
            .as_ref()
            .map(|sudo_account| {
                AccountId32::from_ss58check(sudo_account).expect("Invalid sudo account")
            })
            .unwrap_or(crate::chain_spec::consensus_dev_sudo_account())
    }
}

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Subspace".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn executable_name() -> String {
        // Customize to make sure directory used for data by default is the same regardless of the
        // name of the executable file.
        "subspace-node".to_string()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://forum.subspace.network".into()
    }

    fn copyright_start_year() -> i32 {
        2021
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
        let chain_spec = match id {
            "dev" => crate::chain_spec::dev_config()?,
            path => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        };

        Ok(Box::new(chain_spec))
    }
}

#[derive(Debug, Parser)]
pub struct DomainCli {
    /// Run a domain node.
    #[clap(flatten)]
    pub run: SubstrateRunCmd,

    #[clap(long)]
    pub domain_id: u32,

    /// Additional args for domain.
    #[clap(raw = true)]
    additional_args: Vec<String>,
}

impl DomainCli {
    /// Constructs a new instance of [`DomainCli`].
    pub fn new(domain_args: impl Iterator<Item = String>) -> Self {
        DomainCli::parse_from([Self::executable_name()].into_iter().chain(domain_args))
    }

    pub fn additional_args(&self) -> impl Iterator<Item = String> {
        [Self::executable_name()]
            .into_iter()
            .chain(self.additional_args.clone())
    }
}

impl SubstrateCli for DomainCli {
    fn impl_name() -> String {
        "Subspace Domain".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn executable_name() -> String {
        // Customize to make sure directory used for data by default is the same regardless of the
        // name of the executable file.
        "subspace-node".to_string()
    }

    fn description() -> String {
        "Subspace Domain".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/autonomys/subspace/issues/new".into()
    }

    fn copyright_start_year() -> i32 {
        2022
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
        // TODO: Fetch the runtime name of `self.domain_id` properly.
        let runtime_name = "evm";
        match runtime_name {
            "evm" => crate::chain_spec::load_domain_chain_spec(id),
            unknown_name => Err(format!("Unknown runtime: {unknown_name}")),
        }
    }
}

/// Default sub directory to store network config.
pub(crate) const DEFAULT_NETWORK_CONFIG_PATH: &str = "network";

/// Create a Configuration object from the current object, port from `sc_cli::create_configuration`
/// and changed to take `chain_spec` as argument instead of construct one internally.
pub fn create_malicious_operator_configuration<Cli: SubstrateCli>(
    domain_id: DomainId,
    base_path: BasePath,
    domain_cli: &DomainCli,
    chain_spec: Box<dyn ChainSpec>,
    tokio_handle: tokio::runtime::Handle,
) -> sc_cli::Result<Configuration> {
    let domain_cli_args = &domain_cli.run;
    let is_dev = domain_cli_args.shared_params().is_dev();
    let role = Role::Authority;
    let config_dir = base_path.config_dir(chain_spec.id());
    let net_config_dir = config_dir.join(DEFAULT_NETWORK_CONFIG_PATH);
    let client_id = Cli::client_id();
    let node_key = domain_cli_args
        .node_key_params()
        .map(|x| x.node_key(&net_config_dir, role, is_dev))
        .unwrap_or_else(|| Ok(Default::default()))?;
    let max_runtime_instances = 8;
    let is_validator = role.is_authority();
    // The malicious operator has its own internal keystore
    let keystore = KeystoreConfig::InMemory;
    let telemetry_endpoints = None;
    let runtime_cache_size = 2;
    let mut network = match domain_cli_args.network_params() {
        Some(network_params) => network_params.network_config(
            &chain_spec,
            is_dev,
            is_validator,
            Some(net_config_dir),
            &client_id,
            generate_node_name().as_str(),
            node_key,
            30334,
        ),
        None => NetworkConfiguration::new(
            generate_node_name().as_str(),
            &client_id,
            node_key,
            Some(net_config_dir),
        ),
    };
    if let Some(net_config_path) = &mut network.net_config_path {
        *net_config_path = base_path.path().join("network");
    }

    let rpc_addrs: Option<Vec<sc_service::config::RpcEndpoint>> = domain_cli
        .run
        .rpc_addr(9945)?
        .map(|addrs| addrs.into_iter().map(Into::into).collect());

    Ok(Configuration {
        impl_name: Cli::impl_name(),
        impl_version: Cli::impl_version(),
        tokio_handle,
        transaction_pool: domain_cli_args.transaction_pool(is_dev)?,
        network,
        keystore,
        database: DatabaseSource::ParityDb {
            path: base_path
                .path()
                .join("domains")
                .join(domain_id.to_string())
                .join("db"),
        },
        data_path: config_dir,
        trie_cache_maximum_size: domain_cli_args.trie_cache_maximum_size()?,
        state_pruning: domain_cli_args
            .pruning_params()
            .map(|x| x.state_pruning())
            .unwrap_or_else(|| Ok(Default::default()))?,
        blocks_pruning: domain_cli_args
            .pruning_params()
            .map(|x| x.blocks_pruning())
            .unwrap_or_else(|| Ok(BlocksPruning::KeepFinalized))?,
        executor: ExecutorConfiguration {
            wasm_method: domain_cli_args
                .import_params()
                .map(|x| x.wasm_method())
                .unwrap_or_default(),
            max_runtime_instances,
            default_heap_pages: domain_cli_args.default_heap_pages()?,
            runtime_cache_size,
        },
        wasm_runtime_overrides: domain_cli_args
            .import_params()
            .map(|x| x.wasm_runtime_overrides())
            .unwrap_or_default(),
        rpc: RpcConfiguration {
            addr: rpc_addrs,
            methods: domain_cli_args.rpc_methods()?,
            max_connections: domain_cli_args.rpc_max_connections()?,
            cors: domain_cli_args.rpc_cors(is_dev)?,
            max_request_size: 15,
            max_response_size: 15,
            id_provider: None,
            max_subs_per_conn: 1024,
            port: 9945,
            message_buffer_capacity: domain_cli_args.rpc_buffer_capacity_per_connection()?,
            batch_config: domain_cli_args.rpc_batch_config()?,
            rate_limit: domain_cli_args.rpc_rate_limit()?,
            rate_limit_whitelisted_ips: vec![],
            rate_limit_trust_proxy_headers: false,
        },
        prometheus_config: domain_cli_args.prometheus_config(9616, &chain_spec)?,
        telemetry_endpoints,
        offchain_worker: domain_cli_args
            .offchain_worker_params()
            .map(|x| x.offchain_worker(&role))
            .unwrap_or_else(|| Ok(Default::default()))?,
        force_authoring: domain_cli_args.force_authoring()?,
        disable_grandpa: domain_cli_args.disable_grandpa()?,
        dev_key_seed: domain_cli_args.dev_key_seed(is_dev)?,
        tracing_targets: domain_cli_args.shared_params().tracing_targets(),
        tracing_receiver: domain_cli_args.shared_params().tracing_receiver(),
        chain_spec,
        announce_block: domain_cli_args.announce_block()?,
        role,
        base_path,
    })
}
