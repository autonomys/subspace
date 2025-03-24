use crate::commands::run::shared::RpcOptions;
use crate::commands::shared::{store_key_in_keystore, KeystoreOptions};
use crate::Error;
use clap::Parser;
use domain_client_operator::snap_sync::ConsensusChainSyncParams;
use domain_client_operator::{BootstrapResult, DomainChainSyncOracle, OperatorStreams};
use domain_eth_service::provider::EthProvider;
use domain_eth_service::DefaultEthConfig;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_service::config::{
    SubstrateConfiguration, SubstrateNetworkConfiguration, SubstrateRpcConfiguration,
};
use domain_service::providers::DefaultProvider;
use domain_service::{FullBackend, FullClient};
use evm_domain_runtime::AccountId as AccountId20;
use futures::StreamExt;
use sc_chain_spec::{ChainType, GenericChainSpec, NoExtension, Properties};
use sc_cli::{
    Cors, KeystoreParams, PruningParams, RpcMethods, RuntimeParams, TransactionPoolParams,
    RPC_DEFAULT_PORT,
};
use sc_consensus_subspace::block_import::BlockImportingNotification;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_network::config::{MultiaddrWithPeerId, NonReservedPeerMode, SetConfig, TransportConfig};
use sc_network::{NetworkPeers, NetworkRequest};
use sc_proof_of_time::source::PotSlotInfo;
use sc_service::config::{ExecutorConfiguration, KeystoreConfig};
use sc_service::Configuration;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::SubspaceApi;
use sp_core::crypto::{AccountId32, SecretString};
use sp_domains::{DomainId, DomainInstanceData, OperatorId, RuntimeType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use subspace_runtime::RuntimeApi as CRuntimeApi;
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::DOMAINS_BLOCK_PRUNING_DEPTH;
use subspace_service::FullClient as CFullClient;
use tokio::sync::broadcast::Receiver;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::log::info;
use tracing::warn;

/// Options for Substrate networking
#[derive(Debug, Parser)]
struct SubstrateNetworkOptions {
    /// Specify a list of bootstrap nodes for Substrate networking stack.
    #[arg(long = "bootstrap-node")]
    bootstrap_nodes: Vec<MultiaddrWithPeerId>,

    /// Specify a list of reserved node addresses.
    #[arg(long = "reserved-peer")]
    reserved_peers: Vec<MultiaddrWithPeerId>,

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
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30334")]
    listen_on: Vec<sc_network::Multiaddr>,

    /// Specify the number of outgoing connections we're trying to maintain.
    #[arg(long, default_value_t = 8)]
    out_peers: u32,

    /// Maximum number of inbound full nodes peers.
    #[arg(long, default_value_t = 32)]
    in_peers: u32,
}

/// Options for running a domain
#[derive(Debug, Parser)]
pub(super) struct DomainOptions {
    /// ID of the domain to run
    #[clap(long)]
    domain_id: Option<DomainId>,

    /// Use provided operator id to submit bundles
    #[arg(long)]
    operator_id: Option<OperatorId>,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions<{ RPC_DEFAULT_PORT + 1 }>,

    /// IP and port (TCP) to start Prometheus exporter on
    // TODO: Use the same registry as consensus chain instead
    #[clap(long)]
    prometheus_listen_on: Option<SocketAddr>,

    /// Options for chain database pruning
    #[clap(flatten)]
    pruning_params: PruningParams,

    /// Options for Substrate networking
    #[clap(flatten)]
    network_options: SubstrateNetworkOptions,

    /// Operator secret key URI to insert into keystore.
    ///
    /// Example: "//Alice".
    ///
    /// If the value is a file, the file content is used as URI.
    #[arg(long)]
    keystore_suri: Option<SecretString>,

    /// Options for domain keystore
    #[clap(flatten)]
    keystore_options: KeystoreOptions,

    /// Options for transaction pool
    #[clap(flatten)]
    pool_config: TransactionPoolParams,

    /// Options for Runtime
    #[clap(flatten)]
    pub runtime_params: RuntimeParams,

    /// Additional args for domain.
    #[clap(raw = true)]
    additional_args: Vec<String>,
}

#[derive(Debug)]
pub(super) struct DomainConfiguration {
    pub(super) domain_config: Configuration,
    pub(super) domain_id: DomainId,
    pub(super) operator_id: Option<OperatorId>,
    pub(super) additional_args: Vec<String>,
}

pub(super) fn create_domain_configuration(
    consensus_chain_configuration: &Configuration,
    dev: bool,
    domain_options: DomainOptions,
) -> Result<DomainConfiguration, Error> {
    let DomainOptions {
        domain_id: maybe_domain_id,
        mut operator_id,
        rpc_options,
        prometheus_listen_on,
        pruning_params,
        network_options,
        mut keystore_suri,
        keystore_options,
        pool_config,
        runtime_params,
        additional_args,
    } = domain_options;

    let domain_id;
    let transaction_pool;
    let rpc_cors;
    // Development mode handling is limited to this section
    {
        if dev {
            if operator_id.is_none() {
                operator_id.replace(OperatorId::default());
            }
            if keystore_suri.is_none() {
                keystore_suri.replace(SecretString::new("//Alice".to_string()));
            }
        }

        domain_id = match maybe_domain_id {
            Some(domain_id) => domain_id,
            None => {
                if dev {
                    DomainId::default()
                } else {
                    return Err(Error::Other(
                        "Domain ID must be provided unless --dev mode is used".to_string(),
                    ));
                }
            }
        };
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

    // Code doesn't matter, it will be replaced before running just like genesis storage
    let chain_spec = GenericChainSpec::<NoExtension, ()>::builder(&[], None)
        .with_name(&format!(
            "{} Domain {}",
            consensus_chain_configuration.chain_spec.name(),
            domain_id
        ))
        .with_id(&format!(
            "{}_domain_{}",
            consensus_chain_configuration.chain_spec.id(),
            domain_id
        ))
        .with_chain_type(ChainType::Custom("SubspaceDomain".to_string()))
        .with_boot_nodes(
            consensus_chain_configuration
                .chain_spec
                .properties()
                .get("domainsBootstrapNodes")
                .map(|d| {
                    serde_json::from_value::<HashMap<DomainId, Vec<MultiaddrWithPeerId>>>(d.clone())
                })
                .transpose()
                .map_err(|error| {
                    sc_service::Error::Other(format!(
                        "Failed to decode Domains bootstrap nodes: {error:?}"
                    ))
                })?
                .unwrap_or_default()
                .get(&domain_id)
                .cloned()
                .unwrap_or_default(),
        )
        .with_protocol_id(&format!(
            "{}-domain-{}",
            consensus_chain_configuration.chain_spec.id(),
            domain_id
        ))
        .with_properties({
            let mut properties = Properties::new();

            if let Some(ss58_format) = consensus_chain_configuration
                .chain_spec
                .properties()
                .get("ss58Format")
            {
                properties.insert("ss58Format".to_string(), ss58_format.clone());
            }
            if let Some(decimal_places) = consensus_chain_configuration
                .chain_spec
                .properties()
                .get("tokenDecimals")
            {
                properties.insert("tokenDecimals".to_string(), decimal_places.clone());
            }
            if let Some(token_symbol) = consensus_chain_configuration
                .chain_spec
                .properties()
                .get("tokenSymbol")
            {
                properties.insert("tokenSymbol".to_string(), token_symbol.clone());
            }

            properties
        })
        .build();

    let base_path = consensus_chain_configuration
        .base_path
        .path()
        .join("domains")
        .join(domain_id.to_string());

    let keystore = {
        let keystore_params = KeystoreParams {
            keystore_path: None,
            password_interactive: keystore_options.keystore_password_interactive,
            password: keystore_options.keystore_password,
            password_filename: keystore_options.keystore_password_filename,
        };

        let keystore_config = keystore_params.keystore_config(&base_path)?;

        if let Some(keystore_suri) = keystore_suri {
            let (path, password) = match &keystore_config {
                KeystoreConfig::Path { path, password, .. } => (path.clone(), password.clone()),
                KeystoreConfig::InMemory => {
                    unreachable!("Just constructed non-memory keystore config; qed");
                }
            };

            store_key_in_keystore(path, &keystore_suri, password)?;
        }

        keystore_config
    };

    let domain_config = SubstrateConfiguration {
        impl_name: consensus_chain_configuration.impl_name.clone(),
        impl_version: consensus_chain_configuration.impl_version.clone(),
        operator: operator_id.is_some(),
        base_path: base_path.clone(),
        transaction_pool,
        network: SubstrateNetworkConfiguration {
            listen_on: network_options.listen_on,
            public_addresses: network_options.public_addr,
            bootstrap_nodes: network_options.bootstrap_nodes,
            node_key: consensus_chain_configuration.network.node_key.clone(),
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
            node_name: consensus_chain_configuration.network.node_name.clone(),
            allow_private_ips: match consensus_chain_configuration.network.transport {
                TransportConfig::Normal {
                    allow_private_ip, ..
                } => allow_private_ip,
                TransportConfig::MemoryOnly => {
                    unreachable!("Memory transport not used in CLI; qed")
                }
            },
            // set to be force_synced always for domains since they relay on Consensus chain to derive and import domain blocks.
            // If not set, each domain node will wait to be fully synced and as a result will not propagate the transactions over network.
            // It would have been ideal to use `Consensus` chain sync service to respond to `is_major_sync` requests but this
            // would require upstream changes and with some refactoring. This is not worth the effort at the moment since
            // we are planning to enable domain's block request and state sync mechanism in the near future.
            // Until such change has been made, domain's sync service needs to be in force_synced state.
            force_synced: true,
        },
        keystore,
        state_pruning: pruning_params.state_pruning()?,
        blocks_pruning: pruning_params.blocks_pruning()?,
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
        telemetry_endpoints: consensus_chain_configuration.telemetry_endpoints.clone(),
        force_authoring: false,
        chain_spec: Box::new(chain_spec),
        executor: ExecutorConfiguration {
            wasm_method: Default::default(),
            max_runtime_instances: runtime_params.max_runtime_instances,
            default_heap_pages: None,
            runtime_cache_size: runtime_params.runtime_cache_size,
        },
    };

    Ok(DomainConfiguration {
        domain_config: Configuration::from(domain_config),
        domain_id,
        operator_id,
        additional_args,
    })
}

pub(super) struct DomainStartOptions {
    pub(super) consensus_client: Arc<CFullClient<CRuntimeApi>>,
    pub(super) consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    pub(super) consensus_network: Arc<dyn NetworkPeers + Send + Sync>,
    pub(super) block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<CBlock>>,
    pub(super) pot_slot_info_stream: Receiver<PotSlotInfo>,
    pub(super) consensus_network_sync_oracle: Arc<sc_network_sync::SyncingService<CBlock>>,
    pub(super) domain_message_receiver:
        TracingUnboundedReceiver<cross_domain_message_gossip::ChainMsg>,
    pub(super) gossip_message_sink: TracingUnboundedSender<cross_domain_message_gossip::Message>,
}

pub(super) async fn run_domain<CNR>(
    bootstrap_result: BootstrapResult<CBlock>,
    domain_configuration: DomainConfiguration,
    domain_start_options: DomainStartOptions,
    consensus_chain_sync_params: Option<ConsensusChainSyncParams<CBlock, CNR>>,
) -> Result<(), Error>
where
    CNR: NetworkRequest + Send + Sync + 'static,
{
    let BootstrapResult {
        domain_instance_data,
        domain_created_at,
        imported_block_notification_stream,
    } = bootstrap_result;

    let DomainInstanceData {
        runtime_type,
        raw_genesis,
    } = domain_instance_data;

    let DomainConfiguration {
        mut domain_config,
        domain_id,
        operator_id,
        additional_args,
    } = domain_configuration;

    // Replace storage in the chain spec with correct one for this particular domain
    domain_config
        .chain_spec
        .set_storage(raw_genesis.into_storage());

    let DomainStartOptions {
        consensus_client,
        consensus_offchain_tx_pool_factory,
        consensus_network,
        block_importing_notification_stream,
        pot_slot_info_stream,
        consensus_network_sync_oracle,
        domain_message_receiver,
        gossip_message_sink,
    } = domain_start_options;

    let block_importing_notification_stream = block_importing_notification_stream
        .subscribe()
        .then(|block_importing_notification| async move {
            (
                block_importing_notification.block_number,
                block_importing_notification.acknowledgement_sender,
            )
        })
        .boxed();

    let pot_slot_info_stream = tokio_stream::StreamExt::filter_map(
        tokio_stream::wrappers::BroadcastStream::new(pot_slot_info_stream),
        |result| match result {
            Ok(pot_slot_info) => Some((pot_slot_info.slot, pot_slot_info.checkpoints.output())),
            Err(err) => match err {
                BroadcastStreamRecvError::Lagged(skipped_notifications) => {
                    info!(
                        "Domain slot receiver is lagging. Skipped {} slot notification(s)",
                        skipped_notifications
                    );
                    None
                }
            },
        },
    );

    let operator_streams = OperatorStreams {
        // TODO: proper value
        consensus_block_import_throttling_buffer_size: 10,
        block_importing_notification_stream,
        imported_block_notification_stream,
        new_slot_notification_stream: pot_slot_info_stream,
        acknowledgement_sender_stream: futures::stream::empty(),
        _phantom: Default::default(),
    };

    let consensus_best_hash = consensus_client.info().best_hash;
    let chain_constants = consensus_client
        .runtime_api()
        .chain_constants(consensus_best_hash)
        .map_err(|err| Error::Other(err.to_string()))?;

    let domain_sync_oracle = Arc::new(DomainChainSyncOracle::new(
        consensus_network_sync_oracle,
        consensus_chain_sync_params
            .as_ref()
            .map(|params| params.snap_sync_orchestrator.domain_snap_sync_finished()),
    ));

    match runtime_type {
        RuntimeType::Evm => {
            let eth_provider = EthProvider::<
                evm_domain_runtime::TransactionConverter,
                DefaultEthConfig<
                    FullClient<DomainBlock, evm_domain_runtime::RuntimeApi>,
                    FullBackend<DomainBlock>,
                >,
            >::new(
                Some(domain_config.base_path.path()),
                additional_args.into_iter(),
            );

            let domain_params = domain_service::DomainParams {
                domain_id,
                domain_config,
                domain_created_at,
                consensus_client,
                consensus_offchain_tx_pool_factory,
                consensus_network,
                domain_sync_oracle,
                operator_streams,
                gossip_message_sink,
                domain_message_receiver,
                provider: eth_provider,
                skip_empty_bundle_production: true,
                skip_out_of_order_slot: false,
                maybe_operator_id: operator_id,
                confirmation_depth_k: chain_constants.confirmation_depth_k(),
                consensus_chain_sync_params,
                challenge_period: DOMAINS_BLOCK_PRUNING_DEPTH,
            };

            let mut domain_node = domain_service::new_full::<
                _,
                _,
                _,
                _,
                _,
                _,
                evm_domain_runtime::RuntimeApi,
                AccountId20,
                _,
                _,
            >(domain_params)
            .await?;

            domain_node.network_starter.start_network();

            domain_node.task_manager.future().await?;

            Ok(())
        }
        RuntimeType::AutoId => {
            let domain_params = domain_service::DomainParams {
                domain_id,
                domain_config,
                domain_created_at,
                consensus_client,
                consensus_offchain_tx_pool_factory,
                consensus_network,
                domain_sync_oracle,
                operator_streams,
                gossip_message_sink,
                domain_message_receiver,
                provider: DefaultProvider,
                skip_empty_bundle_production: true,
                skip_out_of_order_slot: false,
                maybe_operator_id: operator_id,
                confirmation_depth_k: chain_constants.confirmation_depth_k(),
                consensus_chain_sync_params,
                challenge_period: DOMAINS_BLOCK_PRUNING_DEPTH,
            };

            let mut domain_node = domain_service::new_full::<
                _,
                _,
                _,
                _,
                _,
                _,
                auto_id_domain_runtime::RuntimeApi,
                AccountId32,
                _,
                _,
            >(domain_params)
            .await?;

            domain_node.network_starter.start_network();

            domain_node.task_manager.future().await?;

            Ok(())
        }
    }
}
