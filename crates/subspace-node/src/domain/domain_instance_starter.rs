use super::{evm_chain_spec, DomainCli};
use crate::domain::AccountId20;
use cross_domain_message_gossip::{ChainTxPoolMsg, Message};
use domain_client_operator::{BootstrapResult, OperatorStreams};
use domain_eth_service::provider::EthProvider;
use domain_eth_service::DefaultEthConfig;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_service::{FullBackend, FullClient};
use evm_domain_runtime::ExecutorDispatch as EVMDomainExecutorDispatch;
use futures::StreamExt;
use sc_chain_spec::ChainSpec;
use sc_cli::{CliConfiguration, Database, DefaultConfigurationValues, SubstrateCli};
use sc_consensus_subspace::block_import::BlockImportingNotification;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::NewSlotNotification;
use sc_network::NetworkPeers;
use sc_service::{BasePath, Configuration};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_domains::{DomainInstanceData, RuntimeType};
use std::sync::Arc;
use subspace_runtime::{ExecutorDispatch as CExecutorDispatch, RuntimeApi as CRuntimeApi};
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_service::FullClient as CFullClient;

/// `DomainInstanceStarter` used to start a domain instance node based on the given
/// bootstrap result
pub struct DomainInstanceStarter<CNetwork> {
    pub domain_cli: DomainCli,
    pub tokio_handle: tokio::runtime::Handle,
    pub consensus_client: Arc<CFullClient<CRuntimeApi, CExecutorDispatch>>,
    pub consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    pub block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<CBlock>>,
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    pub consensus_sync_service: Arc<sc_network_sync::SyncingService<CBlock>>,
    pub domain_message_receiver: TracingUnboundedReceiver<ChainTxPoolMsg>,
    pub gossip_message_sink: TracingUnboundedSender<Message>,
    pub consensus_network: Arc<CNetwork>,
}

impl<CNetwork> DomainInstanceStarter<CNetwork>
where
    CNetwork: NetworkPeers + Send + Sync + 'static,
{
    pub async fn start(
        self,
        bootstrap_result: BootstrapResult<CBlock>,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let BootstrapResult {
            domain_instance_data,
            domain_created_at,
            imported_block_notification_stream,
        } = bootstrap_result;

        let DomainInstanceData {
            runtime_type,
            raw_genesis,
        } = domain_instance_data;

        let DomainInstanceStarter {
            domain_cli,
            tokio_handle,
            consensus_client,
            consensus_offchain_tx_pool_factory,
            block_importing_notification_stream,
            new_slot_notification_stream,
            consensus_sync_service,
            domain_message_receiver,
            gossip_message_sink,
            consensus_network,
        } = self;

        let domain_id = domain_cli.domain_id;
        let domain_config = {
            let chain_id = domain_cli.chain_id(domain_cli.is_dev()?)?;

            let domain_spec = evm_chain_spec::create_domain_spec(chain_id.as_str(), raw_genesis)?;

            create_configuration::<_, DomainCli, DomainCli>(&domain_cli, domain_spec, tokio_handle)?
        };

        let block_importing_notification_stream = || {
            block_importing_notification_stream.subscribe().then(
                |block_importing_notification| async move {
                    (
                        block_importing_notification.block_number,
                        block_importing_notification.acknowledgement_sender,
                    )
                },
            )
        };

        let new_slot_notification_stream = || {
            new_slot_notification_stream
                .subscribe()
                .then(|slot_notification| async move {
                    (
                        slot_notification.new_slot_info.slot,
                        slot_notification.new_slot_info.global_randomness,
                    )
                })
        };

        let operator_streams = OperatorStreams {
            // TODO: proper value
            consensus_block_import_throttling_buffer_size: 10,
            block_importing_notification_stream: block_importing_notification_stream(),
            imported_block_notification_stream,
            new_slot_notification_stream: new_slot_notification_stream(),
            acknowledgement_sender_stream: futures::stream::empty(),
            _phantom: Default::default(),
        };

        match runtime_type {
            RuntimeType::Evm => {
                let evm_base_path = BasePath::new(
                    domain_config
                        .base_path
                        .config_dir(domain_config.chain_spec.id()),
                );

                let eth_provider =
                    EthProvider::<
                        evm_domain_runtime::TransactionConverter,
                        DefaultEthConfig<
                            FullClient<
                                DomainBlock,
                                evm_domain_runtime::RuntimeApi,
                                EVMDomainExecutorDispatch,
                            >,
                            FullBackend<DomainBlock>,
                        >,
                    >::new(Some(evm_base_path), domain_cli.additional_args());

                let domain_params = domain_service::DomainParams {
                    domain_id,
                    domain_config,
                    domain_created_at,
                    consensus_client,
                    consensus_offchain_tx_pool_factory,
                    consensus_network,
                    consensus_network_sync_oracle: consensus_sync_service.clone(),
                    operator_streams,
                    gossip_message_sink,
                    domain_message_receiver,
                    provider: eth_provider,
                    skip_empty_bundle_production: true,
                    maybe_operator_id: domain_cli.operator_id,
                };

                let mut domain_node = domain_service::new_full::<
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    evm_domain_runtime::RuntimeApi,
                    EVMDomainExecutorDispatch,
                    AccountId20,
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
}

/// Default sub directory to store network config.
pub(crate) const DEFAULT_NETWORK_CONFIG_PATH: &str = "network";

/// Create a Configuration object from the current object, port from `sc_cli::create_configuration`
/// and changed to take `chain_spec` as argument instead of construct one internally.
pub fn create_configuration<
    DCV: DefaultConfigurationValues,
    CC: CliConfiguration<DCV>,
    Cli: SubstrateCli,
>(
    cli_config: &CC,
    chain_spec: Box<dyn ChainSpec>,
    tokio_handle: tokio::runtime::Handle,
) -> sc_cli::Result<Configuration> {
    let is_dev = cli_config.is_dev()?;
    let base_path = cli_config
        .base_path()?
        .unwrap_or_else(|| BasePath::from_project("", "", &Cli::executable_name()));
    let config_dir = base_path.config_dir(chain_spec.id());
    let net_config_dir = config_dir.join(DEFAULT_NETWORK_CONFIG_PATH);
    let client_id = Cli::client_id();
    let database_cache_size = cli_config.database_cache_size()?.unwrap_or(1024);
    let database = cli_config.database()?.unwrap_or(
        #[cfg(feature = "rocksdb")]
        {
            Database::RocksDb
        },
        #[cfg(not(feature = "rocksdb"))]
        {
            Database::ParityDb
        },
    );
    let node_key = cli_config.node_key(&net_config_dir)?;
    let role = cli_config.role(is_dev)?;
    let max_runtime_instances = cli_config.max_runtime_instances()?.unwrap_or(8);
    let is_validator = role.is_authority();
    let keystore = cli_config.keystore_config(&config_dir)?;
    let telemetry_endpoints = cli_config.telemetry_endpoints(&chain_spec)?;
    let runtime_cache_size = cli_config.runtime_cache_size()?;

    Ok(Configuration {
        impl_name: Cli::impl_name(),
        impl_version: Cli::impl_version(),
        tokio_handle,
        transaction_pool: cli_config.transaction_pool(is_dev)?,
        network: cli_config.network_config(
            &chain_spec,
            is_dev,
            is_validator,
            net_config_dir,
            client_id.as_str(),
            cli_config.node_name()?.as_str(),
            node_key,
            DCV::p2p_listen_port(),
        )?,
        keystore,
        database: cli_config.database_config(&config_dir, database_cache_size, database)?,
        data_path: config_dir,
        trie_cache_maximum_size: cli_config.trie_cache_maximum_size()?,
        state_pruning: cli_config.state_pruning()?,
        blocks_pruning: cli_config.blocks_pruning()?,
        wasm_method: cli_config.wasm_method()?,
        wasm_runtime_overrides: cli_config.wasm_runtime_overrides(),
        rpc_addr: cli_config.rpc_addr(DCV::rpc_listen_port())?,
        rpc_methods: cli_config.rpc_methods()?,
        rpc_max_connections: cli_config.rpc_max_connections()?,
        rpc_cors: cli_config.rpc_cors(is_dev)?,
        rpc_max_request_size: cli_config.rpc_max_request_size()?,
        rpc_max_response_size: cli_config.rpc_max_response_size()?,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: cli_config.rpc_max_subscriptions_per_connection()?,
        rpc_port: DCV::rpc_listen_port(),
        prometheus_config: cli_config
            .prometheus_config(DCV::prometheus_listen_port(), &chain_spec)?,
        telemetry_endpoints,
        default_heap_pages: cli_config.default_heap_pages()?,
        offchain_worker: cli_config.offchain_worker(&role)?,
        force_authoring: cli_config.force_authoring()?,
        disable_grandpa: cli_config.disable_grandpa()?,
        dev_key_seed: cli_config.dev_key_seed(is_dev)?,
        tracing_targets: cli_config.tracing_targets()?,
        tracing_receiver: cli_config.tracing_receiver()?,
        chain_spec,
        max_runtime_instances,
        announce_block: cli_config.announce_block()?,
        role,
        base_path,
        informant_output_format: Default::default(),
        runtime_cache_size,
    })
}
