use crate::cli::Cli;
use crate::domain::{DomainCli, DomainInstanceStarter};
use crate::{pot_external_entropy, set_default_ss58_version, Error, PosTable};
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_client_operator::Bootstrapper;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use sc_cli::SubstrateCli;
use sc_consensus_slots::SlotProportion;
use sc_network::config::NodeKeyConfig;
use sc_service::config::KeystoreConfig;
use sc_service::DatabaseSource;
use sc_storage_monitor::StorageMonitorService;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_core::traits::SpawnEssentialNamed;
use sp_messenger::messages::ChainId;
use subspace_runtime::{Block, ExecutorDispatch, RuntimeApi};
use subspace_service::{DsnConfig, SubspaceConfiguration, SubspaceNetworking};

/// Default run command for node
pub fn run(cli: Cli) -> Result<(), Error> {
    let mut runner = cli.create_runner(&cli.run)?;
    set_default_ss58_version(&runner.config().chain_spec);
    // Change default paths to Subspace structure
    {
        let config = runner.config_mut();
        config.database = DatabaseSource::ParityDb {
            path: config.base_path.path().join("db"),
        };
        // Consensus node doesn't use keystore
        config.keystore = KeystoreConfig::InMemory;
        if let Some(net_config_path) = &mut config.network.net_config_path {
            *net_config_path = config.base_path.path().join("network");
            config.network.node_key = NodeKeyConfig::Ed25519(sc_network::config::Secret::File(
                net_config_path.join("secret_ed25519"),
            ));
        }
    }
    runner.run_node_until_exit(|consensus_chain_config| async move {
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
            let span = sc_tracing::tracing::info_span!(
                sc_tracing::logging::PREFIX_LOG_SPAN,
                name = "Consensus"
            );
            let _enter = span.enter();

            let pot_external_entropy = pot_external_entropy(&consensus_chain_config, &cli)?;

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

                let dsn_bootstrap_nodes = if cli.dsn_bootstrap_nodes.is_empty() {
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
                    cli.dsn_bootstrap_nodes
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
                    listen_on: cli.dsn_listen_on,
                    bootstrap_nodes: dsn_bootstrap_nodes,
                    reserved_peers: cli.dsn_reserved_peers,
                    // Override enabling private IPs with --dev
                    allow_non_global_addresses_in_dht: cli.dsn_enable_private_ips
                        || cli.run.shared_params.dev,
                    max_in_connections: cli.dsn_in_connections,
                    max_out_connections: cli.dsn_out_connections,
                    max_pending_in_connections: cli.dsn_pending_in_connections,
                    max_pending_out_connections: cli.dsn_pending_out_connections,
                    external_addresses: cli.dsn_external_addresses,
                    // Override initial Kademlia bootstrapping  with --dev
                    disable_bootstrap_on_start: cli.dsn_disable_bootstrap_on_start
                        || cli.run.shared_params.dev,
                }
            };

            let consensus_chain_config = SubspaceConfiguration {
                base: consensus_chain_config,
                // Domain node needs slots notifications for bundle production.
                force_new_slot_notifications: !cli.domain_args.is_empty(),
                subspace_networking: SubspaceNetworking::Create { config: dsn_config },
                sync_from_dsn: cli.sync_from_dsn,
                enable_subspace_block_relay: cli.enable_subspace_block_relay,
                // Timekeeper is enabled if `--dev` is used
                is_timekeeper: cli.timekeeper || cli.run.shared_params.dev,
                timekeeper_cpu_cores: cli.timekeeper_cpu_cores,
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
            cli.storage_monitor,
            database_source,
            &consensus_chain_node.task_manager.spawn_essential_handle(),
        )
        .map_err(|error| {
            sc_service::Error::Other(format!("Failed to start storage monitor: {error:?}"))
        })?;

        // Run a domain node.
        if !cli.domain_args.is_empty() {
            let span = sc_tracing::tracing::info_span!(
                sc_tracing::logging::PREFIX_LOG_SPAN,
                name = "Domain"
            );
            let _enter = span.enter();

            let mut domain_cli = DomainCli::new(cli.domain_args.into_iter());

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
                let span = sc_tracing::tracing::info_span!(
                    sc_tracing::logging::PREFIX_LOG_SPAN,
                    name = "Consensus"
                );
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
                                Err(err) => {
                                    log::error!("Domain bootstrapper exited with an error {err:?}");
                                    return;
                                }
                                Ok(res) => res,
                            };
                        if let Err(error) = domain_starter.start(bootstrap_result).await {
                            log::error!("Domain starter exited with an error {error:?}");
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
        Ok::<_, Error>(consensus_chain_node.task_manager)
    })
}
