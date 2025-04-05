//! Subspace malicious operator node.

use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_client_operator::fetch_domain_bootstrap_info;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use sc_cli::{ChainSpec, CliConfiguration, SubstrateCli};
use sc_consensus_slots::SlotProportion;
use sc_consensus_subspace::archiver::CreateObjectMappings;
use sc_network::config::MultiaddrWithPeerId;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use serde_json::Value;
use sp_core::crypto::Ss58AddressFormat;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::DomainId;
use sp_messenger::messages::ChainId;
use std::collections::HashMap;
use subspace_malicious_operator::malicious_domain_instance_starter::DomainInstanceStarter;
use subspace_malicious_operator::{create_malicious_operator_configuration, Cli, DomainCli};
use subspace_networking::libp2p::Multiaddr;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_runtime::{Block, RuntimeApi};
use subspace_service::config::{SubspaceConfiguration, SubspaceNetworking};
use subspace_service::dsn::DsnConfig;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type PosTable = ChiaTable;

/// Subspace node error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Subspace service error.
    #[error(transparent)]
    SubspaceService(#[from] subspace_service::Error),

    /// CLI error.
    #[error(transparent)]
    SubstrateCli(#[from] sc_cli::Error),

    /// Substrate service error.
    #[error(transparent)]
    SubstrateService(#[from] sc_service::Error),

    /// Other kind of error.
    #[error("Other: {0}")]
    Other(String),
}

impl From<String> for Error {
    #[inline]
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

fn set_default_ss58_version<C: AsRef<dyn ChainSpec>>(chain_spec: C) {
    let maybe_ss58_address_format = chain_spec
        .as_ref()
        .properties()
        .get("ss58Format")
        .map(|v| {
            v.as_u64()
                .expect("ss58Format must always be an unsigned number; qed")
        })
        .map(|v| {
            v.try_into()
                .expect("ss58Format must always be within u16 range; qed")
        })
        .map(Ss58AddressFormat::custom);

    if let Some(ss58_address_format) = maybe_ss58_address_format {
        sp_core::crypto::set_default_ss58_version(ss58_address_format);
    }
}

#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
fn main() -> Result<(), Error> {
    let cli = Cli::from_args();

    let sudo_account = cli.sudo_account();
    let runner = cli.create_runner(&cli.run)?;
    set_default_ss58_version(&runner.config().chain_spec);
    runner.run_node_until_exit(|mut consensus_chain_config| async move {
        // In case there are bootstrap nodes specified explicitly, ignore those that are in the
        // chain spec
        if !cli.run.network_params.bootnodes.is_empty() {
            consensus_chain_config.network.boot_nodes = cli.run.network_params.bootnodes;
        }

        // Enable MMR indexing so the malicious operator can generate fraud proof
        // otherwise the node will stop running
        consensus_chain_config.offchain_worker.indexing_enabled = true;

        let tokio_handle = consensus_chain_config.tokio_handle.clone();
        let base_path = consensus_chain_config.base_path.path().to_path_buf();

        let mut domains_bootstrap_nodes: HashMap<DomainId, Vec<MultiaddrWithPeerId>> =
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

        let (consensus_chain_node, consensus_keystore) = {
            let span = sc_tracing::tracing::info_span!(
                sc_tracing::logging::PREFIX_LOG_SPAN,
                name = "Consensus"
            );
            let _enter = span.enter();

            let pot_external_entropy: Vec<u8> = consensus_chain_config
                .chain_spec
                .properties()
                .get("potExternalEntropy")
                .map(|d| match d.clone() {
                    Value::String(s) => Ok(s.into_bytes()),
                    Value::Null => Ok(Vec::new()),
                    _ => Err(sc_service::Error::Other(
                        "Failed to decode PoT initial key".to_string(),
                    )),
                })
                .transpose()?
                .unwrap_or_default();

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

                let dsn_bootstrap_nodes = consensus_chain_config
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
                    .unwrap_or_default();

                // Convert keypair from Substrate to libp2p type
                let keypair = subspace_networking::libp2p::identity::Keypair::ed25519_from_bytes(
                    network_keypair.secret().to_bytes(),
                )
                .expect("Keypair-from-protobuf decoding should succeed.");

                DsnConfig {
                    keypair,
                    network_path: consensus_chain_config.base_path.path().join("network"),
                    listen_on: vec!["/ip4/0.0.0.0/tcp/30433"
                        .parse::<Multiaddr>()
                        .expect("Manual setting")],
                    bootstrap_nodes: dsn_bootstrap_nodes,
                    reserved_peers: vec![],
                    allow_non_global_addresses_in_dht: false,
                    max_in_connections: 50,
                    max_out_connections: 150,
                    max_pending_in_connections: 100,
                    max_pending_out_connections: 150,
                    external_addresses: vec![],
                }
            };

            let consensus_chain_config = SubspaceConfiguration {
                base: consensus_chain_config,
                // Domain node needs slots notifications for bundle production.
                force_new_slot_notifications: true,
                create_object_mappings: CreateObjectMappings::No,
                subspace_networking: SubspaceNetworking::Create { config: dsn_config },
                sync: Default::default(),
                is_timekeeper: false,
                timekeeper_cpu_cores: Default::default(),
            };

            let partial_components = subspace_service::new_partial::<PosTable, RuntimeApi>(
                &consensus_chain_config,
                false,
                &pot_external_entropy,
            )
            .map_err(|error| {
                sc_service::Error::Other(format!("Failed to build a full subspace node: {error:?}"))
            })?;

            let keystore = partial_components.keystore_container.keystore();

            let consensus_chain_node =
                subspace_service::new_full::<PosTable, _>(
                consensus_chain_config,
                partial_components,
                None,
                true,
                SlotProportion::new(3f32 / 4f32),
                None,
            )
            .await
            .map_err(|error| {
                sc_service::Error::Other(format!("Failed to build a full subspace node: {error:?}"))
            })?;

            (consensus_chain_node, keystore)
        };

        // Run a domain node.
        if cli.domain_args.is_empty() {
            return Err(Error::Other(
                "The domain args must be specified for the malicious operator".to_string(),
            ));
        } else {
            let span = sc_tracing::tracing::info_span!(
                sc_tracing::logging::PREFIX_LOG_SPAN,
                name = "Domain"
            );
            let _enter = span.enter();

            let mut domain_cli = DomainCli::new(cli.domain_args.into_iter());

            let domain_id = domain_cli.domain_id.into();

            if domain_cli.run.network_params.bootnodes.is_empty() {
                domain_cli.run.network_params.bootnodes = domains_bootstrap_nodes
                    .remove(&domain_id)
                    .unwrap_or_default();
            }

            // start relayer for consensus chain
            let mut xdm_gossip_worker_builder = GossipWorkerBuilder::new();
            let consensus_msg_receiver = {
                let span = sc_tracing::tracing::info_span!(
                    sc_tracing::logging::PREFIX_LOG_SPAN,
                    name = "Consensus"
                );
                let _enter = span.enter();

                let channel_update_worker =
                    domain_client_message_relayer::worker::gossip_channel_updates::<_, _, Block, _>(
                        ChainId::Consensus,
                        consensus_chain_node.client.clone(),
                        consensus_chain_node.sync_service.clone(),
                        xdm_gossip_worker_builder.gossip_msg_sink(),
                    );

                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-chain-channel-update-worker",
                        None,
                        Box::pin(channel_update_worker),
                    );

                let (consensus_msg_sink, consensus_msg_receiver) =
                    tracing_unbounded("consensus_message_channel", 100);

                xdm_gossip_worker_builder.push_chain_sink(ChainId::Consensus, consensus_msg_sink);
                consensus_msg_receiver
            };

            let (domain_message_sink, domain_message_receiver) =
                tracing_unbounded("domain_message_channel", 100);

            xdm_gossip_worker_builder
                .push_chain_sink(ChainId::Domain(domain_id), domain_message_sink);

            let domain_config = {
                let chain_id = domain_cli.run.chain_id(domain_cli.run.is_dev()?)?;
                let domain_spec =
                subspace_malicious_operator::create_domain_spec(chain_id.as_str())?;
                create_malicious_operator_configuration::<DomainCli>(
                    domain_id,
                    base_path.into(),
                    &domain_cli,
                    domain_spec,
                    tokio_handle,
                )?
            };

            let domain_backend = sc_service::new_db_backend::<DomainBlock>(
                    domain_config.db_config(),
                )
                .map_err(|error| Error::Other(format!("Failed to create domain backend: {error:?}")))?;

            let domain_starter = DomainInstanceStarter {
                domain_cli,
                consensus_client: consensus_chain_node.client.clone(),
                consensus_keystore,
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
                domain_backend,
                domain_config,
            };

            let consensus_network_service = consensus_chain_node.network_service.clone();
            let consensus_task_spawn_essential_handler = consensus_chain_node.task_manager.spawn_essential_handle();
            let consensus_sync_service = consensus_chain_node.sync_service.clone();
            consensus_chain_node
                .task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking(
                    "domain",
                    None,
                    Box::pin(async move {
                        let bootstrap_result_fut = fetch_domain_bootstrap_info::<DomainBlock, _, _, _>(
                            &*domain_starter.consensus_client,
                            &*domain_starter.domain_backend,
                            domain_id,
                        );
                        let bootstrap_result = match bootstrap_result_fut.await {
                            Ok(bootstrap_result) => bootstrap_result,
                            Err(error) => {
                                log::error!("Domain bootstrapper exited with an error {error:?}");
                                return;
                            }
                        };

                        match domain_starter.start(bootstrap_result, sudo_account).await {
                            Ok(domain_code_executor) => {
                                let span = sc_tracing::tracing::info_span!(
                                    sc_tracing::logging::PREFIX_LOG_SPAN,
                                    name = "Consensus"
                                );
                                let _enter = span.enter();
                                // Start cross domain message listener for Consensus chain to receive messages from domains in the network
                                let consensus_listener =
                                    cross_domain_message_gossip::start_cross_chain_message_listener::<
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                    >(
                                        ChainId::Consensus,
                                        consensus_chain_node.client.clone(),
                                        consensus_chain_node.client.clone(),
                                        consensus_chain_node.transaction_pool.clone(),
                                        consensus_network_service,
                                        consensus_msg_receiver,
                                        domain_code_executor,
                                        consensus_sync_service,
                                    );

                                consensus_task_spawn_essential_handler
                                    .spawn_essential_blocking(
                                        "consensus-message-listener",
                                        None,
                                        Box::pin(consensus_listener),
                                    );
                            }
                            Err(err) => {
                                log::error!("Domain starter exited with an error {err:?}");
                            }
                        }
                    }),
                );

            let cross_domain_message_gossip_worker = xdm_gossip_worker_builder
                .build::<Block, _, _>(
                    consensus_chain_node.network_service,
                    consensus_chain_node.xdm_gossip_notification_service,
                    consensus_chain_node.sync_service,
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
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use sc_cli::Database;

    #[test]
    fn rocksdb_disabled_in_substrate() {
        assert_eq!(
            Database::variants(),
            &["paritydb", "paritydb-experimental", "auto"],
        );
    }
}
