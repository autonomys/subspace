mod consensus;
mod domain;
mod shared;

use crate::commands::run::consensus::{
    create_consensus_chain_configuration, ConsensusChainConfiguration, ConsensusChainOptions,
};
use crate::commands::run::domain::{
    create_domain_configuration, run_evm_domain, DomainOptions, DomainStartOptions,
};
use crate::commands::shared::init_logger;
use crate::{set_default_ss58_version, Error, PosTable};
use clap::Parser;
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_client_operator::fetch_domain_bootstrap_info;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use futures::FutureExt;
use sc_cli::Signals;
use sc_consensus_slots::SlotProportion;
use sc_storage_monitor::StorageMonitorService;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_core::traits::SpawnEssentialNamed;
use sp_messenger::messages::ChainId;
use std::env;
use subspace_runtime::{Block, RuntimeApi};
use tracing::{debug, error, info, info_span, warn};

/// Options for running a node
#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Consensus chain options
    #[clap(flatten)]
    consensus: ConsensusChainOptions,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    domain_args: Vec<String>,
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
    let enable_color = init_logger().enable_color;
    raise_fd_limit();

    let signals = Signals::capture()?;

    let RunOptions {
        consensus,
        domain_args,
    } = run_options;

    let domain_options = (!domain_args.is_empty())
        .then(|| DomainOptions::parse_from(env::args().take(1).chain(domain_args)));

    let ConsensusChainConfiguration {
        maybe_tmp_dir: _maybe_tmp_dir,
        subspace_configuration,
        dev,
        pot_external_entropy,
        storage_monitor,
    } = create_consensus_chain_configuration(consensus, enable_color, domain_options.is_some())?;

    let maybe_domain_configuration = domain_options
        .map(|domain_options| {
            create_domain_configuration(&subspace_configuration, dev, domain_options, enable_color)
        })
        .transpose()?;

    set_default_ss58_version(subspace_configuration.chain_spec.as_ref());

    let base_path = subspace_configuration.base_path.path().to_path_buf();

    info!("Subspace");
    info!("✌️  version {}", env!("SUBSTRATE_CLI_IMPL_VERSION"));
    info!("❤️  by {}", env!("CARGO_PKG_AUTHORS"));
    info!(
        "📋 Chain specification: {}",
        subspace_configuration.chain_spec.name()
    );
    info!("🏷  Node name: {}", subspace_configuration.network.node_name);
    info!("💾 Node path: {}", base_path.display());

    let mut task_manager = {
        let consensus_state_pruning_mode = subspace_configuration
            .state_pruning
            .clone()
            .unwrap_or_default();
        let consensus_chain_node = {
            let span = info_span!("Consensus");
            let _enter = span.enter();

            let partial_components = subspace_service::new_partial::<PosTable, RuntimeApi>(
                &subspace_configuration,
                &pot_external_entropy,
            )
            .map_err(|error| {
                sc_service::Error::Other(format!(
                    "Failed to build a full subspace node 1: {error:?}"
                ))
            })?;

            let full_node_fut = subspace_service::new_full::<PosTable, _>(
                subspace_configuration,
                partial_components,
                true,
                SlotProportion::new(3f32 / 4f32),
            );

            full_node_fut.await.map_err(|error| {
                sc_service::Error::Other(format!(
                    "Failed to build a full subspace node 2: {error:?}"
                ))
            })?
        };

        StorageMonitorService::try_spawn(
            storage_monitor,
            base_path,
            &consensus_chain_node.task_manager.spawn_essential_handle(),
        )
        .map_err(|error| {
            sc_service::Error::Other(format!("Failed to start storage monitor: {error:?}"))
        })?;

        // Run a domain
        if let Some(domain_configuration) = maybe_domain_configuration {
            let mut xdm_gossip_worker_builder = GossipWorkerBuilder::new();
            let gossip_message_sink = xdm_gossip_worker_builder.gossip_msg_sink();
            let (domain_message_sink, domain_message_receiver) =
                tracing_unbounded("domain_message_channel", 100);

            // Start relayer for consensus chain
            {
                let span = info_span!("Consensus");
                let _enter = span.enter();

                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-chain-relayer",
                        None,
                        Box::pin(
                            domain_client_message_relayer::worker::relay_consensus_chain_messages(
                                consensus_chain_node.client.clone(),
                                consensus_state_pruning_mode,
                                consensus_chain_node.sync_service.clone(),
                                xdm_gossip_worker_builder.gossip_msg_sink(),
                            ),
                        ),
                    );

                let (consensus_msg_sink, consensus_msg_receiver) =
                    tracing_unbounded("consensus_message_channel", 100);

                // Start cross domain message listener for Consensus chain to receive messages from domains in the network
                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-message-listener",
                        None,
                        Box::pin(
                            cross_domain_message_gossip::start_cross_chain_message_listener(
                                ChainId::Consensus,
                                consensus_chain_node.client.clone(),
                                consensus_chain_node.transaction_pool.clone(),
                                consensus_chain_node.network_service.clone(),
                                consensus_msg_receiver,
                            ),
                        ),
                    );

                xdm_gossip_worker_builder
                    .push_chain_tx_pool_sink(ChainId::Consensus, consensus_msg_sink);
                xdm_gossip_worker_builder.push_chain_tx_pool_sink(
                    ChainId::Domain(domain_configuration.domain_id),
                    domain_message_sink,
                );

                let cross_domain_message_gossip_worker = xdm_gossip_worker_builder
                    .build::<Block, _, _>(
                        consensus_chain_node.network_service.clone(),
                        consensus_chain_node.xdm_gossip_notification_service,
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
            }

            let domain_start_options = DomainStartOptions {
                consensus_client: consensus_chain_node.client,
                consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(
                    consensus_chain_node.transaction_pool,
                ),
                consensus_network: consensus_chain_node.network_service,
                block_importing_notification_stream: consensus_chain_node
                    .block_importing_notification_stream,
                new_slot_notification_stream: consensus_chain_node.new_slot_notification_stream,
                consensus_network_sync_oracle: consensus_chain_node.sync_service,
                domain_message_receiver,
                gossip_message_sink,
            };

            consensus_chain_node
                .task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking(
                    "domain",
                    Some("domains"),
                    Box::pin(async move {
                        let span = info_span!("Domain");
                        let _enter = span.enter();

                        let bootstrap_result_fut = fetch_domain_bootstrap_info::<DomainBlock, _, _>(
                            &*domain_start_options.consensus_client,
                            domain_configuration.domain_id,
                        );
                        let bootstrap_result = match bootstrap_result_fut.await {
                            Ok(bootstrap_result) => bootstrap_result,
                            Err(error) => {
                                error!(%error, "Domain bootstrapper exited with an error");
                                return;
                            }
                        };

                        let start_evm_domain = run_evm_domain(
                            bootstrap_result,
                            domain_configuration,
                            domain_start_options,
                        );

                        if let Err(error) = start_evm_domain.await {
                            error!(%error, "Domain starter exited with an error");
                        }
                    }),
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
