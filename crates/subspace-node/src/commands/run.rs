mod consensus;
mod domain;
mod shared;
mod substrate;

use crate::commands::run::consensus::{
    create_consensus_chain_configuration, ConsensusChainConfiguration, ConsensusChainOptions,
};
use crate::domain::{DomainCli, DomainInstanceStarter};
use crate::{set_default_ss58_version, Error, PosTable};
use clap::Parser;
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_client_operator::fetch_domain_bootstrap_info;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use futures::FutureExt;
use sc_cli::Signals;
use sc_consensus_slots::SlotProportion;
use sc_network::config::MultiaddrWithPeerId;
use sc_storage_monitor::StorageMonitorService;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::DomainId;
use sp_messenger::messages::ChainId;
use std::collections::HashMap;
use subspace_runtime::{Block, ExecutorDispatch, RuntimeApi};
use tokio::runtime::Handle;
use tracing::{debug, error, info, info_span, warn, Span};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

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
        consensus,
        domain_args,
    } = run_options;

    let domain_cli = (!domain_args.is_empty()).then(|| DomainCli::new(domain_args.into_iter()));

    let ConsensusChainConfiguration {
        maybe_tmp_dir: _maybe_tmp_dir,
        subspace_configuration,
        pot_external_entropy,
        storage_monitor,
    } = create_consensus_chain_configuration(consensus, enable_color, domain_cli.is_some())?;

    set_default_ss58_version(subspace_configuration.chain_spec.as_ref());

    info!("Subspace");
    info!("✌️  version {}", env!("SUBSTRATE_CLI_IMPL_VERSION"));
    info!("❤️  by {}", env!("CARGO_PKG_AUTHORS"));
    info!(
        "📋 Chain specification: {}",
        subspace_configuration.chain_spec.name()
    );
    info!("🏷  Node name: {}", subspace_configuration.network.node_name);
    info!(
        "💾 Node path: {}",
        subspace_configuration.base_path.path().display()
    );

    let root_span = Span::current();

    let mut task_manager = {
        let base_path = subspace_configuration.base_path.path().to_path_buf();
        let database_source = subspace_configuration.database.clone();

        let mut domains_bootstrap_nodes: HashMap<DomainId, Vec<MultiaddrWithPeerId>> =
            subspace_configuration
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

        let consensus_state_pruning_mode = subspace_configuration
            .state_pruning
            .clone()
            .unwrap_or_default();
        let consensus_chain_node = {
            let span = info_span!("Consensus");
            let _enter = span.enter();

            let partial_components = subspace_service::new_partial::<
                PosTable,
                RuntimeApi,
                ExecutorDispatch,
            >(&subspace_configuration, &pot_external_entropy)
            .map_err(|error| {
                sc_service::Error::Other(format!(
                    "Failed to build a full subspace node 1: {error:?}"
                ))
            })?;

            let full_node_fut = subspace_service::new_full::<PosTable, _, _>(
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
            database_source,
            &consensus_chain_node.task_manager.spawn_essential_handle(),
        )
        .map_err(|error| {
            sc_service::Error::Other(format!("Failed to start storage monitor: {error:?}"))
        })?;

        // Run a domain node.
        if let Some(mut domain_cli) = domain_cli {
            // Start relayer for consensus chain
            let mut xdm_gossip_worker_builder = GossipWorkerBuilder::new();
            {
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
            }

            let span = info_span!(parent: &root_span, "Domain");
            let _enter = span.enter();

            let domain_id = domain_cli.domain_id;

            if domain_cli.run.network_params.bootnodes.is_empty() {
                domain_cli.run.network_params.bootnodes = domains_bootstrap_nodes
                    .remove(&domain_id)
                    .unwrap_or_default();
            }

            let (domain_message_sink, domain_message_receiver) =
                tracing_unbounded("domain_message_channel", 100);

            xdm_gossip_worker_builder
                .push_chain_tx_pool_sink(ChainId::Domain(domain_id), domain_message_sink);

            let domain_starter = DomainInstanceStarter {
                domain_cli,
                base_path,
                tokio_handle: Handle::current(),
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
                        let bootstrap_result_fut = fetch_domain_bootstrap_info::<DomainBlock, _, _>(
                            &*domain_starter.consensus_client,
                            domain_id,
                        );
                        let bootstrap_result = match bootstrap_result_fut.await {
                            Ok(bootstrap_result) => bootstrap_result,
                            Err(error) => {
                                error!(%error, "Domain bootstrapper exited with an error");
                                return;
                            }
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
