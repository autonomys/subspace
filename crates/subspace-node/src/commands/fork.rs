use crate::commands::run::consensus::{
    ConsensusChainConfiguration, ConsensusChainOptions, create_consensus_chain_configuration,
};
use crate::commands::run::domain::{
    DomainOptions, DomainStartOptions, create_domain_configuration, run_domain,
};
use crate::commands::run::{ensure_block_and_state_pruning_params, raise_fd_limit};
use crate::{Error, PosTable, set_default_ss58_version};
use clap::Parser;
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_block_builder::{BlockBuilderApi, TrieBackendApi, TrieDeltaBackendFor};
use domain_client_operator::fetch_domain_bootstrap_info;
use domain_client_operator::snap_sync::{
    BlockImportingAcknowledgement, ConsensusChainSyncParams, SnapSyncOrchestrator,
};
use domain_runtime_primitives::opaque::Block as DomainBlock;
use frame_support::{Blake2_128Concat, StorageHasher};
use frame_system::AccountInfo;
use futures::FutureExt;
use futures::stream::StreamExt;
use pallet_balances::AccountData;
use parity_scale_codec::Encode;
use sc_cli::Signals;
use sc_client_api::{BlockBackend, ExecutorProvider, HeaderBackend};
use sc_consensus::block_import::{BlockImportParams, ForkChoiceStrategy};
use sc_consensus::{BlockImport, StateAction, StorageChanges};
use sc_consensus_slots::SlotProportion;
use sc_domains::domain_block_er::receipt_receiver::DomainBlockERReceiver;
use sc_storage_monitor::StorageMonitorService;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiError, CallApiAt, ProvideRuntimeApi};
use sp_blockchain::ApplyExtrinsicFailed;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::SubspaceApi;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_keyring::Sr25519Keyring;
use sp_messenger::messages::ChainId;
use sp_runtime::TransactionOutcome;
use sp_runtime::traits::{Block as BlockT, HashingFor, Header, One};
use sp_state_machine::OverlayedChanges;
use std::path::Path;
use std::sync::Arc;
use std::{env, fs, io};
use subspace_core_primitives::PublicKey;
use subspace_logging::init_logger;
use subspace_metrics::{RegistryAdapter, start_prometheus_metrics_server};
use subspace_runtime::{Block, RuntimeApi};
use subspace_runtime_primitives::{AI3, Nonce};
use subspace_service::config::{ChainSyncMode, SubspaceNetworking};
use tracing::{debug, error, info, info_span};

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

/// Default run command for node
#[tokio::main]
#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
pub async fn run(run_options: RunOptions) -> Result<(), Error> {
    init_logger();
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
        mut subspace_configuration,
        dev,
        pot_external_entropy,
        storage_monitor,
        mut prometheus_configuration,
    } = create_consensus_chain_configuration(consensus, domain_options.is_some())?;

    let maybe_domain_configuration = domain_options
        .map(|domain_options| {
            create_domain_configuration(&subspace_configuration, dev, domain_options)
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

    let fork_id = subspace_configuration
        .base
        .chain_spec
        .fork_id()
        .map(String::from);
    let snap_sync_orchestrator = if maybe_domain_configuration.is_some()
        && subspace_configuration.sync == ChainSyncMode::Snap
    {
        Some(Arc::new(SnapSyncOrchestrator::new()))
    } else {
        None
    };

    if maybe_domain_configuration.is_some() {
        // TODO: currently, we set consensus block and state pruning to challenge period
        //  when the node is running a domain node.
        //  But is there a situation when challenge period is not enough?
        //  If we do such a scenario, we would rather keep the consensus block and state pruning
        //  to archive-canonical
        // we supress warning here since the consensus has different defaults when running without
        // domain node, even if user do not override them, the default vaules are low enough to
        // trigger a warning and confusing user. Instead supress them
        ensure_block_and_state_pruning_params(&mut subspace_configuration.base, true)
    }

    let mut task_manager = {
        let subspace_link;
        let consensus_chain_node = {
            let span = info_span!("Consensus");
            let _enter = span.enter();

            let partial_components = subspace_service::new_partial::<PosTable, RuntimeApi>(
                &subspace_configuration,
                match subspace_configuration.sync {
                    ChainSyncMode::Full => false,
                    ChainSyncMode::Snap => true,
                },
                &pot_external_entropy,
            )
            .map_err(|error| {
                sc_service::Error::Other(format!(
                    "Failed to build a full subspace node 1: {error:?}"
                ))
            })?;

            subspace_link = partial_components.other.subspace_link.clone();

            let full_node_fut = subspace_service::new_full::<PosTable, _>(
                subspace_configuration,
                partial_components,
                prometheus_configuration
                    .as_mut()
                    .map(|prometheus_configuration| {
                        &mut prometheus_configuration.prometheus_registry
                    }),
                true,
                SlotProportion::new(3f32 / 4f32),
                snap_sync_orchestrator
                    .as_ref()
                    .map(|orchestrator| orchestrator.consensus_snap_sync_target_block_receiver()),
            );

            full_node_fut.await.map_err(|error| {
                sc_service::Error::Other(format!(
                    "Failed to build a full subspace node 3: {error:?}"
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
        if let Some(mut domain_configuration) = maybe_domain_configuration {
            ensure_block_and_state_pruning_params(&mut domain_configuration.domain_config, false);
            let mut xdm_gossip_worker_builder = GossipWorkerBuilder::new();
            let gossip_message_sink = xdm_gossip_worker_builder.gossip_msg_sink();
            let (domain_message_sink, domain_message_receiver) =
                tracing_unbounded("domain_message_channel", 100);
            let (consensus_msg_sink, consensus_msg_receiver) =
                tracing_unbounded("consensus_message_channel", 100);

            // Start XDM related workers for consensus chain
            {
                let span = info_span!("Consensus");
                let _enter = span.enter();

                // Start cross domain message listener for Consensus chain to receive messages from domains in the network
                let domain_code_executor: sc_domains::RuntimeExecutor =
                    sc_service::new_wasm_executor(&domain_configuration.domain_config.executor);
                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-message-listener",
                        None,
                        Box::pin(
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
                                consensus_chain_node.network_service.clone(),
                                consensus_msg_receiver,
                                domain_code_executor.into(),
                                consensus_chain_node.sync_service.clone(),
                            ),
                        ),
                    );

                consensus_chain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "consensus-chain-channel-update-worker",
                        None,
                        Box::pin(
                            domain_client_message_relayer::worker::gossip_channel_updates::<
                                _,
                                _,
                                Block,
                                _,
                            >(
                                ChainId::Consensus,
                                consensus_chain_node.client.clone(),
                                consensus_chain_node.sync_service.clone(),
                                xdm_gossip_worker_builder.gossip_msg_sink(),
                            ),
                        ),
                    );

                xdm_gossip_worker_builder.push_chain_sink(ChainId::Consensus, consensus_msg_sink);
                xdm_gossip_worker_builder.push_chain_sink(
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
            };

            let domain_backend = {
                let consensus_best_hash = consensus_chain_node.client.info().best_hash;
                let chain_constants = consensus_chain_node
                    .client
                    .runtime_api()
                    .chain_constants(consensus_best_hash)
                    .map_err(|err| Error::Other(err.to_string()))?;
                Arc::new(
                    sc_client_db::Backend::new(
                        domain_configuration.domain_config.db_config(),
                        chain_constants.confirmation_depth_k().into(),
                    )
                    .map_err(|error| {
                        Error::Other(format!("Failed to create domain backend: {error:?}"))
                    })?,
                )
            };

            let domain_start_options = DomainStartOptions {
                consensus_client: consensus_chain_node.client.clone(),
                consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(
                    consensus_chain_node.transaction_pool,
                ),
                consensus_network: consensus_chain_node.network_service.clone(),
                block_importing_notification_stream: consensus_chain_node
                    .block_importing_notification_stream,
                pot_slot_info_stream: consensus_chain_node.pot_slot_info_stream,
                consensus_network_sync_oracle: consensus_chain_node.sync_service.clone(),
                domain_message_receiver,
                gossip_message_sink,
                domain_backend,
            };

            consensus_chain_node
                .task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking("domain", Some("domains"), {
                    let consensus_chain_network_service =
                        consensus_chain_node.network_service.clone();
                    let consensus_chain_sync_service = consensus_chain_node.sync_service.clone();
                    Box::pin(async move {
                        let span = info_span!("Domain");
                        let _enter = span.enter();

                        let maybe_snap_sync_params =
                            if let Some(snap_sync_orchestrator) = snap_sync_orchestrator {
                                let domain_block_er_receiver = DomainBlockERReceiver::new(
                                    domain_configuration.domain_id,
                                    fork_id,
                                    domain_start_options.consensus_client.clone(),
                                    consensus_chain_network_service,
                                    consensus_chain_sync_service,
                                );

                                let maybe_last_confirmed_er = domain_block_er_receiver
                                    .get_last_confirmed_domain_block_receipt()
                                    .await;

                                let Some(last_confirmed_er) = maybe_last_confirmed_er else {
                                    error!("Failed to get last confirmed domain block ER");
                                    return;
                                };

                                // unblock consensus snap sync
                                snap_sync_orchestrator.unblock_consensus_snap_sync(
                                    *last_confirmed_er.consensus_block_number(),
                                );

                                Some((snap_sync_orchestrator, last_confirmed_er))
                            } else {
                                None
                            };

                        let bootstrap_result_fut =
                            fetch_domain_bootstrap_info::<DomainBlock, _, _, _>(
                                &*domain_start_options.consensus_client,
                                &*domain_start_options.domain_backend,
                                domain_configuration.domain_id,
                            );

                        let bootstrap_result = match bootstrap_result_fut.await {
                            Ok(bootstrap_result) => bootstrap_result,
                            Err(error) => {
                                error!(%error, "Domain bootstrapper exited with an error");
                                return;
                            }
                        };

                        let consensus_chain_sync_params = maybe_snap_sync_params.map(
                            |(snap_sync_orchestrator, last_confirmed_er)| {
                                ConsensusChainSyncParams {
                                    snap_sync_orchestrator,
                                    last_domain_block_er: last_confirmed_er,
                                    block_importing_notification_stream: Box::new(
                                        subspace_link
                                            .block_importing_notification_stream()
                                            .subscribe()
                                            .map(|block| BlockImportingAcknowledgement {
                                                block_number: block.block_number,
                                                acknowledgement_sender: block
                                                    .acknowledgement_sender,
                                            }),
                                    ),
                                }
                            },
                        );

                        let start_domain = run_domain(
                            bootstrap_result,
                            domain_configuration,
                            domain_start_options,
                            consensus_chain_sync_params,
                        );

                        if let Err(error) = start_domain.await {
                            error!(%error, "Domain starter exited with an error");
                        }
                    })
                });
        };

        consensus_chain_node.network_starter.start_network();

        if let Some(prometheus_configuration) = prometheus_configuration.take() {
            let metrics_server = start_prometheus_metrics_server(
                vec![prometheus_configuration.listen_on],
                RegistryAdapter::Both(
                    prometheus_configuration.prometheus_registry,
                    prometheus_configuration.substrate_registry,
                ),
            )
            .map_err(|error| Error::SubspaceService(error.into()))?
            .map(|error| {
                debug!(?error, "Metrics server error.");
            });

            consensus_chain_node.task_manager.spawn_handle().spawn(
                "metrics-server",
                None,
                metrics_server,
            );
        };

        consensus_chain_node.task_manager
    };

    signals
        .run_until_signal(task_manager.future().fuse())
        .await
        .map_err(Into::into)
}
