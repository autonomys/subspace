// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Subspace node implementation.

use cross_domain_message_gossip::{cdm_gossip_peers_set_config, GossipWorker};
use frame_benchmarking_cli::BenchmarkCmd;
use futures::future::TryFutureExt;
use futures::StreamExt;
use sc_cli::{ChainSpec, CliConfiguration, SubstrateCli};
use sc_consensus_slots::SlotProportion;
use sc_executor::NativeExecutionDispatch;
use sc_service::PartialComponents;
use sc_storage_monitor::StorageMonitorService;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sc_utils::mpsc::tracing_unbounded;
use sp_core::crypto::Ss58AddressFormat;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::DomainId;
use std::any::TypeId;
use std::collections::BTreeMap;
use subspace_node::{Cli, ExecutorDispatch, Subcommand, SystemDomainCli};
use subspace_runtime::{Block, RuntimeApi};
use subspace_service::{DsnConfig, SubspaceConfiguration, SubspaceNetworking};
use system_domain_runtime::GenesisConfig as ExecutionGenesisConfig;

/// System domain executor instance.
pub struct SystemDomainExecutorDispatch;

impl NativeExecutionDispatch for SystemDomainExecutorDispatch {
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        system_domain_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        system_domain_runtime::native_version()
    }
}

/// Core payments domain executor instance.
pub struct CorePaymentsDomainExecutorDispatch;

impl NativeExecutionDispatch for CorePaymentsDomainExecutorDispatch {
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        core_payments_domain_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        core_payments_domain_runtime::native_version()
    }
}

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

fn main() -> Result<(), Error> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::Key(cmd)) => cmd.run(&cli)?,
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))?
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    import_queue,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, config.database)
                        .map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, config.chain_spec)
                        .map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    import_queue,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::ImportBlocksFromDsn(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    import_queue,
                    task_manager,
                    other: (_block_import, subspace_link, _telemetry, _bundle_validator),
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;

                sc_consensus_subspace::start_subspace_archiver(
                    &subspace_link,
                    client.clone(),
                    None,
                    &task_manager.spawn_essential_handle(),
                );

                Ok((
                    cmd.run(client, import_queue, task_manager.spawn_essential_handle())
                        .map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            // This is a compatibility layer to make sure we wipe old data from disks of our users
            if let Some(base_dir) = dirs::data_local_dir() {
                for chain in &[
                    "subspace_gemini_1b",
                    "Lamda_2513",
                    "Lamda_2513_2",
                    "Lamda_2513_3",
                ] {
                    let _ = std::fs::remove_dir_all(
                        base_dir.join("subspace-node").join("chains").join(chain),
                    );
                }
            }

            let runner = cli.create_runner(&cmd.base)?;

            runner.sync_run(|primary_chain_config| {
                let maybe_system_domain_chain_spec = primary_chain_config
                    .chain_spec
                    .extensions()
                    .get_any(TypeId::of::<ExecutionChainSpec<ExecutionGenesisConfig>>())
                    .downcast_ref()
                    .cloned();

                let (system_domain_cli, _maybe_core_domain_cli) = SystemDomainCli::new(
                    cmd.base
                        .base_path()?
                        .map(|base_path| base_path.path().to_path_buf()),
                    maybe_system_domain_chain_spec.ok_or_else(|| {
                        "Primary chain spec must contain system domain chain spec".to_string()
                    })?,
                    cli.domain_args.into_iter(),
                );

                let system_domain_config = SubstrateCli::create_configuration(
                    &system_domain_cli,
                    &system_domain_cli,
                    primary_chain_config.tokio_handle.clone(),
                )
                .map_err(|error| {
                    sc_service::Error::Other(format!(
                        "Failed to create system domain configuration: {error:?}"
                    ))
                })?;

                cmd.run(primary_chain_config, system_domain_config)
            })?;
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    backend,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, backend, None).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::ChainInfo(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run::<Block>(&config))?;
        }
        Some(Subcommand::Benchmark(cmd)) => {
            let runner = cli.create_runner(cmd)?;

            runner.sync_run(|config| {
                // This switch needs to be in the client, since the client decides
                // which sub-commands it wants to support.
                match cmd {
                    BenchmarkCmd::Pallet(cmd) => {
                        if !cfg!(feature = "runtime-benchmarks") {
                            return Err(
                                "Runtime benchmarking wasn't enabled when building the node. \
                                You can enable it with `--features runtime-benchmarks`."
                                    .into(),
                            );
                        }

                        cmd.run::<Block, ExecutorDispatch>(config)
                    }
                    BenchmarkCmd::Block(cmd) => {
                        let PartialComponents { client, .. } =
                            subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;

                        cmd.run(client)
                    }
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents {
                            client, backend, ..
                        } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                        let db = backend.expose_db();
                        let storage = backend.expose_storage();

                        cmd.run(config, client, db, storage)
                    }
                    BenchmarkCmd::Overhead(_cmd) => {
                        todo!("Not implemented")
                        // let ext_builder = BenchmarkExtrinsicBuilder::new(client.clone());
                        //
                        // cmd.run(
                        //     config,
                        //     client,
                        //     command_helper::inherent_benchmark_data()?,
                        //     Arc::new(ext_builder),
                        // )
                    }
                    BenchmarkCmd::Machine(cmd) => cmd.run(
                        &config,
                        frame_benchmarking_cli::SUBSTRATE_REFERENCE_HARDWARE.clone(),
                    ),
                    BenchmarkCmd::Extrinsic(_cmd) => {
                        todo!("Not implemented")
                        // let PartialComponents { client, .. } =
                        //     subspace_service::new_partial(&config)?;
                        // // Register the *Remark* and *TKA* builders.
                        // let ext_factory = ExtrinsicFactory(vec![
                        //     Box::new(RemarkBuilder::new(client.clone())),
                        //     Box::new(TransferKeepAliveBuilder::new(
                        //         client.clone(),
                        //         Sr25519Keyring::Alice.to_account_id(),
                        //         ExistentialDeposit: get(),
                        //     )),
                        // ]);
                        //
                        // cmd.run(client, inherent_benchmark_data()?, &ext_factory)
                    }
                }
            })?;
        }
        Some(Subcommand::Executor(_cmd)) => {
            unimplemented!("Executor subcommand");
        }
        None => {
            let runner = cli.create_runner(&cli.run)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.run_node_until_exit(|primary_chain_config| async move {
                let tokio_handle = primary_chain_config.tokio_handle.clone();
                let database_source = primary_chain_config.database.clone();

                let maybe_system_domain_chain_spec = primary_chain_config
                    .chain_spec
                    .extensions()
                    .get_any(TypeId::of::<ExecutionChainSpec<ExecutionGenesisConfig>>())
                    .downcast_ref()
                    .cloned();

                // TODO: proper value
                let block_import_throttling_buffer_size = 10;

                let mut primary_chain_node = {
                    let span = sc_tracing::tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "PrimaryChain"
                    );
                    let _enter = span.enter();

                    let dsn_config = {
                        let network_keypair = primary_chain_config
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
                            primary_chain_config
                                .chain_spec
                                .properties()
                                .get("dsnBootstrapNodes")
                                .map(|d| serde_json::from_value(d.clone()))
                                .transpose()
                                .map_err(|error| {
                                    sc_service::Error::Other(format!(
                                        "Failed to decode DSN bootsrap nodes: {error:?}"
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
                            base_path: cli.run.base_path()?.map(|base_path| {
                                base_path
                                    .config_dir(primary_chain_config.chain_spec.id())
                                    .join("dsn")
                            }),
                            listen_on: cli.dsn_listen_on,
                            bootstrap_nodes: dsn_bootstrap_nodes,
                            reserved_peers: cli.dsn_reserved_peers,
                            allow_non_global_addresses_in_dht: !cli.dsn_disable_private_ips,
                            max_in_connections: cli.dsn_in_connections,
                            max_out_connections: cli.dsn_out_connections,
                            target_connections: cli.dsn_target_connections,
                        }
                    };

                    let mut primary_chain_config = primary_chain_config;
                    primary_chain_config
                        .network
                        .extra_sets
                        .push(cdm_gossip_peers_set_config());

                    let primary_chain_config = SubspaceConfiguration {
                        base: primary_chain_config,
                        // Domain node needs slots notifications for bundle production.
                        force_new_slot_notifications: !cli.domain_args.is_empty(),
                        subspace_networking: SubspaceNetworking::Create {
                            config: dsn_config,
                            piece_cache_size: cli.piece_cache_size.as_u64(),
                        },
                        segment_publish_concurrency: cli.segment_publish_concurrency,
                        sync_from_dsn: cli.sync_from_dsn,
                    };

                    let partial_components = subspace_service::new_partial::<
                        RuntimeApi,
                        ExecutorDispatch,
                    >(&primary_chain_config)
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to build a full subspace node: {error:?}"
                        ))
                    })?;

                    subspace_service::new_full(
                        primary_chain_config,
                        partial_components,
                        true,
                        SlotProportion::new(2f32 / 3f32),
                    )
                    .await
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to build a full subspace node: {error:?}"
                        ))
                    })?
                };

                StorageMonitorService::try_spawn(
                    cli.storage_monitor,
                    database_source,
                    &primary_chain_node.task_manager.spawn_essential_handle(),
                )
                .map_err(|error| {
                    sc_service::Error::Other(format!("Failed to start storage monitor: {error:?}"))
                })?;

                // Run an executor node, an optional component of Subspace full node.
                if !cli.domain_args.is_empty() {
                    let span = sc_tracing::tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "SystemDomain"
                    );
                    let _enter = span.enter();

                    let (system_domain_cli, maybe_core_domain_cli) = SystemDomainCli::new(
                        cli.run
                            .base_path()?
                            .map(|base_path| base_path.path().to_path_buf()),
                        maybe_system_domain_chain_spec.ok_or_else(|| {
                            "Primary chain spec must contain system domain chain spec".to_string()
                        })?,
                        cli.domain_args.into_iter(),
                    );

                    let system_domain_config = system_domain_cli
                        .create_domain_configuration(tokio_handle.clone())
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to create system domain configuration: {error:?}"
                            ))
                        })?;

                    let imported_block_notification_stream = || {
                        primary_chain_node
                            .imported_block_notification_stream
                            .subscribe()
                            .then(|imported_block_notification| async move {
                                (
                                    imported_block_notification.block_number,
                                    imported_block_notification.block_import_acknowledgement_sender,
                                )
                            })
                    };

                    let new_slot_notification_stream = || {
                        primary_chain_node
                            .new_slot_notification_stream
                            .subscribe()
                            .then(|slot_notification| async move {
                                (
                                    slot_notification.new_slot_info.slot,
                                    slot_notification.new_slot_info.global_challenge,
                                )
                            })
                    };

                    let (gossip_msg_sink, gossip_msg_stream) =
                        tracing_unbounded("cross_domain_gossip_messages", 100);

                    let system_domain_node = domain_service::new_full_system::<
                        _,
                        _,
                        _,
                        _,
                        _,
                        system_domain_runtime::RuntimeApi,
                        SystemDomainExecutorDispatch,
                    >(
                        system_domain_config,
                        primary_chain_node.client.clone(),
                        primary_chain_node.network.clone(),
                        &primary_chain_node.select_chain,
                        imported_block_notification_stream(),
                        new_slot_notification_stream(),
                        block_import_throttling_buffer_size,
                        gossip_msg_sink.clone(),
                    )
                    .await?;

                    let mut domain_tx_pool_sinks = BTreeMap::new();
                    domain_tx_pool_sinks.insert(DomainId::SYSTEM, system_domain_node.tx_pool_sink);

                    primary_chain_node
                        .task_manager
                        .add_child(system_domain_node.task_manager);

                    if let Some(core_domain_cli) = maybe_core_domain_cli {
                        let span = sc_tracing::tracing::info_span!(
                            sc_tracing::logging::PREFIX_LOG_SPAN,
                            name = "CoreDomain"
                        );
                        let _enter = span.enter();

                        let core_domain_config = core_domain_cli
                            .create_domain_configuration(tokio_handle)
                            .map_err(|error| {
                                sc_service::Error::Other(format!(
                                    "Failed to create core domain configuration: {error:?}"
                                ))
                            })?;

                        let core_domain_params = domain_service::CoreDomainParams {
                            domain_id: core_domain_cli.domain_id,
                            core_domain_config,
                            system_domain_client: system_domain_node.client.clone(),
                            system_domain_network: system_domain_node.network.clone(),
                            primary_chain_client: primary_chain_node.client.clone(),
                            primary_network_sync_oracle: primary_chain_node.network.clone(),
                            select_chain: primary_chain_node.select_chain.clone(),
                            imported_block_notification_stream: imported_block_notification_stream(
                            ),
                            new_slot_notification_stream: new_slot_notification_stream(),
                            block_import_throttling_buffer_size,
                            gossip_message_sink: gossip_msg_sink,
                        };

                        match core_domain_cli.domain_id {
                            DomainId::CORE_PAYMENTS => {
                                let core_domain_node =
                                    domain_service::new_full_core::<
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                        _,
                                        core_payments_domain_runtime::RuntimeApi,
                                        CorePaymentsDomainExecutorDispatch,
                                    >(core_domain_params)
                                    .await?;

                                domain_tx_pool_sinks.insert(
                                    core_domain_cli.domain_id,
                                    core_domain_node.tx_pool_sink,
                                );
                                primary_chain_node
                                    .task_manager
                                    .add_child(core_domain_node.task_manager);

                                core_domain_node.network_starter.start_network();
                            }
                            core_domain_id => {
                                return Err(Error::Other(format!(
                                    "{core_domain_id:?} unimplemented",
                                )));
                            }
                        }
                    }

                    let cross_domain_message_gossip_worker = GossipWorker::<Block>::new(
                        primary_chain_node.network.clone(),
                        domain_tx_pool_sinks,
                    );

                    primary_chain_node
                        .task_manager
                        .spawn_essential_handle()
                        .spawn_essential_blocking(
                            "cross-domain-gossip-message-worker",
                            None,
                            Box::pin(cross_domain_message_gossip_worker.run(gossip_msg_stream)),
                        );

                    system_domain_node.network_starter.start_network();
                }

                primary_chain_node.network_starter.start_network();
                Ok::<_, Error>(primary_chain_node.task_manager)
            })?;
        }
    }

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
