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

use domain_client_operator::Bootstrapper;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use frame_benchmarking_cli::BenchmarkCmd;
use futures::future::TryFutureExt;
use sc_cli::{ChainSpec, CliConfiguration, SubstrateCli};
use sc_consensus_slots::SlotProportion;
use sc_proof_of_time::PotComponents;
use sc_service::PartialComponents;
use sc_storage_monitor::StorageMonitorService;
use sp_core::crypto::Ss58AddressFormat;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::GenerateGenesisStateRoot;
use std::sync::Arc;
use subspace_node::domain::{
    AccountId32ToAccountId20Converter, DomainCli, DomainGenesisBlockBuilder, DomainInstanceStarter,
    DomainSubcommand, EVMDomainExecutorDispatch,
};
use subspace_node::{Cli, ExecutorDispatch, Subcommand};
use subspace_proof_of_space::chia::ChiaTable;
use subspace_runtime::{Block, RuntimeApi};
use subspace_service::{DsnConfig, SubspaceConfiguration, SubspaceNetworking};

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
                } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                    &config, None, None,
                )?;
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
                } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                    &config, None, None,
                )?;
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
                } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                    &config, None, None,
                )?;
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
                } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                    &config, None, None,
                )?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            // This is a compatibility layer to make sure we wipe old data from disks of our users
            if let Some(base_dir) = dirs::data_local_dir() {
                for chain in &[
                    "subspace_gemini_2a",
                    "subspace_gemini_3a",
                    "subspace_gemini_3b",
                    "subspace_gemini_3c",
                    "subspace_gemini_3d",
                ] {
                    let _ = std::fs::remove_dir_all(
                        base_dir.join("subspace-node").join("chains").join(chain),
                    );
                }
            }

            let runner = cli.create_runner(&cmd.base)?;

            runner.sync_run(|consensus_chain_config| {
                let domain_cli = DomainCli::new(
                    cmd.base
                        .base_path()?
                        .map(|base_path| base_path.path().to_path_buf()),
                    cli.domain_args.into_iter(),
                );

                let domain_config = SubstrateCli::create_configuration(
                    &domain_cli,
                    &domain_cli,
                    consensus_chain_config.tokio_handle.clone(),
                )
                .map_err(|error| {
                    sc_service::Error::Other(format!(
                        "Failed to create domain configuration: {error:?}"
                    ))
                })?;

                cmd.run(consensus_chain_config, domain_config)
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
                } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                    &config, None, None,
                )?;
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
                        let PartialComponents { client, .. } = subspace_service::new_partial::<
                            PosTable,
                            RuntimeApi,
                            ExecutorDispatch,
                        >(
                            &config, None, None
                        )?;

                        cmd.run(client)
                    }
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents {
                            client, backend, ..
                        } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                            &config, None, None,
                        )?;
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
        Some(Subcommand::Domain(domain_cmd)) => match domain_cmd {
            DomainSubcommand::Benchmark(cmd) => {
                let runner = cli.create_runner(cmd)?;
                runner.sync_run(|consensus_chain_config| {
                    let domain_cli = DomainCli::new(
                        cli.run
                            .base_path()?
                            .map(|base_path| base_path.path().to_path_buf()),
                        cli.domain_args.into_iter(),
                    );
                    let domain_config = domain_cli
                        .create_domain_configuration::<_, AccountId32ToAccountId20Converter>(
                            consensus_chain_config.tokio_handle,
                        )
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to create domain configuration: {error:?}"
                            ))
                        })?;
                    match cmd {
                        BenchmarkCmd::Pallet(cmd) => {
                            if !cfg!(feature = "runtime-benchmarks") {
                                return Err(
                                    "Runtime benchmarking wasn't enabled when building the node. \
                                    You can enable it with `--features runtime-benchmarks`."
                                        .into(),
                                );
                            }
                            cmd.run::<DomainBlock, EVMDomainExecutorDispatch>(
                                domain_config.service_config,
                            )
                        }
                        _ => todo!("Not implemented"),
                    }
                })?;
            }
            _ => unimplemented!("Domain subcommand"),
        },
        None => {
            let runner = cli.create_runner(&cli.run)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.run_node_until_exit(|consensus_chain_config| async move {
                let tokio_handle = consensus_chain_config.tokio_handle.clone();
                let database_source = consensus_chain_config.database.clone();
                let pot_components = if cli.pot_role.is_pot_enabled() {
                    Some(PotComponents::new(cli.pot_role.is_time_keeper()))
                } else {
                    None
                };

                let consensus_chain_node = {
                    let span = sc_tracing::tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "Consensus"
                    );
                    let _enter = span.enter();

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
                                    .config_dir(consensus_chain_config.chain_spec.id())
                                    .join("dsn")
                            }),
                            listen_on: cli.dsn_listen_on,
                            bootstrap_nodes: dsn_bootstrap_nodes,
                            reserved_peers: cli.dsn_reserved_peers,
                            allow_non_global_addresses_in_dht: cli.dsn_enable_private_ips,
                            max_in_connections: cli.dsn_in_connections,
                            max_out_connections: cli.dsn_out_connections,
                            max_pending_in_connections: cli.dsn_pending_in_connections,
                            max_pending_out_connections: cli.dsn_pending_out_connections,
                            target_connections: cli.dsn_target_connections,
                            external_addresses: cli.dsn_external_addresses,
                        }
                    };

                    let consensus_chain_config = SubspaceConfiguration {
                        base: consensus_chain_config,
                        // Domain node needs slots notifications for bundle production.
                        force_new_slot_notifications: !cli.domain_args.is_empty(),
                        subspace_networking: SubspaceNetworking::Create {
                            config: dsn_config,
                            piece_cache_size: cli.piece_cache_size.as_u64(),
                        },
                        sync_from_dsn: cli.sync_from_dsn,
                        enable_subspace_block_relay: cli.enable_subspace_block_relay
                            || cli.run.is_dev().unwrap_or(false),
                    };

                    let construct_domain_genesis_block_builder =
                        |backend, executor| -> Arc<dyn GenerateGenesisStateRoot> {
                            Arc::new(DomainGenesisBlockBuilder::new(backend, executor))
                        };
                    let partial_components =
                        subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                            &consensus_chain_config,
                            Some(&construct_domain_genesis_block_builder),
                            pot_components,
                        )
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to build a full subspace node: {error:?}"
                            ))
                        })?;

                    subspace_service::new_full::<PosTable, _, _, _>(
                        consensus_chain_config,
                        partial_components,
                        true,
                        SlotProportion::new(3f32 / 4f32),
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

                    let domain_cli = DomainCli::new(
                        cli.run
                            .base_path()?
                            .map(|base_path| base_path.path().to_path_buf()),
                        cli.domain_args.into_iter(),
                    );
                    let domain_id = domain_cli.domain_id;

                    let bootstrapper =
                        Bootstrapper::<DomainBlock, _, _>::new(consensus_chain_node.client.clone());

                    let domain_starter = DomainInstanceStarter {
                        domain_cli,
                        tokio_handle,
                        consensus_client: consensus_chain_node.client.clone(),
                        block_importing_notification_stream: consensus_chain_node
                            .block_importing_notification_stream
                            .clone(),
                        new_slot_notification_stream: consensus_chain_node
                            .new_slot_notification_stream
                            .clone(),
                        consensus_network_service: consensus_chain_node.network_service.clone(),
                        consensus_sync_service: consensus_chain_node.sync_service.clone(),
                        select_chain: consensus_chain_node.select_chain.clone(),
                    };

                    consensus_chain_node
                        .task_manager
                        .spawn_essential_handle()
                        .spawn_essential_blocking(
                            "domain",
                            None,
                            Box::pin(async move {
                                let bootstrap_result =
                                    match bootstrapper.fetch_domain_bootstrap_info(domain_id).await
                                    {
                                        Err(err) => {
                                            log::error!(
                                                "Domain bootsrapper exited with an error {err:?}"
                                            );
                                            return;
                                        }
                                        Ok(res) => res,
                                    };
                                if let Err(error) = domain_starter.start(bootstrap_result).await {
                                    log::error!("Domain starter exited with an error {error:?}");
                                }
                            }),
                        );
                }

                consensus_chain_node.network_starter.start_network();
                Ok::<_, Error>(consensus_chain_node.task_manager)
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
