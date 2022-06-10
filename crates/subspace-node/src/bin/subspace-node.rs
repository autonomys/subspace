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

use cirrus_runtime::GenesisConfig as ExecutionGenesisConfig;
use frame_benchmarking_cli::BenchmarkCmd;
use futures::future::TryFutureExt;
use futures::StreamExt;
use sc_cli::{ChainSpec, CliConfiguration, Database, DatabaseParams, SubstrateCli};
use sc_client_api::HeaderBackend;
use sc_executor::NativeExecutionDispatch;
use sc_service::PartialComponents;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sp_core::crypto::Ss58AddressFormat;
use std::any::TypeId;
use subspace_node::{Cli, ExecutorDispatch, SecondaryChainCli, Subcommand};
use subspace_runtime::{Block, RuntimeApi};
use subspace_service::SubspaceConfiguration;

/// Secondary executor instance.
pub struct SecondaryExecutorDispatch;

impl NativeExecutionDispatch for SecondaryExecutorDispatch {
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        cirrus_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        cirrus_runtime::native_version()
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

// TODO: Remove once paritydb is the default option, ref https://github.com/paritytech/substrate/pull/11537
fn force_use_parity_db(database_params: &mut DatabaseParams) {
    database_params.database.replace(Database::ParityDb);
}

fn main() -> Result<(), Error> {
    let mut cli = Cli::from_args();

    force_use_parity_db(&mut cli.run.import_params.database_params);

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
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            let mut cmd = cmd.clone();
            force_use_parity_db(&mut cmd.base.database_params);

            // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
            //  wipe old data from disks of our users
            if cmd.base.shared_params.base_path().is_none() {
                let old_dirs = &[
                    "subspace-node-x86_64-macos-11-snapshot-2022-jan-05",
                    "subspace-node-x86_64-ubuntu-20.04-snapshot-2022-jan-05",
                    "subspace-node-x86_64-windows-2019-snapshot-2022-jan-05.exe",
                    "subspace-node-x86_64-windows-2022-snapshot-2022-jan-05.exe",
                    "subspace-node-macos-x86_64-snapshot-2022-mar-09",
                    "subspace-node-ubuntu-x86_64-snapshot-2022-mar-09",
                    "subspace-node-windows-x86_64-snapshot-2022-mar-09.exe",
                ];
                if let Some(base_dir) = dirs::data_local_dir() {
                    for old_dir in old_dirs {
                        let _ = std::fs::remove_dir_all(base_dir.join(old_dir));
                    }
                }
            }

            // Delete testnet data folder
            // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
            //  wipe old data from disks of our users
            if let Some(base_dir) = dirs::data_local_dir() {
                let _ = std::fs::remove_dir_all(
                    base_dir
                        .join("subspace-node")
                        .join("chains")
                        .join("subspace_test"),
                );
                let _ = std::fs::remove_dir_all(
                    base_dir
                        .join("subspace-node")
                        .join("chains")
                        .join("subspace_gemini_1a"),
                );
            }

            let runner = cli.create_runner(&cmd.base)?;

            runner.sync_run(|primary_chain_config| {
                let maybe_secondary_chain_spec = primary_chain_config
                    .chain_spec
                    .extensions()
                    .get_any(TypeId::of::<ExecutionChainSpec<ExecutionGenesisConfig>>())
                    .downcast_ref()
                    .cloned();

                let mut secondary_chain_cli = SecondaryChainCli::new(
                    cmd.base
                        .base_path()?
                        .map(|base_path| base_path.path().to_path_buf()),
                    maybe_secondary_chain_spec.ok_or_else(|| {
                        "Primary chain spec must contain secondary chain spec".to_string()
                    })?,
                    cli.secondary_chain_args.iter(),
                );
                force_use_parity_db(&mut secondary_chain_cli.run.import_params.database_params);

                let secondary_chain_config = SubstrateCli::create_configuration(
                    &secondary_chain_cli,
                    &secondary_chain_cli,
                    primary_chain_config.tokio_handle.clone(),
                )
                .map_err(|error| {
                    sc_service::Error::Other(format!(
                        "Failed to create secondary chain configuration: {error:?}"
                    ))
                })?;

                cmd.run(primary_chain_config, secondary_chain_config)
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

                let maybe_secondary_chain_spec = primary_chain_config
                    .chain_spec
                    .extensions()
                    .get_any(TypeId::of::<ExecutionChainSpec<ExecutionGenesisConfig>>())
                    .downcast_ref()
                    .cloned();

                let (mut primary_chain_node, config_dir) = {
                    let span = sc_tracing::tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "PrimaryChain"
                    );
                    let _enter = span.enter();

                    let config_dir = primary_chain_config
                        .base_path
                        .as_ref()
                        .map(|base_path| base_path.config_dir("subspace_gemini_1b"));

                    let primary_chain_config = SubspaceConfiguration {
                        base: primary_chain_config,
                        // Secondary node needs slots notifications for bundle production.
                        force_new_slot_notifications: !cli.secondary_chain_args.is_empty(),
                    };

                    let primary_chain_node = subspace_service::new_full::<
                        RuntimeApi,
                        ExecutorDispatch,
                    >(primary_chain_config, true)
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to build a full subspace node: {error:?}"
                        ))
                    })?;

                    (primary_chain_node, config_dir)
                };

                // Run an executor node, an optional component of Subspace full node.
                if !cli.secondary_chain_args.is_empty() {
                    let span = sc_tracing::tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "SecondaryChain"
                    );
                    let _enter = span.enter();

                    let mut secondary_chain_cli = SecondaryChainCli::new(
                        cli.run
                            .base_path()?
                            .map(|base_path| base_path.path().to_path_buf()),
                        maybe_secondary_chain_spec.ok_or_else(|| {
                            "Primary chain spec must contain secondary chain spec".to_string()
                        })?,
                        cli.secondary_chain_args.iter(),
                    );
                    force_use_parity_db(&mut secondary_chain_cli.run.import_params.database_params);

                    let secondary_chain_config = SubstrateCli::create_configuration(
                        &secondary_chain_cli,
                        &secondary_chain_cli,
                        tokio_handle,
                    )
                    .map_err(|error| {
                        sc_service::Error::Other(format!(
                            "Failed to create secondary chain configuration: {error:?}"
                        ))
                    })?;

                    let secondary_chain_node_fut = cirrus_node::service::new_full::<
                        _,
                        _,
                        _,
                        _,
                        _,
                        cirrus_runtime::RuntimeApi,
                        SecondaryExecutorDispatch,
                    >(
                        secondary_chain_config,
                        primary_chain_node.client.clone(),
                        primary_chain_node.network.clone(),
                        &primary_chain_node.select_chain,
                        primary_chain_node
                            .imported_block_notification_stream
                            .subscribe()
                            .then(|imported_block_notification| async move {
                                imported_block_notification.block_number
                            }),
                        primary_chain_node
                            .new_slot_notification_stream
                            .subscribe()
                            .then(|slot_notification| async move {
                                (
                                    slot_notification.new_slot_info.slot,
                                    slot_notification.new_slot_info.global_challenge,
                                )
                            }),
                    );

                    let secondary_chain_node = secondary_chain_node_fut.await?;

                    primary_chain_node
                        .task_manager
                        .add_child(secondary_chain_node.task_manager);

                    secondary_chain_node.network_starter.start_network();
                }

                // TODO: Workaround for regression in Gemini 1b 2022-jun-08 release:
                //  we need to reset network identity of the node to remove it from block list of
                //  other nodes on the network
                if primary_chain_node.client.info().best_number == 33670 {
                    if let Some(config_dir) = config_dir {
                        let workaround_file =
                            config_dir.join("network").join("gemini_1b_workaround");
                        if !workaround_file.exists() {
                            let _ = std::fs::write(workaround_file, &[]);
                            let _ = std::fs::remove_file(
                                config_dir.join("network").join("secret_ed25519"),
                            );
                            return Err(Error::Other(
                                "Applied workaround for upgrade from gemini-1b-2022-jun-08, \
                                please restart this node"
                                    .to_string(),
                            ));
                        }
                    }
                }

                primary_chain_node.network_starter.start_network();
                Ok::<_, Error>(primary_chain_node.task_manager)
            })?;
        }
    }

    Ok(())
}
