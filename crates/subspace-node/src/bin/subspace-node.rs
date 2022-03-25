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

use futures::future::TryFutureExt;
use sc_cli::{ChainSpec, SubstrateCli};
use sp_core::crypto::Ss58AddressFormat;
use subspace_node::{Cli, ExecutorDispatch, Subcommand};
use subspace_runtime::consensus::RuntimeApi;

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

fn main() -> std::result::Result<(), Error> {
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
                let sc_service::PartialComponents {
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
                let sc_service::PartialComponents {
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
                let sc_service::PartialComponents {
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
                let sc_service::PartialComponents {
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
                let sc_service::PartialComponents {
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
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))?
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.async_run(|config| {
                let sc_service::PartialComponents {
                    client,
                    backend,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;
                Ok((
                    cmd.run(client, backend).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Some(Subcommand::Benchmark(cmd)) => {
            if cfg!(feature = "runtime-benchmarks") {
                let runner = cli.create_runner(cmd)?;
                set_default_ss58_version(&runner.config().chain_spec);
                runner.sync_run(|config| {
                    cmd.run::<subspace_runtime::consensus::Block, ExecutorDispatch>(config)
                })?;
            } else {
                return Err(Error::Other(
                    "Benchmarking wasn't enabled when building the node. You can enable it with \
                    `--features runtime-benchmarks`."
                        .into(),
                ));
            }
        }
        None => {
            let runner = cli.create_runner(&cli.run.base)?;
            set_default_ss58_version(&runner.config().chain_spec);
            runner.run_node_until_exit(|config| async move {
                subspace_service::new_full::<
                    subspace_runtime::consensus::RuntimeApi,
                    ExecutorDispatch,
                >(config, true)
                .await
                .map(|full| full.task_manager)
            })?;
        }
    }

    Ok(())
}
