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

use crate::cli::{Cli, Subcommand};
use crate::{
    chain_spec,
    service::{self, IsCollator},
};
use sc_cli::{ChainSpec, RuntimeVersion, SubstrateCli};
use sc_service::PartialComponents;
use subspace_runtime::Block;

/// Subspace node error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Subspace service error.
    #[error(transparent)]
    SubspaceService(#[from] crate::service::Error),

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

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Subspace".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://discord.gg/vhKF9w3x".into()
    }

    fn copyright_start_year() -> i32 {
        2021
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "testnet" => Box::new(chain_spec::testnet_config()?),
            "dev" => Box::new(chain_spec::development_config()?),
            "" | "local" => Box::new(chain_spec::local_testnet_config()?),
            path => Box::new(chain_spec::ChainSpec::from_json_file(
                std::path::PathBuf::from(path),
            )?),
        })
    }

    fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &subspace_runtime::VERSION
    }
}

/// Parse and run command line arguments
pub fn run() -> std::result::Result<(), Error> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::Key(cmd)) => cmd.run(&cli).map_err(Into::into),
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .sync_run(|config| cmd.run(config.chain_spec, config.network))
                .map_err(Into::into)
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .async_run(|config| {
                    let PartialComponents {
                        client,
                        task_manager,
                        import_queue,
                        ..
                    } = service::new_partial(&config)?;
                    Ok((cmd.run(client, import_queue), task_manager))
                })
                .map_err(Into::into)
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .async_run(|config| {
                    let PartialComponents {
                        client,
                        task_manager,
                        ..
                    } = service::new_partial(&config)?;
                    Ok((cmd.run(client, config.database), task_manager))
                })
                .map_err(Into::into)
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .async_run(|config| {
                    let PartialComponents {
                        client,
                        task_manager,
                        ..
                    } = service::new_partial(&config)?;
                    Ok((cmd.run(client, config.chain_spec), task_manager))
                })
                .map_err(Into::into)
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .async_run(|config| {
                    let PartialComponents {
                        client,
                        task_manager,
                        import_queue,
                        ..
                    } = service::new_partial(&config)?;
                    Ok((cmd.run(client, import_queue), task_manager))
                })
                .map_err(Into::into)
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .sync_run(|config| cmd.run(config.database))
                .map_err(Into::into)
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner
                .async_run(|config| {
                    let PartialComponents {
                        client,
                        task_manager,
                        backend,
                        ..
                    } = service::new_partial(&config)?;
                    Ok((cmd.run(client, backend), task_manager))
                })
                .map_err(Into::into)
        }
        Some(Subcommand::Benchmark(cmd)) => {
            if cfg!(feature = "runtime-benchmarks") {
                let runner = cli.create_runner(cmd)?;

                runner
                    .sync_run(|config| cmd.run::<Block, service::ExecutorDispatch>(config))
                    .map_err(Into::into)
            } else {
                Err(Error::Other(
                    "Benchmarking wasn't enabled when building the node. You can enable it with \
                    `--features runtime-benchmarks`."
                        .into(),
                ))
            }
        }
        None => {
            let runner = cli.create_runner(&cli.run.base)?;
            runner.run_node_until_exit(|config| async move {
                service::new_full(config, IsCollator::No)
                    .map(|full| full.task_manager)
                    .map_err(Into::into)
            })
        }
    }
}
