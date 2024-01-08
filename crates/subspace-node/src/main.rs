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

mod commands;

mod chain_spec;
mod chain_spec_utils;
mod cli;
mod domain;

use crate::cli::{Cli, Subcommand};
use crate::domain::{DomainCli, DomainSubcommand};
use domain_runtime_primitives::opaque::Block as DomainBlock;
use evm_domain_runtime::ExecutorDispatch as EVMDomainExecutorDispatch;
use frame_benchmarking_cli::BenchmarkCmd;
use futures::future::TryFutureExt;
use log::warn;
use sc_cli::{ChainSpec, SubstrateCli};
use sc_executor::NativeExecutionDispatch;
use sc_service::{Configuration, PartialComponents};
use sp_core::crypto::Ss58AddressFormat;
use sp_io::SubstrateHostFunctions;
use sp_wasm_interface::ExtendedHostFunctions;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_runtime::{Block, ExecutorDispatch, RuntimeApi};

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

fn pot_external_entropy(
    consensus_chain_config: &Configuration,
    cli: &Cli,
) -> Result<Vec<u8>, sc_service::Error> {
    let maybe_chain_spec_pot_external_entropy = consensus_chain_config
        .chain_spec
        .properties()
        .get("potExternalEntropy")
        .map(|d| serde_json::from_value(d.clone()))
        .transpose()
        .map_err(|error| {
            sc_service::Error::Other(format!("Failed to decode PoT initial key: {error:?}"))
        })?
        .flatten();
    if maybe_chain_spec_pot_external_entropy.is_some()
        && cli.pot_external_entropy.is_some()
        && maybe_chain_spec_pot_external_entropy != cli.pot_external_entropy
    {
        warn!(
            "--pot-external-entropy CLI argument was ignored due to chain spec having a different \
            explicit value"
        );
    }
    Ok(maybe_chain_spec_pot_external_entropy
        .or(cli.pot_external_entropy.clone())
        .unwrap_or_default())
}

fn main() -> Result<(), Error> {
    let mut cli = Cli::from_args();
    // Force UTC logs for Subspace node
    cli.run.shared_params.use_utc_log_time = true;

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
                    &config,
                    &pot_external_entropy(&config, &cli)?,
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
                    &config,
                    &pot_external_entropy(&config, &cli)?,
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
                    &config,
                    &pot_external_entropy(&config, &cli)?,
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
                    &config,
                    &pot_external_entropy(&config, &cli)?,
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
                    "subspace_gemini_3e",
                    "subspace_gemini_3f",
                    "subspace_gemini_3g",
                ] {
                    let _ = std::fs::remove_dir_all(
                        base_dir.join("subspace-node").join("chains").join(chain),
                    );
                }
                let _ = std::fs::remove_dir_all(base_dir.join("subspace-node").join("domain-0"));
                let _ = std::fs::remove_dir_all(base_dir.join("subspace-node").join("domain-1"));
            }

            let runner = cli.create_runner(&cmd.base)?;

            runner.sync_run(|consensus_chain_config| cmd.run(consensus_chain_config))?;
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
                    &config,
                    &pot_external_entropy(&config, &cli)?,
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
        #[cfg(feature = "runtime-benchmarks")]
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

                        cmd.run::<Block, ExtendedHostFunctions<
                            SubstrateHostFunctions,
                            <ExecutorDispatch as NativeExecutionDispatch>::ExtendHostFunctions,
                        >>(config)
                    }
                    BenchmarkCmd::Block(cmd) => {
                        let PartialComponents { client, .. } = subspace_service::new_partial::<
                            PosTable,
                            RuntimeApi,
                            ExecutorDispatch,
                        >(
                            &config,
                            &pot_external_entropy(&config, &cli)?,
                        )?;

                        cmd.run(client)
                    }
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents {
                            client, backend, ..
                        } = subspace_service::new_partial::<PosTable, RuntimeApi, ExecutorDispatch>(
                            &config,
                            &pot_external_entropy(&config, &cli)?,
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
                        // pass the domain-id manually for benchmark since this is
                        // not possible through cli commands at this moment.
                        vec!["--domain-id".to_owned(), "0".to_owned()].into_iter(),
                    );
                    let domain_config = domain_cli
                        .create_domain_configuration(
                            &consensus_chain_config.base_path.path().join("domains"),
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
                            cmd.run::<DomainBlock, ExtendedHostFunctions<
                                SubstrateHostFunctions,
                                <EVMDomainExecutorDispatch as NativeExecutionDispatch>::ExtendHostFunctions,
                            >>(domain_config)
                        }
                        _ => todo!("Not implemented"),
                    }
                })?;
            }
            DomainSubcommand::BuildGenesisStorage(cmd) => cmd.run()?,
            DomainSubcommand::ExportExecutionReceipt(cmd) => {
                let runner = cli.create_runner(cmd)?;
                runner.sync_run(|consensus_chain_config| {
                    let domain_cli = DomainCli::new(cmd.domain_args.clone().into_iter());
                    let domain_config = domain_cli
                        .create_domain_configuration(
                            &consensus_chain_config.base_path.path().join("domains"),
                            consensus_chain_config.tokio_handle,
                        )
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to create domain configuration: {error:?}"
                            ))
                        })?;

                    let executor: sc_executor::NativeElseWasmExecutor<EVMDomainExecutorDispatch> =
                        sc_service::new_native_or_wasm_executor(&domain_config);

                    let (client, _, _, _) = sc_service::new_full_parts::<
                        DomainBlock,
                        evm_domain_runtime::RuntimeApi,
                        _,
                    >(&domain_config, None, executor)?;

                    cmd.run(&client, &client)
                })?;
            }
            _ => unimplemented!("Domain subcommand"),
        },
        None => {
            commands::run(cli)?;
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
