//! Subspace node implementation.

#![feature(trait_upcasting)]

mod commands;

mod chain_spec;
mod chain_spec_utils;
mod cli;
mod domain;

use crate::cli::{Cli, SubspaceCliPlaceholder};
use crate::commands::set_exit_on_panic;
use crate::domain::cli::DomainKey;
use crate::domain::{DomainCli, DomainSubcommand};
use clap::Parser;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use frame_benchmarking_cli::BenchmarkCmd;
use futures::future::TryFutureExt;
use sc_cli::{ChainSpec, SubstrateCli};
use sc_domains::HostFunctions as DomainsHostFunctions;
use sc_service::{Configuration, PartialComponents};
use serde_json::Value;
use sp_core::crypto::Ss58AddressFormat;
use sp_runtime::traits::HashingFor;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_runtime::{Block, RuntimeApi};
use subspace_service::HostFunctions;
use tracing::warn;

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

fn set_default_ss58_version<C>(chain_spec: &C)
where
    C: ChainSpec + ?Sized,
{
    let maybe_ss58_address_format = chain_spec
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

fn derive_pot_external_entropy(
    consensus_chain_config: &Configuration,
    maybe_pot_external_entropy: Option<String>,
) -> Result<Vec<u8>, sc_service::Error> {
    let maybe_chain_spec_pot_external_entropy = consensus_chain_config
        .chain_spec
        .properties()
        .get("potExternalEntropy")
        .map(|d| match d.clone() {
            Value::String(s) => Ok(Some(s)),
            Value::Null => Ok(None),
            _ => Err(sc_service::Error::Other(
                "Failed to decode PoT initial key".to_string(),
            )),
        })
        .transpose()?
        .flatten();
    if maybe_chain_spec_pot_external_entropy.is_some()
        && maybe_pot_external_entropy.is_some()
        && maybe_chain_spec_pot_external_entropy != maybe_pot_external_entropy
    {
        warn!(
            "--pot-external-entropy CLI argument was ignored due to chain spec having a different \
            explicit value"
        );
    }
    Ok(maybe_chain_spec_pot_external_entropy
        .or(maybe_pot_external_entropy)
        .unwrap_or_default()
        .into_bytes())
}

fn main() -> Result<(), Error> {
    set_exit_on_panic();

    match Cli::parse() {
        Cli::Run(run_options) => {
            commands::run(run_options)?;
        }
        Cli::BuildSpec(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))?
        }
        Cli::CheckBlock(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            set_default_ss58_version(runner.config().chain_spec.as_ref());
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    import_queue,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                    &config,
                    false,
                    &derive_pot_external_entropy(&config, None)?,
                )?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Cli::ExportBlocks(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            set_default_ss58_version(runner.config().chain_spec.as_ref());
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                    &config,
                    false,
                    &derive_pot_external_entropy(&config, None)?,
                )?;
                Ok((
                    cmd.run(client, config.database)
                        .map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Cli::ExportState(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            set_default_ss58_version(runner.config().chain_spec.as_ref());
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                    &config,
                    false,
                    &derive_pot_external_entropy(&config, None)?,
                )?;
                Ok((
                    cmd.run(client, config.chain_spec)
                        .map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Cli::ImportBlocks(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            set_default_ss58_version(runner.config().chain_spec.as_ref());
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    import_queue,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                    &config,
                    false,
                    &derive_pot_external_entropy(&config, None)?,
                )?;
                Ok((
                    cmd.run(client, import_queue).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Cli::Wipe(wipe_options) => {
            commands::wipe(wipe_options).map_err(|error| Error::Other(error.to_string()))?;
        }
        Cli::Revert(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            set_default_ss58_version(runner.config().chain_spec.as_ref());
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    backend,
                    task_manager,
                    ..
                } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                    &config,
                    false,
                    &derive_pot_external_entropy(&config, None)?,
                )?;
                Ok((
                    cmd.run(client, backend, None).map_err(Error::SubstrateCli),
                    task_manager,
                ))
            })?;
        }
        Cli::ChainInfo(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
            runner.sync_run(|config| cmd.run::<Block>(&config))?;
        }
        Cli::Benchmark(cmd) => {
            let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;

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

                        cmd.run_with_spec::<HashingFor<Block>, HostFunctions>(Some(
                            config.chain_spec,
                        ))
                    }
                    BenchmarkCmd::Block(cmd) => {
                        let PartialComponents { client, .. } =
                            subspace_service::new_partial::<PosTable, RuntimeApi>(
                                &config,
                                false,
                                &derive_pot_external_entropy(&config, None)?,
                            )?;

                        cmd.run(client)
                    }
                    #[cfg(not(feature = "runtime-benchmarks"))]
                    BenchmarkCmd::Storage(_) => Err(sc_cli::Error::Input(
                        "Compile with --features=runtime-benchmarks to enable storage benchmarks."
                            .into(),
                    )),
                    #[cfg(feature = "runtime-benchmarks")]
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents {
                            client, backend, ..
                        } = subspace_service::new_partial::<PosTable, RuntimeApi>(
                            &config,
                            false,
                            &derive_pot_external_entropy(&config, None)?,
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
        Cli::Domain(domain_cmd) => match domain_cmd {
            DomainSubcommand::Key(DomainKey::Create(create_domain_key_options)) => {
                commands::create_domain_key(create_domain_key_options)?;
            }
            DomainSubcommand::Key(DomainKey::Insert(insert_domain_key_options)) => {
                commands::insert_domain_key(insert_domain_key_options)?;
            }
            DomainSubcommand::Benchmark(cmd) => {
                let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
                runner.sync_run(|consensus_chain_config| {
                    let domain_cli = DomainCli::new(
                        // pass the domain-id manually for benchmark since this is
                        // not possible through cli commands at this moment.
                        vec!["--domain-id".to_owned(), "0".to_owned()].into_iter(),
                    );
                    let domain_config = domain_cli
                        .create_domain_configuration(
                            &cmd,
                            consensus_chain_config.base_path.path(),
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
                            cmd.run_with_spec::<HashingFor<DomainBlock>, DomainsHostFunctions>(
                                Some(domain_config.chain_spec),
                            )
                        }
                        _ => todo!("Not implemented"),
                    }
                })?;
            }
            DomainSubcommand::BuildGenesisStorage(cmd) => cmd.run()?,
            DomainSubcommand::ExportExecutionReceipt(cmd) => {
                let runner = SubspaceCliPlaceholder.create_runner(&cmd)?;
                runner.sync_run(|consensus_chain_config| {
                    let domain_cli = DomainCli::new(cmd.domain_args.clone().into_iter());
                    let domain_config = domain_cli
                        .create_domain_configuration(
                            &cmd,
                            consensus_chain_config.base_path.path(),
                            consensus_chain_config.tokio_handle,
                        )
                        .map_err(|error| {
                            sc_service::Error::Other(format!(
                                "Failed to create domain configuration: {error:?}"
                            ))
                        })?;

                    let executor = sc_service::new_wasm_executor::<DomainsHostFunctions>(
                        &domain_config.executor,
                    );

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
