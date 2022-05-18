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

//! Subspace Node library.

mod chain_spec;
mod chain_spec_utils;
mod import_blocks_from_dsn;
mod secondary_chain;

pub use crate::chain_spec::{ChainSpecExtensions, ConsensusChainSpec};
pub use crate::import_blocks_from_dsn::ImportBlocksFromDsnCmd;
pub use crate::secondary_chain::chain_spec::ExecutionChainSpec;
pub use crate::secondary_chain::cli::SecondaryChainCli;
use clap::Parser;
use sc_cli::{RunCmd, SubstrateCli};
use sc_executor::{NativeExecutionDispatch, RuntimeVersion};
use sc_service::ChainSpec;
use sc_telemetry::serde_json;
use std::io::Write;
use std::{fs, io};

/// Executor dispatch for subspace runtime
pub struct ExecutorDispatch;

impl NativeExecutionDispatch for ExecutorDispatch {
    /// Only enable the benchmarking host functions when we actually want to benchmark.
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = (
        sp_executor::fraud_proof_ext::fraud_proof::HostFunctions,
        frame_benchmarking::benchmarking::HostFunctions,
    );
    /// Otherwise we only use the default Substrate host functions.
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = sp_executor::fraud_proof_ext::fraud_proof::HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        subspace_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        subspace_runtime::native_version()
    }
}

/// This `purge-chain` command used to remove both primary and secondary chains.
#[derive(Debug, Parser)]
pub struct PurgeChainCmd {
    /// The base struct of the purge-chain command.
    #[clap(flatten)]
    pub base: sc_cli::PurgeChainCmd,
}

impl PurgeChainCmd {
    /// Run the purge command
    pub fn run(
        &self,
        primary_chain_config: sc_service::Configuration,
        secondary_chain_config: sc_service::Configuration,
    ) -> sc_cli::Result<()> {
        let db_paths = vec![
            secondary_chain_config
                .database
                .path()
                .expect("No custom database used here; qed"),
            primary_chain_config
                .database
                .path()
                .expect("No custom database used here; qed"),
        ];

        if !self.base.yes {
            for db_path in &db_paths {
                println!("{}", db_path.display());
            }
            print!("Are you sure to remove? [y/N]: ");
            io::stdout().flush().expect("failed to flush stdout");

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            match input.chars().next() {
                Some('y') | Some('Y') => {}
                _ => {
                    println!("Aborted");
                    return Ok(());
                }
            }
        }

        for db_path in &db_paths {
            match fs::remove_dir_all(&db_path) {
                Ok(_) => {
                    println!("{:?} removed.", &db_path);
                }
                Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                    eprintln!("{:?} did not exist.", &db_path);
                }
                Err(err) => return Err(err.into()),
            }
        }

        Ok(())
    }
}

/// Utilities for working with a node.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Key management cli utilities
    #[clap(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Import blocks from Subspace Network DSN.
    ImportBlocksFromDsn(ImportBlocksFromDsnCmd),

    /// Remove the whole chain.
    PurgeChain(PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),

    /// Run executor sub-commands.
    #[clap(subcommand)]
    Executor(secondary_chain::cli::Subcommand),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

/// Subspace Cli.
#[derive(Debug, Parser)]
#[clap(
    propagate_version = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Various utility commands.
    #[clap(subcommand)]
    pub subcommand: Option<Subcommand>,

    /// Run a node.
    #[clap(flatten)]
    pub run: RunCmd,

    /// Secondary chain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded primary node,
    /// while the arguments provided after -- will be passed to the executor node.
    ///
    /// subspace-node [primarychain-args] -- [secondarychain-args]
    #[clap(raw = true)]
    pub secondary_chain_args: Vec<String>,
}

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Subspace".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn executable_name() -> String {
        // Customize to make sure directory used for data by default is the same regardless of the
        // name of the executable file.
        "subspace-node".to_string()
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

    fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
        let mut chain_spec = match id {
            "gemini-1" => chain_spec::gemini_config()?,
            "gemini-1-compiled" => chain_spec::gemini_config_compiled()?,
            "testnet" => chain_spec::testnet_config_json()?,
            "testnet-compiled" => chain_spec::testnet_config_compiled()?,
            "dev" => chain_spec::dev_config()?,
            "" | "local" => chain_spec::local_config()?,
            path => ConsensusChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        };

        // In case there are bootstrap nodes specified explicitly, ignore those that are in the
        // chain spec
        if !self.run.network_params.bootnodes.is_empty() {
            let mut chain_spec_value =
                serde_json::to_value(&chain_spec).map_err(|error| error.to_string())?;
            if let Some(boot_nodes) = chain_spec_value.get_mut("bootNodes") {
                if let Some(boot_nodes) = boot_nodes.as_array_mut() {
                    boot_nodes.clear();
                }
            }
            chain_spec =
                serde_json::from_value(chain_spec_value).map_err(|error| error.to_string())?;
        }
        Ok(Box::new(chain_spec))
    }

    fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &subspace_runtime::VERSION
    }
}
