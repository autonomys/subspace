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
mod import_blocks_from_dsn;
mod secondary_chain_cli;
mod secondary_chain_spec;

use crate::chain_spec::SubspaceChainSpec;
pub use crate::import_blocks_from_dsn::ImportBlocksFromDsnCmd;
pub use crate::secondary_chain_cli::SecondaryChainCli;
use crate::serde_json::Value;
use clap::Parser;
use sc_cli::SubstrateCli;
use sc_executor::{NativeExecutionDispatch, RuntimeVersion};
use sc_service::ChainSpec;
use sc_telemetry::serde_json;

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
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Run executor sub-commands.
    #[clap(subcommand)]
    Executor(secondary_chain_cli::Subcommand),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

/// Command used to run a Subspace node.
#[derive(Debug, Parser)]
pub struct RunCmd {
    /// Base command to run a node.
    #[clap(flatten)]
    pub base: sc_cli::RunCmd,
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
            "testnet" => chain_spec::testnet_config_json()?,
            "testnet-compiled" => chain_spec::testnet_config_compiled()?,
            "dev" => chain_spec::dev_config()?,
            "" | "local" => chain_spec::local_config()?,
            path => SubspaceChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        };

        // In case there are bootstrap nodes specified explicitly, ignore those that are in the
        // chain spec
        if !self.run.base.network_params.bootnodes.is_empty() {
            let mut chain_spec_value =
                serde_json::from_str::<'_, Value>(&chain_spec.as_json(true)?)
                    .map_err(|error| error.to_string())?;
            if let Some(boot_nodes) = chain_spec_value.get_mut("bootNodes") {
                if let Some(boot_nodes) = boot_nodes.as_array_mut() {
                    boot_nodes.clear();
                }
            }
            chain_spec =
                SubspaceChainSpec::from_json_bytes(chain_spec_value.to_string().into_bytes())?;
        }
        Ok(Box::new(chain_spec))
    }

    fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &subspace_runtime::VERSION
    }
}
