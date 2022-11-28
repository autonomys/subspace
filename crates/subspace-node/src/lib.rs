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
mod core_domain;
mod import_blocks_from_dsn;
mod secondary_chain;

pub use crate::import_blocks_from_dsn::ImportBlocksFromDsnCmd;
pub use crate::secondary_chain::cli::SecondaryChainCli;
use bytesize::ByteSize;
use clap::Parser;
use sc_cli::{RunCmd, SubstrateCli};
use sc_executor::{NativeExecutionDispatch, RuntimeVersion};
use sc_service::ChainSpec;
use sc_subspace_chain_specs::ConsensusChainSpec;
use sc_telemetry::serde_json;
use serde_json::Value;
use std::io::Write;
use std::{fs, io};
use subspace_networking::libp2p::Multiaddr;

/// Executor dispatch for subspace runtime
pub struct ExecutorDispatch;

impl NativeExecutionDispatch for ExecutorDispatch {
    /// Only enable the benchmarking host functions when we actually want to benchmark.
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    /// Otherwise we only use the default Substrate host functions.
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        subspace_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        subspace_runtime::native_version()
    }
}

/// This `purge-chain` command used to remove both primary and secondary chains.
#[derive(Debug, Clone, Parser)]
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
            match fs::remove_dir_all(db_path) {
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
#[allow(clippy::large_enum_variant)]
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

    /// Where local DSN node will listen for incoming connections.
    // TODO: Add more DSN-related parameters
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30433")]
    pub dsn_listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    #[arg(long)]
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,

    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses
    /// in Kademlia DHT for the DSN.
    #[arg(long, default_value_t = false)]
    pub dsn_disable_private_ips: bool,

    /// Piece cache size in human readable format (e.g. 10GB, 2TiB) or just bytes (e.g. 4096).
    #[arg(long, default_value = "1GiB")]
    pub piece_cache_size: ByteSize,

    /// Secondary chain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded primary node,
    /// while the arguments provided after `--` will be passed to the system domain node.
    ///
    /// If you want to run a core domain node, specify the core domain node arguments after
    /// the system domain node arguments with an extra `-- --`.
    ///
    /// subspace-node [primarychain-args] -- [secondarychain-args] -- -- [core-domain-args]
    #[arg(raw = true)]
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
        "https://forum.subspace.network".into()
    }

    fn copyright_start_year() -> i32 {
        2021
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
        let mut chain_spec = match id {
            "gemini-3a" => chain_spec::gemini_3a()?,
            "gemini-3a-compiled" => chain_spec::gemini_3a_compiled()?,
            "x-net-2" => chain_spec::x_net_2_config()?,
            "x-net-2-compiled" => chain_spec::x_net_2_config_compiled()?,
            "dev" => chain_spec::dev_config()?,
            "" | "local" => chain_spec::local_config()?,
            path => ConsensusChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        };

        // In case there are bootstrap nodes specified explicitly, ignore those that are in the
        // chain spec
        if !self.run.network_params.bootnodes.is_empty() {
            let mut chain_spec_value: Value = serde_json::from_str(&chain_spec.as_json(true)?)
                .map_err(|error| error.to_string())?;
            if let Some(boot_nodes) = chain_spec_value.get_mut("bootNodes") {
                if let Some(boot_nodes) = boot_nodes.as_array_mut() {
                    boot_nodes.clear();
                }
            }
            // Such mess because native serialization of the chain spec serializes it twice, see
            // docs on `sc_subspace_chain_specs::utils::SerializableChainSpec`.
            chain_spec = serde_json::to_string(&chain_spec_value.to_string())
                .and_then(|chain_spec_string| serde_json::from_str(&chain_spec_string))
                .map_err(|error| error.to_string())?;
        }
        Ok(Box::new(chain_spec))
    }

    fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &subspace_runtime::VERSION
    }
}

pub mod parser {
    use domain_runtime_primitives::RelayerId;
    use sp_core::crypto::Ss58Codec;

    /// Parses relayer id in string format. Used for Cli.
    pub fn parse_relayer_id(s: &str) -> Result<RelayerId, sp_core::crypto::PublicError> {
        RelayerId::from_ss58check(s)
    }
}
