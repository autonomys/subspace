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

use crate::chain_spec;
use crate::commands::RunOptions;
use clap::Parser;
use sc_cli::SubstrateCli;
use sc_service::ChainSpec;
use sc_subspace_chain_specs::ConsensusChainSpec;
use std::io::Write;
use std::{fs, io};

/// This `purge-chain` command used to remove both consensus chain and domain.
#[derive(Debug, Clone, Parser)]
#[group(skip)]
pub struct PurgeChainCmd {
    /// The base struct of the purge-chain command.
    #[clap(flatten)]
    pub base: sc_cli::PurgeChainCmd,
}

impl PurgeChainCmd {
    /// Run the purge command
    pub fn run(&self, consensus_chain_config: sc_service::Configuration) -> sc_cli::Result<()> {
        let paths = vec![
            consensus_chain_config.base_path.path().join("db"),
            consensus_chain_config.base_path.path().join("domains"),
            consensus_chain_config.base_path.path().join("network"),
            // TODO: Following three are temporary workaround for wiping old chains, remove once enough time has passed
            consensus_chain_config.base_path.path().join("chains"),
            consensus_chain_config.base_path.path().join("domain-0"),
            consensus_chain_config.base_path.path().join("domain-1"),
        ];

        if !self.base.yes {
            println!("Following paths (if exist) are about to be removed:");
            for path in &paths {
                println!(" {}", path.display());
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

        for db_path in &paths {
            match fs::remove_dir_all(db_path) {
                Ok(_) => {
                    println!("{:?} removed.", &db_path);
                }
                Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                    eprintln!("{:?} did not exist already, skipping.", &db_path);
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

    /// Remove the whole chain.
    PurgeChain(PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),

    /// Run domain sub-commands.
    #[clap(subcommand)]
    Domain(crate::domain::cli::Subcommand),

    /// Sub-commands concerned with benchmarking.
    #[cfg(feature = "runtime-benchmarks")]
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

fn parse_pot_external_entropy(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
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

    /// Options for running a node
    #[clap(flatten)]
    pub run: RunOptions,

    /// External entropy, used initially when PoT chain starts to derive the first seed
    #[arg(long, value_parser = parse_pot_external_entropy)]
    pub pot_external_entropy: Option<Vec<u8>>,
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
        let chain_spec = match id {
            "gemini-3g-compiled" => chain_spec::gemini_3g_compiled()?,
            "gemini-3g" => chain_spec::gemini_3g_config()?,
            "devnet" => chain_spec::devnet_config()?,
            "devnet-compiled" => chain_spec::devnet_config_compiled()?,
            "dev" => chain_spec::dev_config()?,
            "" | "local" => chain_spec::local_config()?,
            path => ConsensusChainSpec::from_json_file(std::path::PathBuf::from(path))?,
        };

        Ok(Box::new(chain_spec))
    }
}
