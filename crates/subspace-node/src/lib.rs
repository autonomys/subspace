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

pub mod chain_spec;
mod chain_spec_utils;
pub mod domain;

use clap::Parser;
use sc_cli::{RunCmd, SubstrateCli};
use sc_service::ChainSpec;
use sc_storage_monitor::StorageMonitorParams;
use sc_subspace_chain_specs::ConsensusChainSpec;
use sc_telemetry::serde_json;
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use std::{fs, io};
use subspace_networking::libp2p::Multiaddr;

/// This `purge-chain` command used to remove both consensus chain and domain.
#[derive(Debug, Clone, Parser)]
#[group(skip)]
pub struct PurgeChainCmd {
    /// The base struct of the purge-chain command.
    #[clap(flatten)]
    pub base: sc_cli::PurgeChainCmd,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node purge-chain [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    pub domain_args: Vec<String>,
}

impl PurgeChainCmd {
    /// Run the purge command
    pub fn run(
        &self,
        consensus_chain_config: sc_service::Configuration,
        domain_config: Option<sc_service::Configuration>,
    ) -> sc_cli::Result<()> {
        let mut db_paths = domain_config.map_or(vec![], |dc| {
            vec![dc
                .database
                .path()
                .expect("No custom database used here; qed")
                .to_path_buf()
                .clone()]
        });

        db_paths.push(
            consensus_chain_config
                .database
                .path()
                .expect("No custom database used here; qed")
                .to_path_buf(),
        );

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

    /// Remove the whole chain.
    PurgeChain(PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),

    /// Run domain sub-commands.
    #[clap(subcommand)]
    Domain(domain::cli::Subcommand),

    /// Sub-commands concerned with benchmarking.
    #[cfg(feature = "runtime-benchmarks")]
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

fn parse_timekeeper_cpu_cores(
    s: &str,
) -> Result<HashSet<usize>, Box<dyn std::error::Error + Send + Sync>> {
    if s.is_empty() {
        return Ok(HashSet::new());
    }

    let mut cpu_cores = HashSet::new();
    for s in s.split(',') {
        let mut parts = s.split('-');
        let range_start = parts
            .next()
            .ok_or("Bad string format, must be comma separated list of CPU cores or ranges")?
            .parse()?;
        if let Some(range_end) = parts.next() {
            let range_end = range_end.parse()?;

            cpu_cores.extend(range_start..=range_end);
        } else {
            cpu_cores.insert(range_start);
        }
    }

    Ok(cpu_cores)
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

    /// Run a node.
    #[clap(flatten)]
    pub run: RunCmd,

    /// Where local DSN node will listen for incoming connections.
    // TODO: Add more DSN-related parameters
    #[arg(long, default_values_t = [
        "/ip4/0.0.0.0/udp/30433/quic-v1".parse::<Multiaddr>().expect("Manual setting"),
        "/ip4/0.0.0.0/tcp/30433".parse::<Multiaddr>().expect("Manual setting"),
    ])]
    pub dsn_listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    #[arg(long)]
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,

    /// Reserved peers for DSN.
    #[arg(long)]
    pub dsn_reserved_peers: Vec<Multiaddr>,

    /// Defines max established incoming connection limit for DSN.
    #[arg(long, default_value_t = 50)]
    pub dsn_in_connections: u32,

    /// Defines max established outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    pub dsn_out_connections: u32,

    /// Defines max pending incoming connection limit for DSN.
    #[arg(long, default_value_t = 100)]
    pub dsn_pending_in_connections: u32,

    /// Defines max pending outgoing swarm connection limit for DSN.
    #[arg(long, default_value_t = 150)]
    pub dsn_pending_out_connections: u32,

    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses
    /// in Kademlia DHT for the DSN.
    #[arg(long, default_value_t = false)]
    pub dsn_enable_private_ips: bool,

    /// Defines whether we should run blocking Kademlia bootstrap() operation before other requests.
    #[arg(long, default_value_t = false)]
    pub dsn_disable_bootstrap_on_start: bool,

    /// Enables DSN-sync on startup.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub sync_from_dsn: bool,

    /// Known external addresses
    #[arg(long, alias = "dsn-external-address")]
    pub dsn_external_addresses: Vec<Multiaddr>,

    /// Domain arguments
    ///
    /// The command-line arguments provided first will be passed to the embedded consensus node,
    /// while the arguments provided after `--` will be passed to the domain node.
    ///
    /// subspace-node [consensus-chain-args] -- [domain-args]
    #[arg(raw = true)]
    pub domain_args: Vec<String>,

    /// Parameters used to create the storage monitor.
    #[clap(flatten)]
    pub storage_monitor: StorageMonitorParams,

    /// Use the block request handler implementation from subspace
    /// instead of the default substrate handler.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub enable_subspace_block_relay: bool,

    /// Assigned PoT role for this node.
    #[arg(long)]
    pub timekeeper: bool,

    /// CPU cores that timekeeper can use.
    ///
    /// At least 2 cores should be provided, if more cores than necessary are provided, random cores
    /// out of provided will be utilized, if not enough cores are provided timekeeper may occupy
    /// random CPU cores.
    ///
    /// Comma separated list of individual cores or ranges of cores.
    ///
    /// Examples:
    /// * `0,1` - use cores 0 and 1
    /// * `0-3` - use cores 0, 1, 2 and 3
    /// * `0,1,6-7` - use cores 0, 1, 6 and 7
    #[arg(long, default_value = "", value_parser = parse_timekeeper_cpu_cores, verbatim_doc_comment)]
    pub timekeeper_cpu_cores: HashSet<usize>,

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
        let mut chain_spec = match id {
            "gemini-3g-compiled" => chain_spec::gemini_3g_compiled()?,
            "gemini-3g" => chain_spec::gemini_3g_config()?,
            "devnet" => chain_spec::devnet_config()?,
            "devnet-compiled" => chain_spec::devnet_config_compiled()?,
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
}
