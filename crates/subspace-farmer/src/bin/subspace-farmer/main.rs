mod bench_rpc_client;
mod commands;
mod ss58;
mod utils;

use anyhow::Result;
use clap::{ArgEnum, Parser, ValueHint};
use ss58::parse_ss58_reward_address;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use subspace_core_primitives::PublicKey;
use subspace_networking::libp2p::Multiaddr;
use tempfile::TempDir;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::{self};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Arguments for farmer
#[derive(Debug, Parser)]
struct FarmingArgs {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[clap(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported, subspace networking is disabled when none specified.
    #[clap(long)]
    listen_on: Vec<Multiaddr>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[clap(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Host and port where built-in WebSocket RPC server should listen for incoming connections
    #[clap(long, short, default_value = "127.0.0.1:9955")]
    ws_server_listen_addr: SocketAddr,
    /// Address for farming rewards
    #[clap(long, parse(try_from_str = parse_ss58_reward_address))]
    reward_address: PublicKey,
    /// Maximum plot size in human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
    ///
    /// Only `G` and `T` endings are supported.
    #[clap(long, parse(try_from_str = parse_human_readable_size))]
    plot_size: u64,
    /// Maximum single plot size in bytes human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
    ///
    /// Only `G` and `T` endings are supported.
    ///
    /// Only a developer testing flag, as it might be needed for testing.
    #[clap(long, parse(try_from_str = parse_human_readable_size))]
    max_plot_size: Option<u64>,
    /// Enable DSN subscription for archiving segments.
    #[clap(long)]
    enable_dsn_archiving: bool,
    /// Use dsn for syncing
    #[clap(long)]
    dsn_sync: bool,
    /// Do not archive from the node
    #[clap(long)]
    disable_node_archiving: bool,
}

#[derive(Debug, Clone, Copy, ArgEnum)]
enum WriteToDisk {
    Nothing,
    Everything,
}

impl Default for WriteToDisk {
    fn default() -> Self {
        Self::Everything
    }
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    /// Wipes plot and identity
    Wipe,
    /// Start a farmer using previously created plot
    Farm(FarmingArgs),
    /// Benchmark disk in order to see a throughput of the disk for plotting
    Bench {
        /// Maximum plot size in human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
        ///
        /// Only `G` and `T` endings are supported.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        plot_size: u64,
        /// Maximum single plot size in bytes human readable format (e.g. 10G, 2T) or just bytes (e.g. 4096).
        ///
        /// Only `G` and `T` endings are supported.
        ///
        /// Only a developer testing flag, as it might be needed for testing.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        max_plot_size: Option<u64>,
        /// How much things to write on disk (the more we write during benchmark, the more accurate
        /// it is)
        #[clap(arg_enum, long, default_value_t)]
        write_to_disk: WriteToDisk,
        /// Amount of data to plot for benchmarking.
        ///
        /// Only `G` and `T` endings are supported.
        #[clap(long, parse(try_from_str = parse_human_readable_size))]
        write_pieces_size: u64,
        /// Skip recommitment benchmark
        #[clap(long)]
        no_recommitments: bool,
    },
}

#[derive(Debug, Parser)]
#[clap(about, version)]
struct Command {
    #[clap(subcommand)]
    subcommand: Subcommand,
    /// Base path for data storage instead of platform-specific default
    #[clap(long, default_value_os_t = utils::default_base_path(), value_hint = ValueHint::FilePath)]
    base_path: PathBuf,
    /// Run temporary farmer, this will create a temporary directory for storing farmer data that
    /// will be delete at the end of the process
    #[clap(long, conflicts_with = "base-path")]
    tmp: bool,
}

fn parse_human_readable_size(s: &str) -> Result<u64, std::num::ParseIntError> {
    const SUFFIXES: &[(&str, u64)] = &[
        ("G", 10u64.pow(9)),
        ("GB", 10u64.pow(9)),
        ("T", 10u64.pow(12)),
        ("TB", 10u64.pow(12)),
    ];

    SUFFIXES
        .iter()
        .find_map(|(suf, mul)| s.strip_suffix(suf).map(|s| (s, mul)))
        .map(|(s, mul)| s.parse::<u64>().map(|num| num * mul))
        .unwrap_or_else(|| s.parse::<u64>())
}

// TODO: Add graceful shutdown handling, without it temporary directory may be left not deleted
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            fmt::layer().with_span_events(FmtSpan::CLOSE).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .init();

    let command = Command::parse();

    let (base_path, _tmp_directory) = if command.tmp {
        let tmp_directory = TempDir::new()?;
        (tmp_directory.as_ref().to_path_buf(), Some(tmp_directory))
    } else {
        (command.base_path, None)
    };

    match command.subcommand {
        Subcommand::Wipe => {
            commands::wipe(&base_path)?;
            info!("Done");
        }
        Subcommand::Farm(farming_args) => {
            if !base_path.exists() {
                fs::create_dir_all(&base_path).unwrap_or_else(|error| {
                    panic!(
                        "Failed to create data directory {:?}: {:?}",
                        base_path, error
                    )
                });
            }

            commands::farm(base_path, farming_args).await?;
        }
        Subcommand::Bench {
            plot_size,
            max_plot_size,
            write_to_disk,
            write_pieces_size,
            no_recommitments,
        } => {
            if !base_path.exists() {
                fs::create_dir_all(&base_path).unwrap_or_else(|error| {
                    panic!(
                        "Failed to create data directory {:?}: {:?}",
                        base_path, error
                    )
                });
            }

            commands::bench(
                base_path,
                plot_size,
                max_plot_size,
                write_to_disk,
                write_pieces_size,
                !no_recommitments,
            )
            .await?
        }
    }
    Ok(())
}
