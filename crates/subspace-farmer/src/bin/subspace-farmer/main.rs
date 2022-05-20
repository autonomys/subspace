mod bench_rpc_client;
mod commands;
mod utils;

use anyhow::Result;
use clap::{ArgEnum, Parser, ValueHint};
use sp_core::crypto::PublicError;
use std::net::SocketAddr;
use std::path::PathBuf;
use subspace_core_primitives::PublicKey;
use subspace_networking::libp2p::Multiaddr;
use tracing::info;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

/// Arguments for farmer
#[derive(Debug, Parser)]
struct FarmingArgs {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[clap(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Custom path for data storage instead of platform-specific default
    #[clap(long, value_hint = ValueHint::FilePath)]
    custom_path: Option<PathBuf>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported, subspace networking is disabled when none specified
    #[clap(long)]
    listen_on: Vec<Multiaddr>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[clap(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Host and port where built-in WebSocket RPC server should listen for incoming connections
    #[clap(long, short, default_value = "127.0.0.1:9955")]
    ws_server_listen_addr: SocketAddr,
    /// Address for farming rewards
    #[clap(long, parse(try_from_str = parse_reward_address))]
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

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Wipes plot and identity
    Wipe {
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
    /// Start a farmer using previously created plot
    Farm(FarmingArgs),
    /// Benchmark disk in order to see a throughput of the disk for plotting
    Bench {
        /// Custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
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
        skip_recommitments: bool,
    },
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

fn parse_reward_address(s: &str) -> Result<PublicKey, PublicError> {
    s.parse::<sp_core::sr25519::Public>()
        .map(|key| PublicKey::from(key.0))
}

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

    match Command::parse() {
        Command::Wipe { custom_path } => {
            let path = utils::get_path(custom_path);
            commands::wipe(&path)?;
            info!("Done");
        }
        Command::Farm(args) => {
            commands::farm(args).await?;
        }
        Command::Bench {
            custom_path,
            plot_size,
            max_plot_size,
            write_to_disk,
            write_pieces_size,
            skip_recommitments,
        } => {
            commands::bench(
                custom_path,
                plot_size,
                max_plot_size,
                write_to_disk,
                write_pieces_size,
                skip_recommitments,
            )
            .await?
        }
    }
    Ok(())
}
