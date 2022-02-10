mod commands;
mod utils;

use anyhow::Result;
use clap::{Parser, ValueHint};
use env_logger::Env;
use log::info;
use std::net::SocketAddr;
use std::path::PathBuf;
use subspace_networking::libp2p::Multiaddr;

#[derive(Debug, Parser)]
enum IdentityCommand {
    /// View identity information
    View {
        /// Print SS58 address [default if no other option is specified]
        #[clap(long, short)]
        address: bool,
        /// Print public key (hex)
        #[clap(long, short)]
        public_key: bool,
        /// Print mnemonic (NOTE: never share this with anyone!)
        #[clap(long, short)]
        mnemonic: bool,
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
    /// Import identity from BIP39 mnemonic phrase
    ImportFromMnemonic {
        /// BIP39 mnemonic phrase to import identity from
        phrase: String,
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Identity management
    #[clap(subcommand)]
    Identity(IdentityCommand),
    /// Erase existing plot (doesn't touch identity)
    ErasePlot {
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
    /// Wipes plot and identity
    Wipe {
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
    /// Start a farmer using previously created plot
    Farm {
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::new().default_filter_or("info"));
    let command: Command = Command::parse();
    match command {
        Command::Identity(identity_command) => {
            commands::identity(identity_command)?;
        }
        Command::ErasePlot { custom_path } => {
            let path = utils::get_path(custom_path);
            commands::erase_plot(&path)?;
            info!("Done");
        }
        Command::Wipe { custom_path } => {
            let path = utils::get_path(custom_path);
            commands::wipe(&path)?;
            info!("Done");
        }
        Command::Farm {
            bootstrap_nodes,
            custom_path,
            listen_on,
            node_rpc_url,
            ws_server_listen_addr,
        } => {
            let path = utils::get_path(custom_path);
            commands::farm(
                path,
                bootstrap_nodes,
                listen_on,
                &node_rpc_url,
                ws_server_listen_addr,
            )
            .await?;
        }
    }
    Ok(())
}
