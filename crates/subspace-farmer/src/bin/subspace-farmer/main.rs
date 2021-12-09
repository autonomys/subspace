mod commands;
mod utils;

use anyhow::Result;
use clap::{Parser, ValueHint};
use env_logger::Env;
use log::info;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

// TODO: Separate commands for erasing the plot and wiping everything
#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Erase existing plot (including identity)
    ErasePlot {
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
    },
    /// Start a farmer using previously created plot
    Farm {
        /// Custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
        /// WebSocket RPC URL of the Subspace node to connect to
        #[clap(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
        node_rpc_url: String,
        /// Host and port where built-in WebSocket RPC server should listen for incoming connections
        #[clap(long, default_value = "127.0.0.1:9955")]
        ws_server_listen_addr: SocketAddr,
    },
}

/// Helper function for ignoring the error that given file/directory does not exist.
fn try_remove<P: AsRef<Path>>(
    path: P,
    remove: impl FnOnce(P) -> std::io::Result<()>,
) -> Result<()> {
    if path.as_ref().exists() {
        remove(path)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::new().default_filter_or("info"));
    let command: Command = Command::parse();
    match command {
        Command::ErasePlot { custom_path } => {
            let path = utils::get_path(custom_path);
            info!("Erasing the plot");
            try_remove(path.join("plot.bin"), fs::remove_file)?;
            info!("Erasing plot metadata");
            try_remove(path.join("plot-metadata"), fs::remove_dir_all)?;
            info!("Erasing plot commitments");
            try_remove(path.join("commitments"), fs::remove_dir_all)?;
            info!("Erasing object mappings");
            try_remove(path.join("object-mappings"), fs::remove_dir_all)?;
            info!("Erasing identity");
            try_remove(path.join("identity.bin"), fs::remove_file)?;
            info!("Done");
        }
        Command::Farm {
            custom_path,
            node_rpc_url,
            ws_server_listen_addr,
        } => {
            let path = utils::get_path(custom_path);
            commands::farm(path, &node_rpc_url, ws_server_listen_addr).await?;
        }
    }
    Ok(())
}
