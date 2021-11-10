//! subspace-farmer implementation overview
//!
//! The application typically runs two processes in parallel: plotting and farming.
//!
//! During plotting we create a binary plot file, which contains subspace-encoded pieces one
//! after another as well as RocksDB key-value database with tags, where key is tag (first 8 bytes
//! of `hmac(encoding, salt)`) and value is an offset of corresponding encoded piece in the plot (we
//! can do this because all pieces have the same size). So for every 4096 bytes we also store a
//! record with 8-bytes tag and 8-bytes index (+some overhead of RocksDB itself).
//!
//! During farming we receive a global challenge and need to find a solution, given target and
//! solution range. In order to find solution we derive local challenge as our target and do range
//! query in RocksDB. For that we interpret target as 64-bit unsigned integer, and find all of the
//! keys in tags database that are `target ± solution range` (while also handing overflow/underflow)
//! converted back to bytes.
#![feature(try_blocks)]
#![feature(hash_drain_filter)]

mod commands;
mod commitments;
mod farming;
mod identity;
mod object_mappings;
mod plot;
mod plotting;
mod utils;
mod web_socket_rpc;

use anyhow::Result;
use clap::{Parser, ValueHint};
use env_logger::Env;
use log::info;
use std::fs;
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
        /// Use custom path for data storage instead of platform-specific default
        #[clap(long, value_hint = ValueHint::FilePath)]
        custom_path: Option<PathBuf>,
        /// Specify WebSocket RPC server TCP port
        #[clap(long, default_value = "ws://127.0.0.1:9944")]
        ws_server: String,
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
            ws_server,
        } => {
            let path = utils::get_path(custom_path);
            commands::farm(path, &ws_server).await?;
        }
    }
    Ok(())
}
