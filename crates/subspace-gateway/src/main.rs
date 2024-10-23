//! Subspace gateway implementation.

mod commands;
mod node_client;
mod piece_getter;
mod piece_validator;

use crate::commands::{init_logger, raise_fd_limit, Command};
use clap::Parser;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logger();
    raise_fd_limit();

    let command = Command::parse();

    match command {
        Command::Run(run_options) => {
            commands::run::run(run_options).await?;
        }
    }
    Ok(())
}
