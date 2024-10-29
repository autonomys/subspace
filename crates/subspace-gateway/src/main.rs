//! Subspace gateway implementation.

mod commands;
mod node_client;
mod piece_getter;
mod piece_validator;

use crate::commands::{
    init_logger, raise_fd_limit, set_exit_on_panic, spawn_shutdown_watchdog, Command,
};
use clap::Parser;
use tokio::runtime::Handle;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    set_exit_on_panic();
    init_logger();
    raise_fd_limit();

    let command = Command::parse();

    match command {
        Command::Run(run_options) => {
            // The async runtime can wait forever for tasks to yield or finish.
            // This watchdog runs on shutdown, and makes sure the process exits within a timeout,
            // or when the user sends a second Ctrl-C.
            scopeguard::defer! {
                spawn_shutdown_watchdog(Handle::current());
            };
            commands::run::run(run_options).await?;
        }
    }

    Ok(())
}
