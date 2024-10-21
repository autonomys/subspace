//! Subspace gateway implementation.

// TODO: Remove
#![allow(
    clippy::needless_return,
    reason = "https://github.com/rust-lang/rust-clippy/issues/13458"
)]

mod commands;
mod node_client;

use crate::commands::{init_logger, raise_fd_limit, Command};
use clap::Parser;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Subspace gateway error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Other kind of error.
    #[error("Other: {0}")]
    Other(String),
}

impl From<String> for Error {
    #[inline]
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

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
