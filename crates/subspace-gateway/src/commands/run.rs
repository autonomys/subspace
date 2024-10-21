//! Gateway run command.
//! This is the primary command for the gateway.

mod dsn;

use crate::commands::run::dsn::NetworkArgs;
use crate::commands::shutdown_signal;
use clap::Parser;
use futures::{select, FutureExt};
use std::pin::pin;
use std::{env, future};
use tracing::info;

/// Options for running a node
#[derive(Debug, Parser)]
pub struct RunOptions {
    #[clap(flatten)]
    gateway: GatewayOptions,
}

/// Options for running a gateway
#[derive(Debug, Parser)]
pub(super) struct GatewayOptions {
    /// Enable development mode.
    ///
    /// Implies following flags (unless customized):
    /// * `--allow-private-ips`
    #[arg(long, verbatim_doc_comment)]
    dev: bool,

    #[clap(flatten)]
    dsn_options: NetworkArgs,
}

/// Default run command for gateway
#[expect(clippy::redundant_locals, reason = "code is incomplete")]
pub async fn run(run_options: RunOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let RunOptions {
        gateway: GatewayOptions {
            dev,
            mut dsn_options,
        },
    } = run_options;

    // Development mode handling is limited to this section
    {
        if dev {
            dsn_options.allow_private_ips = true;
        }
    }

    info!("Subspace Gateway");
    info!("✌️  version {}", env!("CARGO_PKG_VERSION"));
    info!("❤️  by {}", env!("CARGO_PKG_AUTHORS"));

    // TODO: move this service code into its own function, in a new library part of this crate
    #[expect(unused_variables, reason = "implementation is incomplete")]
    let (dsn_node, mut dsn_node_runner, node_client) = dsn::configure_network(dsn_options).await?;
    let dsn_fut = dsn_node_runner.run();

    let rpc_fut = future::pending::<()>();

    // This defines order in which things are dropped
    let dsn_fut = dsn_fut;
    let rpc_fut = rpc_fut;

    let dsn_fut = pin!(dsn_fut);
    let rpc_fut = pin!(rpc_fut);

    select! {
        // Signal future
        () = signal.fuse() => {},

        // Networking future
        () = dsn_fut.fuse() => {
            info!("DSN network runner exited.");
        },

        // RPC service future
        () = rpc_fut.fuse() => {
            info!("RPC server exited.");
        },

    }

    anyhow::Ok(())
}
