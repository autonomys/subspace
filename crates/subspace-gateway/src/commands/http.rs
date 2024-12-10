//! Gateway http command.
//! This command starts an HTTP server to serve object requests.

pub(crate) mod server;

use crate::commands::http::server::{start_server, ServerParameters};
use crate::commands::{initialize_object_fetcher, shutdown_signal, GatewayOptions};
use clap::Parser;
use futures::{select, FutureExt};
use tracing::info;

/// Options for HTTP server.
#[derive(Debug, Parser)]
pub(crate) struct HttpCommandOptions {
    #[clap(flatten)]
    gateway_options: GatewayOptions,

    #[arg(long, default_value = "127.0.0.1:3000")]
    indexer_endpoint: String,

    #[arg(long, default_value = "127.0.0.1:8080")]
    http_listen_on: String,
}

/// Runs an HTTP server which fetches DSN objects based on object hashes.
pub async fn run(run_options: HttpCommandOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let HttpCommandOptions {
        gateway_options,
        indexer_endpoint,
        http_listen_on,
    } = run_options;

    let (object_fetcher, mut dsn_node_runner) = initialize_object_fetcher(gateway_options).await?;
    let dsn_fut = dsn_node_runner.run();

    let server_params = ServerParameters {
        object_fetcher,
        indexer_endpoint,
        http_endpoint: http_listen_on,
    };
    let http_server_fut = start_server(server_params);

    // This defines order in which things are dropped
    let dsn_fut = dsn_fut;
    let http_server_fut = http_server_fut;

    select! {
        // Signal future
        () = signal.fuse() => {},

        // Networking future
        () = dsn_fut.fuse() => {
            info!("DSN network runner exited.");
        },

        // HTTP service future
        _ = http_server_fut.fuse() => {
            info!("HTTP server exited.");
        },
    }

    anyhow::Ok(())
}
