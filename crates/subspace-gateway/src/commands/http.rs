//! Gateway http command.
//! This command starts an HTTP server to serve object requests.

pub(crate) mod server;

use crate::commands::http::server::{ServerParameters, start_server};
use crate::commands::{GatewayOptions, initialize_object_fetcher};
use clap::Parser;
use futures::{FutureExt, select};
use subspace_process::{run_future_in_dedicated_thread, shutdown_signal};
use tracing::info;

/// Options for HTTP server.
#[derive(Debug, Parser)]
pub(crate) struct HttpCommandOptions {
    #[clap(flatten)]
    gateway_options: GatewayOptions,

    #[arg(long, default_value = "http://127.0.0.1:3000")]
    indexer_endpoint: String,

    #[arg(long, default_value = "127.0.0.1:8080")]
    http_listen_on: String,
}

/// Runs an HTTP server which fetches DSN objects based on object hashes.
pub async fn run(run_options: HttpCommandOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal("gateway");

    let HttpCommandOptions {
        gateway_options,
        indexer_endpoint,
        http_listen_on,
    } = run_options;

    let (object_fetcher, mut dsn_node_runner) = initialize_object_fetcher(gateway_options).await?;
    let dsn_fut = run_future_in_dedicated_thread(
        move || async move { dsn_node_runner.run().await },
        "gateway-networking".to_string(),
    )?;

    // TODO: spawn this in a dedicated thread
    let server_params = ServerParameters {
        object_fetcher,
        indexer_endpoint,
        http_endpoint: http_listen_on,
    };
    let http_server_handle = actix_web::rt::spawn(start_server(server_params));

    // This defines order in which things are dropped
    let dsn_fut = dsn_fut;
    let http_server_handle = http_server_handle;

    select! {
        // Signal future
        () = signal.fuse() => {},

        // Networking future
        _ = dsn_fut.fuse() => {
            info!("DSN network runner exited.");
        },

        // HTTP service future
        _ = http_server_handle.fuse() => {
            info!("HTTP server exited.");
        },
    }

    anyhow::Ok(())
}
