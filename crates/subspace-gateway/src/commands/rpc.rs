//! Gateway rpc command.
//! This command starts an RPC server to serve object requests from the DSN.
pub(crate) mod server;

use crate::commands::rpc::server::{launch_rpc_server, RpcOptions, RPC_DEFAULT_PORT};
use crate::commands::{initialize_object_fetcher, shutdown_signal, GatewayOptions};
use clap::Parser;
use futures::{select, FutureExt};
use std::pin::pin;
use subspace_gateway_rpc::{SubspaceGatewayRpc, SubspaceGatewayRpcConfig};
use tracing::info;

/// Options for RPC server.
#[derive(Debug, Parser)]
pub(crate) struct RpcCommandOptions {
    #[clap(flatten)]
    gateway_options: GatewayOptions,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions<RPC_DEFAULT_PORT>,
}

/// Runs an RPC server which fetches DSN objects based on mappings.
pub async fn run(run_options: RpcCommandOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let RpcCommandOptions {
        gateway_options,
        rpc_options,
    } = run_options;
    let (object_fetcher, mut dsn_node_runner) = initialize_object_fetcher(gateway_options).await?;
    let dsn_fut = dsn_node_runner.run();

    let rpc_api = SubspaceGatewayRpc::new(SubspaceGatewayRpcConfig { object_fetcher });
    let rpc_handle = launch_rpc_server(rpc_api, rpc_options).await?;
    let rpc_fut = rpc_handle.stopped();

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
