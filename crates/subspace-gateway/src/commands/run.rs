//! Gateway run command.
//! This is the primary command for the gateway.

mod dsn;
mod rpc;

use crate::commands::run::dsn::NetworkArgs;
use crate::commands::run::rpc::{launch_rpc_server, RpcOptions, RPC_DEFAULT_PORT};
use crate::commands::shutdown_signal;
use anyhow::anyhow;
use clap::Parser;
use futures::{select, FutureExt};
use std::env;
use std::num::NonZeroUsize;
use std::pin::pin;
use subspace_core_primitives::pieces::Record;
use subspace_data_retrieval::object_fetcher::ObjectFetcher;
use subspace_erasure_coding::ErasureCoding;
use subspace_gateway_rpc::{SubspaceGatewayRpc, SubspaceGatewayRpcConfig};
use subspace_networking::utils::piece_provider::{NoPieceValidator, PieceProvider};
use tracing::info;

/// Options for running a node
#[derive(Debug, Parser)]
pub(crate) struct RunOptions {
    #[clap(flatten)]
    gateway: GatewayOptions,
}

/// Options for running a gateway
#[derive(Debug, Parser)]
pub(crate) struct GatewayOptions {
    /// Enable development mode.
    ///
    /// Implies following flags (unless customized):
    /// * `--allow-private-ips`
    #[arg(long, verbatim_doc_comment)]
    dev: bool,

    #[clap(flatten)]
    dsn_options: NetworkArgs,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions<RPC_DEFAULT_PORT>,
    // TODO: maximum object size
}

/// Default run command for gateway
#[expect(clippy::redundant_locals, reason = "code is incomplete")]
pub async fn run(run_options: RunOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let RunOptions {
        gateway:
            GatewayOptions {
                dev,
                mut dsn_options,
                rpc_options,
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

    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;

    // TODO: move this service code into its own function, in a new library part of this crate
    #[expect(unused_variables, reason = "implementation is incomplete")]
    let (dsn_node, mut dsn_node_runner, node_client) = dsn::configure_network(dsn_options).await?;
    let dsn_fut = dsn_node_runner.run();

    // TODO: implement piece validation
    let piece_provider = PieceProvider::new(dsn_node, NoPieceValidator);
    let object_fetcher = ObjectFetcher::new(piece_provider, erasure_coding, None);

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
