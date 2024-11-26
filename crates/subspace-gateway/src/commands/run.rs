//! Gateway run command.
//! This is the primary command for the gateway.

mod network;
mod rpc;

use crate::commands::run::network::{configure_network, NetworkArgs};
use crate::commands::run::rpc::{launch_rpc_server, RpcOptions, RPC_DEFAULT_PORT};
use crate::commands::shutdown_signal;
use crate::piece_getter::DsnPieceGetter;
use crate::piece_validator::SegmentCommitmentPieceValidator;
use anyhow::anyhow;
use async_lock::Semaphore;
use clap::Parser;
use futures::{select, FutureExt};
use std::env;
use std::num::NonZeroUsize;
use std::pin::pin;
use subspace_core_primitives::pieces::Record;
use subspace_data_retrieval::object_fetcher::ObjectFetcher;
use subspace_erasure_coding::ErasureCoding;
use subspace_gateway_rpc::{SubspaceGatewayRpc, SubspaceGatewayRpcConfig};
use subspace_kzg::Kzg;
use subspace_networking::utils::piece_provider::PieceProvider;
use tracing::info;

/// The default size limit, based on the maximum block size in some domains.
pub const DEFAULT_MAX_SIZE: usize = 5 * 1024 * 1024;
/// Multiplier on top of outgoing connections number for piece downloading purposes
const PIECE_PROVIDER_MULTIPLIER: usize = 10;

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

    /// The maximum object size to fetch.
    /// Larger objects will return an error.
    #[arg(long, default_value_t = DEFAULT_MAX_SIZE)]
    max_size: usize,

    #[clap(flatten)]
    dsn_options: NetworkArgs,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions<RPC_DEFAULT_PORT>,
}

/// Default run command for gateway
pub async fn run(run_options: RunOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let RunOptions {
        gateway:
            GatewayOptions {
                dev,
                max_size,
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

    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;

    let out_connections = dsn_options.out_connections;
    // TODO: move this service code into its own function, in a new library part of this crate
    let (dsn_node, mut dsn_node_runner, node_client) = configure_network(dsn_options).await?;
    let dsn_fut = dsn_node_runner.run();

    let piece_provider = PieceProvider::new(
        dsn_node.clone(),
        SegmentCommitmentPieceValidator::new(dsn_node, node_client, kzg),
        Semaphore::new(out_connections as usize * PIECE_PROVIDER_MULTIPLIER),
    );
    let piece_getter = DsnPieceGetter::new(piece_provider);
    let object_fetcher = ObjectFetcher::new(piece_getter, erasure_coding, Some(max_size));

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
