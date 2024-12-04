//! Gateway run command.
//! This is the primary command for the gateway.

pub(crate) mod server;

use crate::commands::network::configure_network;
use crate::commands::rpc::server::{launch_rpc_server, RpcOptions, RPC_DEFAULT_PORT};
use crate::commands::{shutdown_signal, GatewayOptions, PIECE_PROVIDER_MULTIPLIER};
use crate::piece_getter::DsnPieceGetter;
use crate::piece_validator::SegmentCommitmentPieceValidator;
use anyhow::anyhow;
use async_lock::Semaphore;
use clap::Parser;
use futures::{select, FutureExt};
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::pieces::Record;
use subspace_data_retrieval::object_fetcher::ObjectFetcher;
use subspace_erasure_coding::ErasureCoding;
use subspace_gateway_rpc::{SubspaceGatewayRpc, SubspaceGatewayRpcConfig};
use subspace_kzg::Kzg;
use subspace_networking::utils::piece_provider::PieceProvider;
use tracing::info;

/// Options for running a node
#[derive(Debug, Parser)]
pub(crate) struct RpcCommandOptions {
    #[clap(flatten)]
    gateway: GatewayOptions,

    /// Options for RPC
    #[clap(flatten)]
    rpc_options: RpcOptions<RPC_DEFAULT_PORT>,
}

/// Default run command for gateway
pub async fn run(run_options: RpcCommandOptions) -> anyhow::Result<()> {
    let signal = shutdown_signal();

    let RpcCommandOptions {
        gateway:
            GatewayOptions {
                dev,
                max_size,
                mut dsn_options,
            },
        rpc_options,
    } = run_options;

    // Development mode handling is limited to this section
    {
        if dev {
            dsn_options.allow_private_ips = true;
        }
    }

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
        Arc::new(Semaphore::new(
            out_connections as usize * PIECE_PROVIDER_MULTIPLIER,
        )),
    );
    let piece_getter = DsnPieceGetter::new(piece_provider);
    let object_fetcher = ObjectFetcher::new(piece_getter.into(), erasure_coding, Some(max_size));

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
