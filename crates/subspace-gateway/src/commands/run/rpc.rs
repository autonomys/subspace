//! RPC service configuration and launch.

use clap::Parser;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use subspace_gateway_rpc::{SubspaceGatewayRpc, SubspaceGatewayRpcApiServer};
use tracing::info;

/// The default gateway RPC port.
pub const RPC_DEFAULT_PORT: u16 = 9955;

/// Options for the RPC server.
#[derive(Debug, Parser)]
pub(crate) struct RpcOptions<const DEFAULT_PORT: u16> {
    /// IP and port (TCP) on which to listen for RPC requests.
    ///
    /// Note: not all RPC methods are safe to be exposed publicly. Use an RPC proxy server to filter out
    /// dangerous methods.
    /// More details: <https://docs.substrate.io/main-docs/build/custom-rpc/#public-rpcs>.
    #[arg(long, default_value_t = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        DEFAULT_PORT,
    ))]
    rpc_listen_on: SocketAddr,
    // TODO:
    // - Disable unsafe methods on public IP addresses
    // - Maximum number of connections
    // - RPC rate limiting, IPs/range that get rate-limit exceptions, trust proxy headers
    // - CORS
    // - Message buffer capacity
    // - Batch requests & max batch request length
}

/// Launch the RPC server `api` with the provided `options`.
// TODO:
// - add an argument for a custom tokio runtime
// - move this RPC code into a new library part of this crate
// - make a RPC config that is independent of clap
pub async fn launch_rpc_server<const P: u16>(
    rpc_api: SubspaceGatewayRpc,
    rpc_options: RpcOptions<P>,
) -> anyhow::Result<ServerHandle> {
    let server = ServerBuilder::default()
        .build(rpc_options.rpc_listen_on)
        .await?;
    let addr = server.local_addr()?;
    let server_handle = server.start(rpc_api.into_rpc());

    info!(?addr, "Running JSON-RPC server");

    Ok(server_handle)
}
