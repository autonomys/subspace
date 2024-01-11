use crate::commands::run::substrate::Cors;
use clap::Parser;
use sc_cli::{
    RpcMethods, RPC_DEFAULT_MAX_CONNECTIONS, RPC_DEFAULT_MAX_SUBS_PER_CONN, RPC_DEFAULT_PORT,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Options for RPC
#[derive(Debug, Parser)]
pub(super) struct RpcOptions {
    /// IP and port (TCP) on which to listen for RPC requests.
    ///
    /// Note: not all RPC methods are safe to be exposed publicly. Use an RPC proxy server to filter out
    /// dangerous methods.
    /// More details: <https://docs.substrate.io/main-docs/build/custom-rpc/#public-rpcs>.
    #[arg(long, default_value_t = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        RPC_DEFAULT_PORT,
    ))]
    pub(super) rpc_listen_on: SocketAddr,

    /// RPC methods to expose.
    /// - `unsafe`: Exposes every RPC method.
    /// - `safe`: Exposes only a safe subset of RPC methods, denying unsafe RPC methods.
    /// - `auto`: Acts as `safe` if non-localhost `--rpc-listen-on` is passed, otherwise
    ///           acts as `unsafe`.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        default_value_t = RpcMethods::Auto,
        verbatim_doc_comment
    )]
    pub(super) rpc_methods: RpcMethods,

    /// Set the the maximum concurrent subscriptions per connection.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_SUBS_PER_CONN)]
    pub(super) rpc_max_subscriptions_per_connection: u32,

    /// Maximum number of RPC server connections.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_CONNECTIONS)]
    pub(super) rpc_max_connections: u32,

    /// Specify browser Origins allowed to access the HTTP & WS RPC servers.
    /// A comma-separated list of origins (protocol://domain or special `null`
    /// value). Value of `all` will disable origin validation. Default is to
    /// allow localhost and <https://polkadot.js.org> origins. When running in
    /// --dev mode the default is to allow all origins.
    #[arg(long)]
    pub(super) rpc_cors: Option<Cors>,
}
