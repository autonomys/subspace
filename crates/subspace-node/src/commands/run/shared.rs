use clap::Parser;
use sc_cli::{
    Cors, RPC_DEFAULT_MAX_CONNECTIONS, RPC_DEFAULT_MAX_SUBS_PER_CONN,
    RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN, RpcMethods,
};
use sc_service::config::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;

/// Options for RPC
#[derive(Debug, Parser)]
pub(super) struct RpcOptions<const DEFAULT_PORT: u16> {
    /// IP and port (TCP) on which to listen for RPC requests.
    ///
    /// Note: not all RPC methods are safe to be exposed publicly. Use an RPC proxy server to filter out
    /// dangerous methods.
    /// More details: <https://docs.substrate.io/main-docs/build/custom-rpc/#public-rpcs>.
    #[arg(long, default_value_t = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        DEFAULT_PORT,
    ))]
    pub(super) rpc_listen_on: SocketAddr,

    /// RPC methods to expose.
    /// - `unsafe`: Exposes every RPC method.
    /// - `safe`: Exposes only a safe subset of RPC methods, denying unsafe RPC methods.
    /// - `auto`: Acts as `safe` if non-localhost `--rpc-listen-on` is passed, otherwise acts as
    ///   `unsafe`.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        default_value_t = RpcMethods::Auto,
        verbatim_doc_comment
    )]
    pub(super) rpc_methods: RpcMethods,

    /// RPC rate limiting (calls/minute) for each connection.
    ///
    /// This is disabled by default.
    ///
    /// For example `--rpc-rate-limit 10` will maximum allow
    /// 10 calls per minute per connection.
    #[arg(long)]
    pub(super) rpc_rate_limit: Option<NonZeroU32>,

    /// Disable RPC rate limiting for certain ip addresses.
    ///
    /// Each IP address must be in CIDR notation such as `1.2.3.4/24`.
    #[arg(long, num_args = 1..)]
    pub(super) rpc_rate_limit_whitelisted_ips: Vec<IpNetwork>,

    /// Trust proxy headers for disable rate limiting.
    ///
    /// By default, the rpc server will not trust headers such `X-Real-IP`, `X-Forwarded-For` and
    /// `Forwarded` and this option will make the rpc server to trust these headers.
    ///
    /// For instance this may be secure if the rpc server is behind a reverse proxy and that the
    /// proxy always sets these headers.
    #[arg(long)]
    pub(super) rpc_rate_limit_trust_proxy_headers: bool,

    /// Set the maximum concurrent subscriptions per connection.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_SUBS_PER_CONN)]
    pub(super) rpc_max_subscriptions_per_connection: u32,

    /// Maximum number of RPC server connections.
    #[arg(long, default_value_t = RPC_DEFAULT_MAX_CONNECTIONS)]
    pub(super) rpc_max_connections: u32,

    /// The number of messages the RPC server is allowed to keep in memory.
    ///
    /// If the buffer becomes full then the server will not process
    /// new messages until the connected client start reading the
    /// underlying messages.
    ///
    /// This applies per connection which includes both
    /// JSON-RPC methods calls and subscriptions.
    #[arg(long, default_value_t = RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN)]
    pub(super) rpc_message_buffer_capacity_per_connection: u32,

    /// Disable RPC batch requests
    #[arg(long, alias = "rpc_no_batch_requests", conflicts_with_all = &["rpc_max_batch_request_len"])]
    pub(super) rpc_disable_batch_requests: bool,

    /// Limit the max length per RPC batch request
    #[arg(long, conflicts_with_all = &["rpc_disable_batch_requests"])]
    pub(super) rpc_max_batch_request_len: Option<u32>,

    /// Specify browser Origins allowed to access the HTTP & WS RPC servers.
    /// A comma-separated list of origins (protocol://domain or special `null`
    /// value). Value of `all` will disable origin validation. Default is to
    /// allow localhost and <https://polkadot.js.org> origins. When running in
    /// --dev mode the default is to allow all origins.
    #[arg(long)]
    pub(super) rpc_cors: Option<Cors>,
}

/// Parameters for Trie cache.
#[derive(Debug, Parser)]
pub struct TrieCacheParams {
    /// Specify the state cache size.
    ///
    /// Providing `0` will disable the cache.
    #[arg(long, value_name = "Bytes", default_value_t = 67108864)]
    pub trie_cache_size: usize,
}

impl TrieCacheParams {
    /// Specify the trie cache maximum size.
    pub fn trie_cache_maximum_size(&self) -> Option<usize> {
        if self.trie_cache_size == 0 {
            None
        } else {
            Some(self.trie_cache_size)
        }
    }
}
