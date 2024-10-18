//! DSN config and implementation for the gateway.

use clap::Parser;
use subspace_networking::libp2p::kad::Mode;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::{construct, Config, KademliaMode, Node, NodeRunner};

/// Configuration for network stack
#[derive(Debug, Parser)]
pub(crate) struct NetworkArgs {
    /// Multiaddrs of DSN bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long)]
    pub(crate) dsn_bootstrap_nodes: Vec<Multiaddr>,

    /// Enable non-global (private, shared, loopback..) addresses in the Kademlia DHT.
    /// By default these addresses are excluded from the DHT.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_private_ips: bool,

    /// Multiaddrs of DSN reserved nodes to maintain a connection to, multiple are supported
    #[arg(long)]
    pub(crate) dsn_reserved_peers: Vec<Multiaddr>,

    /// Maximum established outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pub(crate) out_connections: u32,

    /// Maximum pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pub(crate) pending_out_connections: u32,
}

/// Create a DSN network client with the supplied configuration.
pub(crate) fn configure_network(
    NetworkArgs {
        dsn_bootstrap_nodes,
        allow_private_ips,
        dsn_reserved_peers,
        out_connections,
        pending_out_connections,
    }: NetworkArgs,
) -> anyhow::Result<(Node, NodeRunner<()>)> {
    // TODO:
    // - store keypair on disk and allow CLI override
    // - cache known peers on disk
    // - get default dsnBootstrapNodes from chainspec?
    // - prometheus telemetry
    let default_config = Config::<()>::default();
    let config = Config {
        reserved_peers: dsn_reserved_peers,
        allow_non_global_addresses_in_dht: allow_private_ips,
        max_established_outgoing_connections: out_connections,
        max_pending_outgoing_connections: pending_out_connections,
        bootstrap_addresses: dsn_bootstrap_nodes,
        kademlia_mode: KademliaMode::Static(Mode::Client),
        ..default_config
    };

    let (node, node_runner) = construct(config)?;

    Ok((node, node_runner))
}
