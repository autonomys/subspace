//! DSN config and implementation for the gateway.

use crate::node_client::{NodeClient, RpcNodeClient};
use anyhow::anyhow;
use clap::{Parser, ValueHint};
use subspace_networking::libp2p::kad::Mode;
use subspace_networking::libp2p::{Multiaddr, identity};
use subspace_networking::protocols::request_response::handlers::cached_piece_by_index::CachedPieceByIndexRequestHandler;
use subspace_networking::protocols::request_response::handlers::piece_by_index::PieceByIndexRequestHandler;
use subspace_networking::{Config, KademliaMode, Node, NodeRunner, construct};
use tracing::{debug, info};

/// Configuration for network stack
#[derive(Debug, Parser)]
pub(crate) struct NetworkArgs {
    /// WebSocket RPC URL of the Subspace node to connect to.
    ///
    /// This node provides the DSN protocol version, default bootstrap nodes, and piece validation
    /// metadata.
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,

    /// Multiaddrs of DSN bootstrap nodes to connect to on startup, multiple are supported.
    ///
    /// The default bootstrap nodes are fetched from the node RPC connection.
    #[arg(long = "bootstrap-node")]
    bootstrap_nodes: Vec<Multiaddr>,

    /// Multiaddrs of DSN reserved nodes to maintain a connection to, multiple are supported.
    #[arg(long = "reserved-peer")]
    reserved_peers: Vec<Multiaddr>,

    /// Enable non-global (private, shared, loopback..) addresses in the Kademlia DHT.
    /// By default, these addresses are excluded from the DHT.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_private_ips: bool,

    /// Maximum established outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pub(crate) out_connections: u32,

    /// Maximum pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pending_out_connections: u32,

    /// Multiaddrs to listen on for DSN connections, multiple are supported.
    ///
    /// This is mainly for debugging.
    #[arg(long)]
    listen_on: Vec<Multiaddr>,
}

/// Create a DSN network client with the supplied configuration.
// TODO:
// - move this DSN code into a new library part of this crate
// - change NetworkArgs to a struct that's independent of clap
pub async fn configure_network(
    NetworkArgs {
        node_rpc_url,
        mut bootstrap_nodes,
        reserved_peers,
        allow_private_ips,
        out_connections,
        pending_out_connections,
        listen_on,
    }: NetworkArgs,
) -> anyhow::Result<(Node, NodeRunner, RpcNodeClient)> {
    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = RpcNodeClient::new(&node_rpc_url)
        .await
        .map_err(|error| anyhow!("Failed to connect to node RPC: {error}"))?;

    // The gateway only needs the first part of the farmer info.
    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow!("Failed to get gateway app info: {error}"))?;

    // Fall back to the node's bootstrap nodes.
    if bootstrap_nodes.is_empty() {
        debug!(
            bootstrap_nodes = ?farmer_app_info.dsn_bootstrap_nodes,
            "Setting DSN bootstrap nodes..."
        );
        bootstrap_nodes.clone_from(&farmer_app_info.dsn_bootstrap_nodes);
    }

    let dsn_protocol_version = hex::encode(farmer_app_info.genesis_hash);
    debug!(?dsn_protocol_version, "Setting DSN protocol version...");

    // TODO:
    // - use a fixed identity keypair
    // - cache known peers on disk
    // - prometheus telemetry
    let keypair = identity::ed25519::Keypair::generate();
    let keypair = identity::Keypair::from(keypair);
    let default_config = Config::new(dsn_protocol_version, keypair, None);

    let config = Config {
        bootstrap_addresses: bootstrap_nodes,
        reserved_peers,
        allow_non_global_addresses_in_dht: allow_private_ips,
        request_response_protocols: vec![
            // We need to enable protocol to request pieces
            CachedPieceByIndexRequestHandler::create(|_, _| async { None }),
            // We need to enable protocol to request pieces
            PieceByIndexRequestHandler::create(|_, _| async { None }),
        ],
        max_established_outgoing_connections: out_connections,
        max_pending_outgoing_connections: pending_out_connections,
        kademlia_mode: KademliaMode::Static(Mode::Client),
        listen_on,
        ..default_config
    };

    let (node, node_runner) = construct(config)?;

    Ok((node, node_runner, node_client))
}
