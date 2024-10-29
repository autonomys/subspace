//! Simple bootstrap node implementation

#![feature(type_changing_struct_update)]

use clap::Parser;
use futures::{select, FutureExt};
use libp2p::identity::ed25519::Keypair;
use libp2p::kad::Mode;
use libp2p::{identity, Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic;
use std::process::exit;
use std::sync::Arc;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{peer_id, Config, KademliaMode};
use tracing::{debug, info, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: u32 = 10000;

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start bootstrap node
    Start {
        /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
        #[arg(long = "bootstrap-node")]
        bootstrap_nodes: Vec<Multiaddr>,
        /// Keypair for node identity, can be obtained with `generate-keypair` command
        #[clap(long)]
        keypair: String,
        /// Multiaddr to listen on for subspace networking, multiple are supported
        #[arg(long, default_values_t = [
            Multiaddr::from(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .with(Protocol::Tcp(0)),
            Multiaddr::from(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                .with(Protocol::Tcp(0))
        ])]
        listen_on: Vec<Multiaddr>,
        /// Multiaddresses of reserved peers to maintain connections to, multiple are supported
        #[arg(long = "reserved-peer")]
        reserved_peers: Vec<Multiaddr>,
        /// Maximum established incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        in_peers: u32,
        /// Maximum established outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        out_peers: u32,
        /// Maximum pending incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_in_peers: u32,
        /// Maximum pending outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_out_peers: u32,
        /// Enable non-global (private, shared, loopback..) addresses in the Kademlia DHT.
        /// By default these addresses are excluded from the DHT.
        #[arg(long, default_value_t = false)]
        allow_private_ips: bool,
        /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
        /// production use.
        #[arg(long)]
        protocol_version: String,
        /// Known external addresses
        #[arg(long = "external-address")]
        external_addresses: Vec<Multiaddr>,
        /// Endpoints for the prometheus metrics server. It doesn't start without at least one
        /// specified endpoint. Format: 127.0.0.1:8080
        #[arg(long, aliases = ["metrics-endpoint", "metrics-endpoints"])]
        prometheus_listen_on: Vec<SocketAddr>,
    },
    /// Generate a new keypair
    GenerateKeypair {
        /// Produce output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

/// Helper struct for the `GenerateKeypair` command output.
#[derive(Debug, Serialize, Deserialize)]
struct KeypairOutput {
    keypair: String,
    peer_id: String,
}

impl Display for KeypairOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PeerId: {}", self.peer_id)?;
        writeln!(f, "Keypair: {}", self.keypair)
    }
}

impl KeypairOutput {
    fn new(keypair: Keypair) -> Self {
        Self {
            keypair: hex::encode(keypair.to_bytes()),
            peer_id: peer_id_from_keypair(keypair).to_base58(),
        }
    }
}

/// Install a panic handler which exits on panics, rather than unwinding. Unwinding can hang the
/// tokio runtime waiting for stuck tasks or threads.
fn set_exit_on_panic() {
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));
}

fn init_logging() {
    // set default log to info if the RUST_LOG is not set.
    let env_filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    let builder = Subscriber::builder().with_env_filter(env_filter).finish();

    builder.init()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    set_exit_on_panic();
    init_logging();

    let command: Command = Command::parse();

    match command {
        Command::Start {
            bootstrap_nodes,
            keypair,
            listen_on,
            reserved_peers,
            in_peers,
            out_peers,
            pending_in_peers,
            pending_out_peers,
            allow_private_ips,
            protocol_version,
            external_addresses,
            prometheus_listen_on,
        } => {
            debug!(
                "Libp2p protocol stack instantiated with version: {} ",
                protocol_version
            );

            let decoded_keypair = Keypair::try_from_bytes(hex::decode(keypair)?.as_mut_slice())?;
            let keypair = identity::Keypair::from(decoded_keypair);

            // Metrics
            let should_start_prometheus_server = !prometheus_listen_on.is_empty();
            let mut metrics_registry = Registry::default();
            let dsn_metrics_registry =
                should_start_prometheus_server.then_some(&mut metrics_registry);

            let config = Config {
                listen_on,
                allow_non_global_addresses_in_dht: allow_private_ips,
                reserved_peers,
                max_established_incoming_connections: in_peers,
                max_established_outgoing_connections: out_peers,
                max_pending_incoming_connections: pending_in_peers,
                max_pending_outgoing_connections: pending_out_peers,
                bootstrap_addresses: bootstrap_nodes,
                kademlia_mode: KademliaMode::Static(Mode::Server),
                external_addresses,

                ..Config::new(
                    protocol_version.to_string(),
                    keypair,
                    (),
                    dsn_metrics_registry,
                )
            };
            let (node, mut node_runner) =
                subspace_networking::construct(config).expect("Networking stack creation failed.");

            node.on_new_listener(Arc::new({
                let node_id = node.id();

                move |multiaddr| {
                    info!(
                        "Listening on {}",
                        multiaddr.clone().with(Protocol::P2p(node_id))
                    );
                }
            }))
            .detach();

            info!("Subspace Bootstrap Node started");

            let prometheus_task = should_start_prometheus_server
                .then(|| {
                    start_prometheus_metrics_server(
                        prometheus_listen_on,
                        RegistryAdapter::PrometheusClient(metrics_registry),
                    )
                })
                .transpose()?;
            if let Some(prometheus_task) = prometheus_task {
                select! {
                   _ = node_runner.run().fuse() => {},
                   _ = prometheus_task.fuse() => {},
                }
            } else {
                node_runner.run().await
            }
        }
        Command::GenerateKeypair { json } => {
            let output = KeypairOutput::new(Keypair::generate());

            if json {
                let json_output = serde_json::to_string(&output)?;

                println!("{json_output}")
            } else {
                println!("{output}")
            }
        }
    }

    Ok(())
}

fn peer_id_from_keypair(keypair: Keypair) -> PeerId {
    peer_id(&libp2p::identity::Keypair::from(keypair))
}
