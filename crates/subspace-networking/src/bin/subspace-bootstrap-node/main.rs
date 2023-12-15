//! Simple bootstrap node implementation

#![feature(const_option, type_changing_struct_update)]

use clap::Parser;
use futures::{select, FutureExt};
use libp2p::identity::ed25519::Keypair;
use libp2p::kad::Mode;
use libp2p::{identity, Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::utils::strip_peer_id;
use subspace_networking::{
    peer_id, Config, KademliaMode, KnownPeersManager, KnownPeersManagerConfig,
};
use tracing::{debug, info, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Defines an expiration period for the peer marked for the removal for Kademlia DHT.
const REMOVE_KNOWN_PEERS_GRACE_PERIOD_FOR_KADEMLIA_SECS: Duration = Duration::from_secs(3600);

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(10000).expect("Not zero; qed");

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start bootstrap node
    Start {
        /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
        #[arg(long, alias = "bootstrap-node")]
        bootstrap_nodes: Vec<Multiaddr>,
        /// Keypair for node identity, can be obtained with `generate-keypair` command
        #[clap(long)]
        keypair: String,
        /// Multiaddr to listen on for subspace networking, multiple are supported
        #[arg(long, default_values_t = [
            "/ip4/0.0.0.0/udp/0/quic-v1".parse::<Multiaddr>().expect("Manual setting"),
            "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().expect("Manual setting"),
        ])]
        listen_on: Vec<Multiaddr>,
        /// Multiaddresses of reserved peers to maintain connections to, multiple are supported
        #[arg(long, alias = "reserved-peer")]
        reserved_peers: Vec<Multiaddr>,
        /// Defines max established incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        in_peers: u32,
        /// Defines max established outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        out_peers: u32,
        /// Defines max pending incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_in_peers: u32,
        /// Defines max pending outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_out_peers: u32,
        /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
        #[arg(long, default_value_t = false)]
        enable_private_ips: bool,
        /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
        /// production use.
        #[arg(long)]
        protocol_version: String,
        /// Known external addresses
        #[arg(long, alias = "external-address")]
        external_addresses: Vec<Multiaddr>,
        /// Defines endpoints for the prometheus metrics server. It doesn't start without at least
        /// one specified endpoint. Format: 127.0.0.1:8080
        #[arg(long, alias = "metrics-endpoint")]
        metrics_endpoints: Vec<SocketAddr>,
    },
    /// Generate a new keypair
    GenerateKeypair {
        /// Produce an output in JSON format when enabled.
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
            enable_private_ips,
            protocol_version,
            external_addresses,
            metrics_endpoints,
        } => {
            debug!(
                "Libp2p protocol stack instantiated with version: {} ",
                protocol_version
            );

            let decoded_keypair = Keypair::try_from_bytes(hex::decode(keypair)?.as_mut_slice())?;
            let keypair = identity::Keypair::from(decoded_keypair);

            // Metrics
            let metrics_endpoints_are_specified = !metrics_endpoints.is_empty();
            let mut metrics_registry = Registry::default();
            let dsn_metrics_registry =
                metrics_endpoints_are_specified.then_some(&mut metrics_registry);

            let known_peers_registry_config = KnownPeersManagerConfig {
                enable_known_peers_source: false,
                cache_size: KNOWN_PEERS_CACHE_SIZE,
                ignore_peer_list: strip_peer_id(bootstrap_nodes.clone())
                    .into_iter()
                    .map(|(peer_id, _)| peer_id)
                    .collect::<HashSet<_>>(),
                path: None,
                failed_address_kademlia_removal_interval:
                    REMOVE_KNOWN_PEERS_GRACE_PERIOD_FOR_KADEMLIA_SECS,
                failed_address_cache_removal_interval:
                    REMOVE_KNOWN_PEERS_GRACE_PERIOD_FOR_KADEMLIA_SECS,
            };
            let known_peers_registry = KnownPeersManager::new(known_peers_registry_config)?;

            let config = Config {
                listen_on,
                allow_non_global_addresses_in_dht: enable_private_ips,
                reserved_peers,
                max_established_incoming_connections: in_peers,
                max_established_outgoing_connections: out_peers,
                max_pending_incoming_connections: pending_in_peers,
                max_pending_outgoing_connections: pending_out_peers,
                bootstrap_addresses: bootstrap_nodes,
                kademlia_mode: KademliaMode::Static(Mode::Server),
                external_addresses,
                networking_parameters_registry: known_peers_registry.boxed(),

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

            let prometheus_task = metrics_endpoints_are_specified
                .then(|| {
                    start_prometheus_metrics_server(
                        metrics_endpoints,
                        RegistryAdapter::Libp2p(metrics_registry),
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
