//! Simple bootstrap node implementation

use clap::Parser;
use libp2p::identity::ed25519::Keypair;
use libp2p::Multiaddr;
use std::sync::Arc;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{BootstrappedNetworkingParameters, Config};
use tracing::info;

// The default maximum incoming connections number for the peer.
const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 300;
// The default maximum outgoing connections number for the peer.
const MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 300;

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start bootstrap node
    Start {
        /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
        #[arg(long, alias = "bootstrap-node")]
        bootstrap_nodes: Vec<Multiaddr>,
        /// Keypair for node identity, can be obtained with `generate-keypair` command
        keypair: String,
        /// Multiaddr to listen on for subspace networking, multiple are supported
        #[clap(default_value = "/ip4/0.0.0.0/tcp/0")]
        listen_on: Vec<Multiaddr>,
        /// Multiaddresses of reserved peers to maintain connections to, multiple are supported
        #[arg(long, alias = "reserved-peer")]
        reserved_peers: Vec<Multiaddr>,
        /// Defines max incoming connections limit for the peer.
        #[arg(long)]
        in_peers: Option<u32>,
        /// Defines max outgoing connections limit for the peer.
        #[arg(long)]
        out_peers: Option<u32>,
    },
    /// Generate a new keypair
    GenerateKeypair,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Subspace Bootstrap Node started",);

    let command: Command = Command::parse();

    match command {
        Command::Start {
            bootstrap_nodes,
            keypair,
            listen_on,
            reserved_peers,
            in_peers,
            out_peers,
        } => {
            let config = Config {
                networking_parameters_registry: BootstrappedNetworkingParameters::new(
                    bootstrap_nodes,
                )
                .boxed(),
                listen_on,
                allow_non_globals_in_dht: true,
                reserved_peers,
                max_established_incoming_connections: in_peers
                    .unwrap_or(MAX_ESTABLISHED_INCOMING_CONNECTIONS),
                max_established_outgoing_connections: out_peers
                    .unwrap_or(MAX_ESTABLISHED_OUTGOING_CONNECTIONS),
                ..Config::with_keypair(Keypair::decode(hex::decode(keypair)?.as_mut_slice())?)
            };
            let (node, mut node_runner) = subspace_networking::create(config).await.unwrap();

            node.on_new_listener(Arc::new({
                let node_id = node.id();

                move |multiaddr| {
                    info!(
                        "Listening on {}",
                        multiaddr.clone().with(Protocol::P2p(node_id.into()))
                    );
                }
            }))
            .detach();

            node_runner.run().await
        }
        Command::GenerateKeypair => {
            println!("{}", hex::encode(Keypair::generate().encode()))
        }
    }

    Ok(())
}
