//! Simple bootstrap node implementation

#![feature(type_changing_struct_update)]

use clap::{Parser, ValueHint};
use either::Either;
use libp2p::identity::ed25519::Keypair;
use libp2p::Multiaddr;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{
    peer_id, BootstrappedNetworkingParameters, Config, CustomRecordStore, MemoryProviderStorage,
    NoRecordStorage, ParityDbProviderStorage,
};
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
        /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
        #[arg(long, default_value_t = false)]
        disable_private_ips: bool,
        /// Defines path for the provider record storage DB (optional).
        /// No value will enable memory storage instead.
        #[arg(long, value_hint = ValueHint::FilePath)]
        db_path: Option<PathBuf>,
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
            disable_private_ips,
            db_path,
        } => {
            let keypair = Keypair::decode(hex::decode(keypair)?.as_mut_slice())?;
            let local_peer_id = peer_id(&libp2p::identity::Keypair::Ed25519(keypair.clone()));

            let provider_storage = if let Some(path) = db_path {
                let db_path = path.join("subspace_storage_providers_db").into_boxed_path();

                Either::Left(
                    ParityDbProviderStorage::new(&db_path, local_peer_id)
                        .expect("Provider storage DB path should be valid."),
                )
            } else {
                Either::Right(MemoryProviderStorage::new(local_peer_id))
            };

            let config = Config {
                networking_parameters_registry: BootstrappedNetworkingParameters::new(
                    bootstrap_nodes,
                )
                .boxed(),
                listen_on,
                allow_non_global_addresses_in_dht: !disable_private_ips,
                reserved_peers,
                max_established_incoming_connections: in_peers
                    .unwrap_or(MAX_ESTABLISHED_INCOMING_CONNECTIONS),
                max_established_outgoing_connections: out_peers
                    .unwrap_or(MAX_ESTABLISHED_OUTGOING_CONNECTIONS),
                record_store: CustomRecordStore::new(NoRecordStorage, provider_storage),
                ..Config::with_keypair(keypair)
            };
            let (node, mut node_runner) = subspace_networking::create(config)
                .await
                .expect("Networking stack creation failed.");

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
