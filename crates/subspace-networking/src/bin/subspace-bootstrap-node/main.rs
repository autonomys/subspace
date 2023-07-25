//! Simple bootstrap node implementation

#![feature(type_changing_struct_update)]

use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use either::Either;
use futures::future::pending;
use futures::FutureExt;
use libp2p::identity::ed25519::Keypair;
use libp2p::{identity, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{
    peer_id, Config, NetworkingParametersManager, ParityDbProviderStorage, PeerInfoProvider,
    StubNetworkingParametersManager, VoidProviderStorage,
};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
        disable_private_ips: bool,
        /// Defines path for the provider record storage DB (optional).
        #[arg(long, value_hint = ValueHint::FilePath)]
        db_path: Option<PathBuf>,
        /// Piece providers cache size in human readable format (e.g. 10GB, 2TiB) or just bytes (e.g. 4096).
        #[arg(long, default_value = "100MiB")]
        piece_providers_cache_size: ByteSize,
        /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
        /// production use.
        #[arg(long)]
        protocol_version: String,
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
async fn main() -> anyhow::Result<()> {
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
            disable_private_ips,
            db_path,
            piece_providers_cache_size,
            protocol_version,
        } => {
            debug!(
                "Libp2p protocol stack instantiated with version: {} ",
                protocol_version
            );

            const APPROX_PROVIDER_RECORD_SIZE: u64 = 1000; // ~ 1KB
            let recs = piece_providers_cache_size.as_u64() / APPROX_PROVIDER_RECORD_SIZE;
            let converted_cache_size =
                NonZeroUsize::new(recs as usize).ok_or_else(|| anyhow!("Incorrect cache size."))?;

            let decoded_keypair = Keypair::try_from_bytes(hex::decode(keypair)?.as_mut_slice())?;
            let local_peer_id = peer_id_from_keypair(decoded_keypair.clone());
            let keypair = identity::Keypair::from(decoded_keypair);

            let provider_storage = if let Some(path) = &db_path {
                let db_path = path.join("subspace_storage_providers_db");

                Either::Left(ParityDbProviderStorage::new(
                    &db_path,
                    converted_cache_size,
                    local_peer_id,
                )?)
            } else {
                Either::Right(VoidProviderStorage)
            };

            let networking_parameters_registry = {
                db_path
                    .map(|path| {
                        let known_addresses_db = path.join("known_addresses_db");

                        NetworkingParametersManager::new(&known_addresses_db)
                            .map(|manager| manager.boxed())
                    })
                    .unwrap_or(Ok(StubNetworkingParametersManager.boxed()))
                    .map_err(|err| anyhow!(err))?
            };

            let config = Config {
                networking_parameters_registry,
                listen_on,
                allow_non_global_addresses_in_dht: !disable_private_ips,
                reserved_peers,
                max_established_incoming_connections: in_peers,
                max_established_outgoing_connections: out_peers,
                max_pending_incoming_connections: pending_in_peers,
                max_pending_outgoing_connections: pending_out_peers,
                // we don't maintain permanent connections with any peer
                general_connected_peers_handler: Arc::new(|_| false),
                special_connected_peers_handler: Arc::new(|_| false),
                bootstrap_addresses: bootstrap_nodes,

                ..Config::new(
                    protocol_version.to_string(),
                    keypair,
                    provider_storage,
                    PeerInfoProvider::new_bootstrap_node(),
                )
            };
            let (node, mut node_runner) =
                subspace_networking::create(config).expect("Networking stack creation failed.");

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

            info!("Subspace Bootstrap Node started");
            let bootstrap_fut = Box::pin({
                let node = node.clone();

                async move {
                    if let Err(err) = node.bootstrap().await {
                        warn!(?err, "DSN bootstrap failed.");
                    }

                    pending::<()>().await;
                }
            });

            futures::select!(
                // Network bootstrapping future
                _ = bootstrap_fut.fuse() => {},

                // Networking runner
                _ = node_runner.run().fuse() => {},
            );
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
