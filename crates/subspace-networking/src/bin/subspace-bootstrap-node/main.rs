//! Simple bootstrap node implementation

#![feature(type_changing_struct_update)]

use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use either::Either;
use libp2p::identity::ed25519::Keypair;
use libp2p::Multiaddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{
    peer_id, BootstrappedNetworkingParameters, Config, MemoryProviderStorage,
    NetworkingParametersManager, ParityDbProviderStorage,
};
use tracing::info;

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
        /// No value will enable memory storage instead.
        #[arg(long, value_hint = ValueHint::FilePath)]
        db_path: Option<PathBuf>,
        /// Piece providers cache size in human readable format (e.g. 10GB, 2TiB) or just bytes (e.g. 4096).
        #[arg(long, default_value = "100MiB")]
        piece_providers_cache_size: ByteSize,
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
            pending_in_peers,
            pending_out_peers,
            disable_private_ips,
            db_path,
            piece_providers_cache_size,
        } => {
            const APPROX_PROVIDER_RECORD_SIZE: u64 = 1000; // ~ 1KB
            let recs = piece_providers_cache_size.as_u64() / APPROX_PROVIDER_RECORD_SIZE;
            let converted_cache_size =
                NonZeroUsize::new(recs as usize).ok_or_else(|| anyhow!("Incorrect cache size."))?;

            let keypair = Keypair::decode(hex::decode(keypair)?.as_mut_slice())?;
            let local_peer_id = peer_id(&libp2p::identity::Keypair::Ed25519(keypair.clone()));

            let provider_storage = if let Some(path) = &db_path {
                let db_path = path.join("subspace_storage_providers_db");

                Either::Left(ParityDbProviderStorage::new(
                    &db_path,
                    converted_cache_size,
                    local_peer_id,
                )?)
            } else {
                Either::Right(MemoryProviderStorage::new(local_peer_id))
            };

            let networking_parameters_registry = {
                db_path
                    .map(|path| {
                        let known_addresses_db = path.join("known_addresses_db");

                        NetworkingParametersManager::new(
                            &known_addresses_db,
                            bootstrap_nodes.clone(),
                        )
                        .map(|manager| manager.boxed())
                    })
                    .unwrap_or(Ok(
                        BootstrappedNetworkingParameters::new(bootstrap_nodes).boxed()
                    ))
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
                ..Config::with_keypair_and_provider_storage(keypair, provider_storage)
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

            node_runner.run().await
        }
        Command::GenerateKeypair => {
            println!("{}", hex::encode(Keypair::generate().encode()))
        }
    }

    Ok(())
}
