use prometheus_client::registry::Registry;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use subspace_networking::libp2p::kad::Mode;
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::protocols::request_response::handlers::cached_piece_by_index::CachedPieceByIndexRequestHandler;
use subspace_networking::protocols::request_response::handlers::piece_by_index::PieceByIndexRequestHandler;
use subspace_networking::protocols::request_response::handlers::segment_header::SegmentHeaderBySegmentIndexesRequestHandler;
use subspace_networking::utils::strip_peer_id;
use subspace_networking::{
    CreationError, KademliaMode, KnownPeersManager, KnownPeersManagerConfig,
    KnownPeersManagerPersistenceError, Node, NodeRunner,
};
use thiserror::Error;
use tracing::{error, trace};

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: u32 = 100;

/// Errors that might happen during DSN configuration.
#[derive(Debug, Error)]
pub enum DsnConfigurationError {
    /// Can't instantiate the DSN.
    #[error("Can't instantiate the DSN: {0}")]
    CreationError(#[from] CreationError),
    /// Network parameter manager error.
    #[error("Network parameter manager error: {0}")]
    NetworkParameterManagerError(#[from] KnownPeersManagerPersistenceError),
}

/// DSN configuration parameters.
#[derive(Clone, Debug)]
pub struct DsnConfig {
    /// Where local DSN node will listen for incoming connections.
    pub listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    pub bootstrap_nodes: Vec<Multiaddr>,

    /// Reserved nodes for DSN.
    pub reserved_peers: Vec<Multiaddr>,

    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,

    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
    pub allow_non_global_addresses_in_dht: bool,

    /// System base path.
    pub network_path: PathBuf,

    /// Defines max established incoming swarm connection limit.
    pub max_in_connections: u32,

    /// Defines max established outgoing swarm connection limit.
    pub max_out_connections: u32,

    /// Defines max pending incoming swarm connection limit.
    pub max_pending_in_connections: u32,

    /// Defines max pending outgoing swarm connection limit.
    pub max_pending_out_connections: u32,

    /// Known external addresses
    pub external_addresses: Vec<Multiaddr>,
}

pub(crate) fn create_dsn_instance(
    dsn_protocol_version: String,
    dsn_config: DsnConfig,
    prometheus_registry: Option<&mut Registry>,
) -> Result<(Node, NodeRunner<()>), DsnConfigurationError> {
    trace!("Subspace networking starting.");

    let known_peers_registry = {
        let network_path = dsn_config.network_path;

        if !network_path.is_dir() {
            fs::create_dir(&network_path)
                .map_err(|error| DsnConfigurationError::CreationError(CreationError::Io(error)))?;
        }
        let file_path = network_path.join("known_addresses.bin");

        KnownPeersManager::new(KnownPeersManagerConfig {
            path: Some(file_path.into_boxed_path()),
            ignore_peer_list: strip_peer_id(dsn_config.bootstrap_nodes.clone())
                .into_iter()
                .map(|(peer_id, _)| peer_id)
                .collect::<HashSet<_>>(),
            cache_size: KNOWN_PEERS_CACHE_SIZE,
            ..Default::default()
        })
        .map(KnownPeersManager::boxed)?
    };

    let keypair = dsn_config.keypair.clone();
    let default_networking_config =
        subspace_networking::Config::new(dsn_protocol_version, keypair, (), prometheus_registry);

    let networking_config = subspace_networking::Config {
        keypair: dsn_config.keypair.clone(),
        listen_on: dsn_config.listen_on,
        allow_non_global_addresses_in_dht: dsn_config.allow_non_global_addresses_in_dht,
        known_peers_registry,
        request_response_protocols: vec![
            // We need to enable protocol to request pieces
            CachedPieceByIndexRequestHandler::create(|_, _| async { None }),
            // We need to enable protocol to request pieces
            PieceByIndexRequestHandler::create(|_, _| async { None }),
            SegmentHeaderBySegmentIndexesRequestHandler::create(move |_, _| async move { None }),
        ],
        max_established_incoming_connections: dsn_config.max_in_connections,
        max_established_outgoing_connections: dsn_config.max_out_connections,
        max_pending_incoming_connections: dsn_config.max_pending_in_connections,
        max_pending_outgoing_connections: dsn_config.max_pending_out_connections,
        reserved_peers: dsn_config.reserved_peers,
        bootstrap_addresses: dsn_config.bootstrap_nodes,
        external_addresses: dsn_config.external_addresses,
        kademlia_mode: KademliaMode::Static(Mode::Client),

        ..default_networking_config
    };

    subspace_networking::construct(networking_config).map_err(Into::into)
}
