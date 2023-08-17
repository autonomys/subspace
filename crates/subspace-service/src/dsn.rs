use sc_client_api::AuxStore;
use sc_consensus_subspace::archiver::SegmentHeadersStore;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{SegmentHeader, SegmentIndex};
use subspace_networking::libp2p::kad::Mode as KademliaMode;
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::utils::strip_peer_id;
use subspace_networking::{
    CreationError, NetworkParametersPersistenceError, NetworkingParametersManager, Node,
    NodeRunner, PeerInfoProvider, SegmentHeaderBySegmentIndexesRequestHandler,
    SegmentHeaderRequest, SegmentHeaderResponse,
};
use thiserror::Error;
use tracing::{debug, error, trace};

const SEGMENT_HEADERS_NUMBER_LIMIT: u64 = 1000;

/// Errors that might happen during DSN configuration.
#[derive(Debug, Error)]
pub enum DsnConfigurationError {
    /// Can't instantiate the DSN.
    #[error("Can't instantiate the DSN: {0}")]
    CreationError(#[from] CreationError),
    /// Network parameter manager error.
    #[error("Network parameter manager error: {0}")]
    NetworkParameterManagerError(#[from] NetworkParametersPersistenceError),
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
    pub base_path: Option<PathBuf>,

    /// Defines max established incoming swarm connection limit.
    pub max_in_connections: u32,

    /// Defines max established outgoing swarm connection limit.
    pub max_out_connections: u32,

    /// Defines max pending incoming swarm connection limit.
    pub max_pending_in_connections: u32,

    /// Defines max pending outgoing swarm connection limit.
    pub max_pending_out_connections: u32,

    /// Defines target total (in and out) connection number for DSN that should be maintained.
    pub target_connections: u32,

    /// Known external addresses
    pub external_addresses: Vec<Multiaddr>,
}

pub(crate) fn create_dsn_instance<AS>(
    dsn_protocol_version: String,
    dsn_config: DsnConfig,
    segment_headers_store: SegmentHeadersStore<AS>,
) -> Result<(Node, NodeRunner<()>), DsnConfigurationError>
where
    AS: AuxStore + Sync + Send + 'static,
{
    trace!("Subspace networking starting.");

    let networking_parameters_registry = dsn_config
        .base_path
        .map(|path| {
            // TODO: Remove this in the future after enough upgrade time that this no longer exist
            if path.join("known_addresses_db").is_dir() {
                let _ = fs::remove_file(path.join("known_addresses_db"));
            }
            let file_path = path.join("known_addresses.bin");

            NetworkingParametersManager::new(
                &file_path,
                strip_peer_id(dsn_config.bootstrap_nodes.clone())
                    .into_iter()
                    .map(|(peer_id, _)| peer_id)
                    .collect::<HashSet<_>>(),
            )
            .map(NetworkingParametersManager::boxed)
        })
        .transpose()?;

    let keypair = dsn_config.keypair.clone();
    let default_networking_config = subspace_networking::Config::new(
        dsn_protocol_version,
        keypair,
        (),
        Some(PeerInfoProvider::new_node()),
    );

    let networking_config = subspace_networking::Config {
        keypair: dsn_config.keypair.clone(),
        listen_on: dsn_config.listen_on,
        allow_non_global_addresses_in_dht: dsn_config.allow_non_global_addresses_in_dht,
        networking_parameters_registry,
        request_response_protocols: vec![SegmentHeaderBySegmentIndexesRequestHandler::create(
            move |_, req| {
                let segment_indexes = match req {
                    SegmentHeaderRequest::SegmentIndexes { segment_indexes } => {
                        segment_indexes.clone()
                    }
                    SegmentHeaderRequest::LastSegmentHeaders {
                        segment_header_number,
                    } => {
                        let mut segment_headers_limit = *segment_header_number;
                        if *segment_header_number > SEGMENT_HEADERS_NUMBER_LIMIT {
                            debug!(
                                %segment_header_number,
                                "Segment header number exceeded the limit."
                            );

                            segment_headers_limit = SEGMENT_HEADERS_NUMBER_LIMIT;
                        }

                        match segment_headers_store.max_segment_index() {
                            Some(max_segment_index) => {
                                // Several last segment indexes
                                (SegmentIndex::ZERO..=max_segment_index)
                                    .rev()
                                    .take(segment_headers_limit as usize)
                                    .collect::<Vec<_>>()
                            }
                            None => {
                                // Nothing yet
                                Vec::new()
                            }
                        }
                    }
                };

                let maybe_segment_headers = segment_indexes
                    .iter()
                    .map(|segment_index| segment_headers_store.get_segment_header(*segment_index))
                    .collect::<Option<Vec<SegmentHeader>>>();

                let result = match maybe_segment_headers {
                    Some(segment_headers) => Some(SegmentHeaderResponse { segment_headers }),
                    None => {
                        error!("Segment header collection contained empty segment headers.");

                        None
                    }
                };

                async move { result }
            },
        )],
        max_established_incoming_connections: dsn_config.max_in_connections,
        max_established_outgoing_connections: dsn_config.max_out_connections,
        max_pending_incoming_connections: dsn_config.max_pending_in_connections,
        max_pending_outgoing_connections: dsn_config.max_pending_out_connections,
        general_target_connections: dsn_config.target_connections,
        special_target_connections: 0,
        reserved_peers: dsn_config.reserved_peers,
        // maintain permanent connections with any peer
        general_connected_peers_handler: Some(Arc::new(|_| true)),
        bootstrap_addresses: dsn_config.bootstrap_nodes,
        external_addresses: dsn_config.external_addresses,
        kademlia_mode: Some(KademliaMode::Client),

        ..default_networking_config
    };

    subspace_networking::create(networking_config).map_err(Into::into)
}
