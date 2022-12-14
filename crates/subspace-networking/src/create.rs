#[cfg(test)]
mod tests;

pub use crate::behavior::custom_record_store::ValueGetter;
use crate::behavior::custom_record_store::{
    CustomRecordStore, MemoryProviderStorage, NoRecordStorage,
};
use crate::behavior::persistent_parameters::NetworkingParametersRegistry;
use crate::behavior::{Behavior, BehaviorConfig};
use crate::node::{CircuitRelayClientError, Node};
use crate::node_runner::{NodeRunner, NodeRunnerConfig};
use crate::request_responses::RequestHandler;
use crate::shared::Shared;
use crate::utils::convert_multiaddresses;
use crate::BootstrappedNetworkingParameters;
use futures::channel::mpsc;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::dns::TokioDnsConfig;
use libp2p::gossipsub::{
    GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::Config as IdentifyConfig;
use libp2p::kad::{KademliaBucketInserts, KademliaCaching, KademliaConfig, KademliaStoreInserts};
use libp2p::metrics::Metrics;
use libp2p::multiaddr::Protocol;
use libp2p::noise::NoiseConfig;
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::tokio::Transport as TokioTcpTransport;
use libp2p::tcp::Config as GenTcpConfig;
use libp2p::websocket::WsConfig;
use libp2p::yamux::YamuxConfig;
use libp2p::{core, identity, noise, Multiaddr, PeerId, Transport, TransportError};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::{fmt, io};
use subspace_core_primitives::{crypto, PIECE_SIZE};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{error, info};

const KADEMLIA_PROTOCOL: &[u8] = b"/subspace/kad/0.1.0";
const GOSSIPSUB_PROTOCOL_PREFIX: &str = "subspace/gossipsub";
// Defines max_negotiating_inbound_streams constant for the swarm.
// It must be set for large plots.
const SWARM_MAX_NEGOTIATING_INBOUND_STREAMS: usize = 100000;
// The default maximum incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 50;
// The default maximum incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 50;
// Defines an expiration interval for item providers in Kademlia network.
const KADEMLIA_PROVIDER_TTL_IN_SECS: Option<Duration> = Some(Duration::from_secs(86400)); /* 1 day */
// Defines a republication interval for item providers in Kademlia network.
const KADEMLIA_PROVIDER_REPUBLICATION_INTERVAL_IN_SECS: Option<Duration> =
    Some(Duration::from_secs(3600)); /* 1 hour */
// Object replication factor. It must consider different peer types with no record stores.
const KADEMLIA_RECORD_REPLICATION_FACTOR: NonZeroUsize =
    NonZeroUsize::new(10).expect("Manually set value should be > 0");
// Defines a replication factor for Kademlia on get_record operation.
// "Good citizen" supports the network health.
const KADEMLIA_CACHING_FACTOR_ON_GET_RECORDS: u16 = 3;
const YAMUX_MAX_STREAMS: usize = 256;

/// Base limit for number of concurrent tasks initiated towards Kademlia.
///
/// Kademlia has 32 substream as a hardcoded constant, we leave 2 for auxiliary internal functions
/// like periodic random walk.
///
/// We restrict this so we don't exceed number of incoming streams for single peer, but this value
/// will be boosted depending on number of connected peers.
const KADEMLIA_BASE_CONCURRENT_TASKS: usize = 30;
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
const KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 1;
/// Base limit for number of any concurrent tasks except Kademlia.
///
/// We configure total number of streams per connection to 256. Here we assume half of them might be
/// incoming and half outgoing, we also leave a small buffer of streams just in case.
///
/// We restrict this so we don't exceed number of streams for single peer, but this value will be
/// boosted depending on number of connected peers.
const REGULAR_BASE_CONCURRENT_TASKS: usize = 120 - KADEMLIA_BASE_CONCURRENT_TASKS;
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
const REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 2;
/// How many peers should node be connected to before boosting turns on.
///
/// 1 means boosting starts with second peer.
const CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD: NonZeroUsize =
    NonZeroUsize::new(5).expect("Not zero; qed");
const SEMAPHORE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

async fn maintain_semaphore_permits_capacity(
    semaphore: &Semaphore,
    interval: Duration,
    connected_peers_count_weak: Weak<AtomicUsize>,
    boost_per_peer: usize,
    boost_peers_threshold: NonZeroUsize,
) {
    let base_permits = semaphore.available_permits();
    // Total permits technically supported by semaphore
    let mut total_permits = base_permits;
    // Some permits might be reserved due to number of peers decreasing and will be released back if
    // necessary, this is because semaphore supports increasing number of
    let mut reserved_permits = Vec::new();
    loop {
        let connected_peers_count = match connected_peers_count_weak.upgrade() {
            Some(connected_peers_count) => connected_peers_count.load(Ordering::Relaxed),
            None => {
                return;
            }
        };
        let expected_total_permits = base_permits
            + connected_peers_count.saturating_sub(boost_peers_threshold.get()) * boost_per_peer;

        // Release reserves to match expected number of permits if necessary
        while total_permits < expected_total_permits && !reserved_permits.is_empty() {
            reserved_permits.pop();
            total_permits += 1;
        }
        // If reserved permits were not sufficient, add permits to the semaphore directly.
        if total_permits < expected_total_permits {
            semaphore.add_permits(expected_total_permits - total_permits);
            total_permits = expected_total_permits;
        }
        // Peers disconnected and expected number of permits went down, we need to put some into
        // reserve
        if total_permits > expected_total_permits {
            let to_reserve = total_permits - expected_total_permits;
            reserved_permits.reserve(to_reserve);
            for _ in 0..to_reserve {
                reserved_permits.push(
                    semaphore
                        .acquire()
                        .await
                        .expect("We never close a semaphore; qed"),
                );
            }
            total_permits = expected_total_permits;
        }

        tokio::time::sleep(interval).await;
    }
}

/// Defines relay configuration for the Node
#[derive(Clone, Debug)]
pub enum RelayMode {
    /// No relay configured.
    NoRelay,
    /// The node enables the relay behaviour.
    Server,
    /// Client relay configuration (enables relay client behavior).
    /// It uses a circuit relay server address as a parameter.
    ///
    /// Example: /memory/\<port>/p2p/\<server_peer_id>/p2p-circuit
    Client(Multiaddr),
}

impl RelayMode {
    /// Defines whether the node has its relay behavior enabled.
    pub fn is_relay_server(&self) -> bool {
        matches!(self, RelayMode::Server)
    }
}

/// [`Node`] configuration.
pub struct Config<RecordStore = CustomRecordStore> {
    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,
    /// List of [`Multiaddr`] on which to listen for incoming connections.
    pub listen_on: Vec<Multiaddr>,
    /// Fallback to random port if specified (or default) port is already occupied.
    pub listen_on_fallback_to_random_port: bool,
    /// Adds a timeout to the setup and protocol upgrade process for all inbound and outbound
    /// connections established through the transport.
    pub timeout: Duration,
    /// The configuration for the Identify behaviour.
    pub identify: IdentifyConfig,
    /// The configuration for the Kademlia behaviour.
    pub kademlia: KademliaConfig,
    /// The configuration for the Gossip behaviour.
    pub gossipsub: GossipsubConfig,
    /// Externally provided implementation of the custom record store for Kademlia DHT,
    pub record_store: RecordStore,
    /// Yamux multiplexing configuration.
    pub yamux_config: YamuxConfig,
    /// Should non-global addresses be added to the DHT?
    pub allow_non_global_addresses_in_dht: bool,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    pub initial_random_query_interval: Duration,
    /// A reference to the `NetworkingParametersRegistry` implementation.
    pub networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    /// The configuration for the `RequestResponsesBehaviour` protocol.
    pub request_response_protocols: Vec<Box<dyn RequestHandler>>,
    /// Defines set of peers with a permanent connection (and reconnection if necessary).
    pub reserved_peers: Vec<Multiaddr>,
    /// Incoming swarm connection limit.
    pub max_established_incoming_connections: u32,
    /// Outgoing swarm connection limit.
    pub max_established_outgoing_connections: u32,
    /// Optional external prometheus metrics. None will disable metrics gathering.
    pub metrics: Option<Metrics>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").finish()
    }
}

impl Config {
    pub fn with_generated_keypair() -> Self {
        Self::with_keypair(identity::ed25519::Keypair::generate())
    }

    pub fn with_keypair(keypair: identity::ed25519::Keypair) -> Self {
        let mut kademlia = KademliaConfig::default();
        kademlia
            .set_protocol_names(vec![KADEMLIA_PROTOCOL.into()])
            .set_max_packet_size(2 * PIECE_SIZE)
            .set_kbucket_inserts(KademliaBucketInserts::Manual)
            .set_replication_factor(KADEMLIA_RECORD_REPLICATION_FACTOR)
            .set_caching(KademliaCaching::Enabled {
                max_peers: KADEMLIA_CACHING_FACTOR_ON_GET_RECORDS,
            })
            // Ignore any puts
            // TODO change back to FilterBoth after https://github.com/libp2p/rust-libp2p/issues/3048
            .set_record_filtering(KademliaStoreInserts::Unfiltered)
            // Providers' settings
            .set_provider_record_ttl(KADEMLIA_PROVIDER_TTL_IN_SECS)
            .set_provider_publication_interval(KADEMLIA_PROVIDER_REPUBLICATION_INTERVAL_IN_SECS)
            // Our records don't expire.
            .set_record_ttl(None)
            .set_replication_interval(None);

        let mut yamux_config = YamuxConfig::default();
        yamux_config.set_max_num_streams(YAMUX_MAX_STREAMS);

        let gossipsub = GossipsubConfigBuilder::default()
            .protocol_id_prefix(GOSSIPSUB_PROTOCOL_PREFIX)
            // TODO: Do we want message signing?
            .validation_mode(ValidationMode::None)
            // To content-address message, we can take the hash of message and use it as an ID.
            .message_id_fn(|message: &GossipsubMessage| {
                MessageId::from(crypto::blake2b_256_hash(&message.data))
            })
            .max_transmit_size(2 * 1024 * 1024) // 2MB
            .build()
            .expect("Default config for gossipsub is always correct; qed");

        let keypair = identity::Keypair::Ed25519(keypair);
        let identify = IdentifyConfig::new("ipfs/0.1.0".to_string(), keypair.public());

        Self {
            keypair,
            listen_on: vec![],
            listen_on_fallback_to_random_port: true,
            timeout: Duration::from_secs(10),
            identify,
            kademlia,
            gossipsub,
            record_store: CustomRecordStore::new(NoRecordStorage, MemoryProviderStorage::default()),
            allow_non_global_addresses_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
            networking_parameters_registry: BootstrappedNetworkingParameters::default().boxed(),
            request_response_protocols: Vec::new(),
            yamux_config,
            reserved_peers: Vec::new(),
            max_established_incoming_connections: SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS,
            max_established_outgoing_connections: SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
            metrics: None,
        }
    }
}

/// Errors that might happen during network creation.
#[derive(Debug, Error)]
pub enum CreationError {
    /// Circuit relay client error.
    #[error("Circuit relay client error: {0}")]
    CircuitRelayClient(#[from] CircuitRelayClientError),
    /// Circuit relay client error.
    #[error("Expected relay server node.")]
    RelayServerExpected,
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Transport error when attempting to listen on multiaddr.
    #[error("Transport error when attempting to listen on multiaddr: {0}")]
    TransportError(#[from] TransportError<io::Error>),
}

/// Converts public key from keypair to PeerId.
/// It serves as the shared PeerId generating algorithm.
pub fn peer_id(keypair: &identity::Keypair) -> PeerId {
    keypair.public().to_peer_id()
}

/// Create a new network node and node runner instances.
pub async fn create<RecordStore>(
    config: Config<RecordStore>,
) -> Result<(Node, NodeRunner<RecordStore>), CreationError>
where
    RecordStore: Send + Sync + for<'a> libp2p::kad::store::RecordStore<'a> + 'static,
{
    let Config {
        keypair,
        listen_on,
        listen_on_fallback_to_random_port,
        timeout,
        identify,
        kademlia,
        gossipsub,
        record_store,
        yamux_config,
        allow_non_global_addresses_in_dht,
        initial_random_query_interval,
        networking_parameters_registry,
        request_response_protocols,
        reserved_peers,
        max_established_incoming_connections,
        max_established_outgoing_connections,
        metrics,
    } = config;
    let local_peer_id = peer_id(&keypair);

    let transport = build_transport(&keypair, timeout, yamux_config)?;

    // libp2p uses blocking API, hence we need to create a blocking task.
    let create_swarm_fut = tokio::task::spawn_blocking(move || {
        let behaviour = Behavior::new(BehaviorConfig {
            peer_id: local_peer_id,
            identify,
            kademlia,
            gossipsub,
            record_store,
            request_response_protocols,
        });

        let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
            .max_negotiating_inbound_streams(SWARM_MAX_NEGOTIATING_INBOUND_STREAMS)
            .build();

        // Setup listen_on addresses
        for mut addr in listen_on {
            if let Err(error) = swarm.listen_on(addr.clone()) {
                if !listen_on_fallback_to_random_port {
                    return Err(error.into());
                }

                let addr_string = addr.to_string();
                // Listen on random port if specified is already occupied
                if let Some(Protocol::Tcp(_port)) = addr.pop() {
                    info!(
                        "Failed to listen on {addr_string} ({error}), falling back to random port"
                    );
                    addr.push(Protocol::Tcp(0));
                    swarm.listen_on(addr)?;
                }
            }
        }

        // Create final structs
        let (command_sender, command_receiver) = mpsc::channel(1);

        let shared = Arc::new(Shared::new(local_peer_id, command_sender));
        let shared_weak = Arc::downgrade(&shared);

        let kademlia_tasks_semaphore = Arc::new(Semaphore::new(KADEMLIA_BASE_CONCURRENT_TASKS));
        let regular_tasks_semaphore = Arc::new(Semaphore::new(REGULAR_BASE_CONCURRENT_TASKS));

        tokio::spawn({
            let kademlia_tasks_semaphore = Arc::clone(&kademlia_tasks_semaphore);
            let connected_peers_count_weak = Arc::downgrade(&shared.connected_peers_count);

            async move {
                maintain_semaphore_permits_capacity(
                    &kademlia_tasks_semaphore,
                    SEMAPHORE_MAINTENANCE_INTERVAL,
                    connected_peers_count_weak,
                    KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER,
                    CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD,
                )
                .await;
            }
        });
        tokio::spawn({
            let regular_tasks_semaphore = Arc::clone(&regular_tasks_semaphore);
            let connected_peers_count_weak = Arc::downgrade(&shared.connected_peers_count);

            async move {
                maintain_semaphore_permits_capacity(
                    &regular_tasks_semaphore,
                    SEMAPHORE_MAINTENANCE_INTERVAL,
                    connected_peers_count_weak,
                    REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER,
                    CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD,
                )
                .await;
            }
        });

        let node = Node::new(shared, kademlia_tasks_semaphore, regular_tasks_semaphore);
        let node_runner = NodeRunner::<RecordStore>::new(NodeRunnerConfig::<RecordStore> {
            allow_non_global_addresses_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval: initial_random_query_interval,
            networking_parameters_registry,
            reserved_peers: convert_multiaddresses(reserved_peers).into_iter().collect(),
            max_established_incoming_connections,
            max_established_outgoing_connections,
            metrics,
        });

        Ok((node, node_runner))
    });

    info!(%allow_non_global_addresses_in_dht, peer_id = %local_peer_id, "DSN instance configured.");

    create_swarm_fut.await.expect(
        "Blocking tasks never panics, if it does it is an implementation bug and everything \
        must crash",
    )
}

// Builds the transport stack that LibP2P will communicate over along with a relay client.
fn build_transport(
    keypair: &identity::Keypair,
    timeout: Duration,
    yamux_config: YamuxConfig,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, CreationError> {
    let transport = {
        let dns_tcp = TokioDnsConfig::system(TokioTcpTransport::new(
            GenTcpConfig::default().nodelay(true),
        ))?;
        let ws = WsConfig::new(TokioDnsConfig::system(TokioTcpTransport::new(
            GenTcpConfig::default().nodelay(true),
        ))?);

        dns_tcp.or_transport(ws)
    };

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");

    Ok(transport
        .upgrade(core::upgrade::Version::V1Lazy)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(yamux_config)
        .timeout(timeout)
        .boxed())
}
