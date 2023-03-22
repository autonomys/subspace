pub(crate) mod temporary_bans;
mod transport;

use crate::behavior::persistent_parameters::{
    BootstrappedNetworkingParameters, NetworkingParametersRegistry,
};
use crate::behavior::provider_storage::MemoryProviderStorage;
use crate::behavior::{provider_storage, Behavior, BehaviorConfig};
use crate::create::temporary_bans::TemporaryBans;
use crate::create::transport::build_transport;
use crate::node::{CircuitRelayClientError, Node};
use crate::node_runner::{NodeRunner, NodeRunnerConfig};
use crate::request_responses::RequestHandler;
use crate::shared::Shared;
use crate::utils::{convert_multiaddresses, ResizableSemaphore};
use backoff::{ExponentialBackoff, SystemClock};
use futures::channel::mpsc;
use libp2p::gossipsub::{
    Config as GossipsubConfig, ConfigBuilder as GossipsubConfigBuilder,
    Message as GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::Config as IdentifyConfig;
use libp2p::kad::record::Key;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{
    store, KademliaBucketInserts, KademliaConfig, KademliaStoreInserts, ProviderRecord, Record,
};
use libp2p::metrics::Metrics;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{ConnectionLimits, SwarmBuilder};
use libp2p::yamux::YamuxConfig;
use libp2p::{identity, Multiaddr, PeerId, TransportError};
use parking_lot::Mutex;
use std::borrow::Cow;
use std::iter::Empty;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, iter};
use subspace_core_primitives::{crypto, PIECE_SIZE};
use thiserror::Error;
use tracing::{debug, error, info};

const KADEMLIA_PROTOCOL: &[u8] = b"/subspace/kad/0.1.0";
const GOSSIPSUB_PROTOCOL_PREFIX: &str = "subspace/gossipsub";
// Defines max_negotiating_inbound_streams constant for the swarm.
// It must be set for large plots.
const SWARM_MAX_NEGOTIATING_INBOUND_STREAMS: usize = 100000;
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 50;
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 50;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_INCOMING_CONNECTIONS: u32 = 50;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 50;
// The default maximum connection number to be maintained for the swarm.
const SWARM_TARGET_CONNECTION_NUMBER: u32 = 50;
// Defines an expiration interval for item providers in Kademlia network.
const KADEMLIA_PROVIDER_TTL_IN_SECS: Option<Duration> = Some(Duration::from_secs(86400)); /* 1 day */
// Defines a republication interval for item providers in Kademlia network.
const KADEMLIA_PROVIDER_REPUBLICATION_INTERVAL_IN_SECS: Option<Duration> =
    Some(Duration::from_secs(3600)); /* 1 hour */
// Defines a replication factor for Kademlia on get_record operation.
// "Good citizen" supports the network health.
const YAMUX_MAX_STREAMS: usize = 256;
const KADEMLIA_QUERY_TIMEOUT: Duration = Duration::from_secs(40);
const SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER: Option<u32> = Some(2);

/// Base limit for number of concurrent tasks initiated towards Kademlia.
///
/// We restrict this so we can manage outgoing requests a bit better by cancelling low-priority
/// requests, but this value will be boosted depending on number of connected peers.
const KADEMLIA_BASE_CONCURRENT_TASKS: NonZeroUsize = NonZeroUsize::new(25).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 5;
/// Base limit for number of any concurrent tasks except Kademlia.
///
/// We configure total number of streams per connection to 256. Here we assume half of them might be
/// incoming and half outgoing, we also leave a small buffer of streams just in case.
///
/// We restrict this so we don't exceed number of streams for single peer, but this value will be
/// boosted depending on number of connected peers.
const REGULAR_BASE_CONCURRENT_TASKS: NonZeroUsize =
    NonZeroUsize::new(80 - KADEMLIA_BASE_CONCURRENT_TASKS.get()).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 10;

const TEMPORARY_BANS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).expect("Not zero; qed");
const TEMPORARY_BANS_DEFAULT_BACKOFF_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
const TEMPORARY_BANS_DEFAULT_BACKOFF_RANDOMIZATION_FACTOR: f64 = 0.1;
const TEMPORARY_BANS_DEFAULT_BACKOFF_MULTIPLIER: f64 = 1.5;
const TEMPORARY_BANS_DEFAULT_MAX_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Record store that can't be created, only
pub(crate) struct ProviderOnlyRecordStore<ProviderStorage> {
    provider_storage: ProviderStorage,
}

impl<ProviderStorage> ProviderOnlyRecordStore<ProviderStorage> {
    fn new(provider_storage: ProviderStorage) -> Self {
        Self { provider_storage }
    }
}

impl<ProviderStorage> RecordStore for ProviderOnlyRecordStore<ProviderStorage>
where
    ProviderStorage: provider_storage::ProviderStorage,
{
    type RecordsIter<'a> = Empty<Cow<'a, Record>> where Self: 'a;
    type ProvidedIter<'a> = ProviderStorage::ProvidedIter<'a> where Self: 'a;

    fn get(&self, _key: &Key) -> Option<Cow<'_, Record>> {
        // Not supported
        None
    }

    fn put(&mut self, _record: Record) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn remove(&mut self, _key: &Key) {
        // Not supported
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        // We don't use Kademlia's periodic replication
        iter::empty()
    }

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        self.provider_storage.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.provider_storage.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.provider_storage.provided()
    }

    fn remove_provider(&mut self, key: &Key, provider: &PeerId) {
        self.provider_storage.remove_provider(key, provider)
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
pub struct Config<ProviderStorage> {
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
    /// Externally provided implementation of the custom provider storage for Kademlia DHT,
    pub provider_storage: ProviderStorage,
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
    /// Established incoming swarm connection limit.
    pub max_established_incoming_connections: u32,
    /// Established outgoing swarm connection limit.
    pub max_established_outgoing_connections: u32,
    /// Pending incoming swarm connection limit.
    pub max_pending_incoming_connections: u32,
    /// Pending outgoing swarm connection limit.
    pub max_pending_outgoing_connections: u32,
    /// Defines target total (in and out) connection number that should be maintained.
    pub target_connections: u32,
    /// How many temporarily banned unreachable peers to keep in memory.
    pub temporary_bans_cache_size: NonZeroUsize,
    /// Backoff policy for temporary banning of unreachable peers.
    pub temporary_ban_backoff: ExponentialBackoff,
    /// Optional external prometheus metrics. None will disable metrics gathering.
    pub metrics: Option<Metrics>,
}

impl<ProviderStorage> fmt::Debug for Config<ProviderStorage> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").finish()
    }
}

impl Default for Config<MemoryProviderStorage> {
    fn default() -> Self {
        let keypair = identity::ed25519::Keypair::generate();
        let peer_id = identity::PublicKey::Ed25519(keypair.public()).to_peer_id();
        Self::with_keypair_and_provider_storage(keypair, MemoryProviderStorage::new(peer_id))
    }
}

impl<ProviderStorage> Config<ProviderStorage>
where
    ProviderStorage: provider_storage::ProviderStorage,
{
    pub fn with_keypair_and_provider_storage(
        keypair: identity::ed25519::Keypair,
        provider_storage: ProviderStorage,
    ) -> Self {
        let mut kademlia = KademliaConfig::default();
        kademlia
            .set_query_timeout(KADEMLIA_QUERY_TIMEOUT)
            .set_protocol_names(vec![KADEMLIA_PROTOCOL.into()])
            .set_max_packet_size(2 * PIECE_SIZE)
            .set_kbucket_inserts(KademliaBucketInserts::Manual)
            .set_record_filtering(KademliaStoreInserts::FilterBoth)
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

        let temporary_ban_backoff = ExponentialBackoff {
            current_interval: TEMPORARY_BANS_DEFAULT_BACKOFF_INITIAL_INTERVAL,
            initial_interval: TEMPORARY_BANS_DEFAULT_BACKOFF_INITIAL_INTERVAL,
            randomization_factor: TEMPORARY_BANS_DEFAULT_BACKOFF_RANDOMIZATION_FACTOR,
            multiplier: TEMPORARY_BANS_DEFAULT_BACKOFF_MULTIPLIER,
            max_interval: TEMPORARY_BANS_DEFAULT_MAX_INTERVAL,
            start_time: Instant::now(),
            max_elapsed_time: None,
            clock: SystemClock::default(),
        };

        Self {
            keypair,
            listen_on: vec![],
            listen_on_fallback_to_random_port: true,
            timeout: Duration::from_secs(10),
            identify,
            kademlia,
            gossipsub,
            provider_storage,
            allow_non_global_addresses_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
            networking_parameters_registry: BootstrappedNetworkingParameters::default().boxed(),
            request_response_protocols: Vec::new(),
            yamux_config,
            reserved_peers: Vec::new(),
            max_established_incoming_connections: SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS,
            max_established_outgoing_connections: SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
            max_pending_incoming_connections: SWARM_MAX_PENDING_INCOMING_CONNECTIONS,
            max_pending_outgoing_connections: SWARM_MAX_PENDING_OUTGOING_CONNECTIONS,
            target_connections: SWARM_TARGET_CONNECTION_NUMBER,
            temporary_bans_cache_size: TEMPORARY_BANS_CACHE_SIZE,
            temporary_ban_backoff,
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
    /// ParityDb storage error
    #[error("ParityDb storage error: {0}")]
    ParityDbStorageError(#[from] parity_db::Error),
}

/// Converts public key from keypair to PeerId.
/// It serves as the shared PeerId generating algorithm.
pub fn peer_id(keypair: &identity::Keypair) -> PeerId {
    keypair.public().to_peer_id()
}

/// Create a new network node and node runner instances.
pub fn create<ProviderStorage>(
    config: Config<ProviderStorage>,
) -> Result<(Node, NodeRunner<ProviderStorage>), CreationError>
where
    ProviderStorage: Send + Sync + provider_storage::ProviderStorage + 'static,
{
    let Config {
        keypair,
        listen_on,
        listen_on_fallback_to_random_port,
        timeout,
        identify,
        kademlia,
        gossipsub,
        provider_storage,
        yamux_config,
        allow_non_global_addresses_in_dht,
        initial_random_query_interval,
        networking_parameters_registry,
        request_response_protocols,
        reserved_peers,
        max_established_incoming_connections,
        max_established_outgoing_connections,
        max_pending_incoming_connections,
        max_pending_outgoing_connections,
        target_connections,
        temporary_bans_cache_size,
        temporary_ban_backoff,
        metrics,
    } = config;
    let local_peer_id = peer_id(&keypair);

    let temporary_bans = Arc::new(Mutex::new(TemporaryBans::new(
        temporary_bans_cache_size,
        temporary_ban_backoff,
    )));
    let transport = build_transport(
        allow_non_global_addresses_in_dht,
        &keypair,
        Arc::clone(&temporary_bans),
        timeout,
        yamux_config,
    )?;

    info!(%allow_non_global_addresses_in_dht, peer_id = %local_peer_id, "DSN instance configured.");

    let behaviour = Behavior::new(BehaviorConfig {
        peer_id: local_peer_id,
        identify,
        kademlia,
        gossipsub,
        record_store: ProviderOnlyRecordStore::new(provider_storage),
        request_response_protocols,
    });

    let connection_limits = ConnectionLimits::default()
        .with_max_established_per_peer(SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER)
        .with_max_pending_incoming(Some(max_pending_incoming_connections))
        .with_max_pending_outgoing(Some(max_pending_outgoing_connections));

    debug!(?connection_limits, "DSN connection limits set.");

    let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
        .max_negotiating_inbound_streams(SWARM_MAX_NEGOTIATING_INBOUND_STREAMS)
        .connection_limits(connection_limits)
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
                info!("Failed to listen on {addr_string} ({error}), falling back to random port");
                addr.push(Protocol::Tcp(0));
                swarm.listen_on(addr)?;
            }
        }
    }

    // Create final structs
    let (command_sender, command_receiver) = mpsc::channel(1);

    let kademlia_tasks_semaphore = ResizableSemaphore::new(KADEMLIA_BASE_CONCURRENT_TASKS);
    let regular_tasks_semaphore = ResizableSemaphore::new(REGULAR_BASE_CONCURRENT_TASKS);

    let shared = Arc::new(Shared::new(
        local_peer_id,
        command_sender,
        kademlia_tasks_semaphore,
        regular_tasks_semaphore,
    ));
    let shared_weak = Arc::downgrade(&shared);

    let node = Node::new(shared);
    let node_runner = NodeRunner::<ProviderStorage>::new(NodeRunnerConfig::<ProviderStorage> {
        allow_non_global_addresses_in_dht,
        command_receiver,
        swarm,
        shared_weak,
        next_random_query_interval: initial_random_query_interval,
        networking_parameters_registry,
        reserved_peers: convert_multiaddresses(reserved_peers).into_iter().collect(),
        max_established_incoming_connections,
        max_established_outgoing_connections,
        target_connections,
        temporary_bans,
        metrics,
    });

    Ok((node, node_runner))
}
