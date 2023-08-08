pub(crate) mod temporary_bans;
mod transport;

use crate::behavior::persistent_parameters::{
    NetworkingParametersRegistry, StubNetworkingParametersManager,
};
use crate::behavior::{Behavior, BehaviorConfig};
use crate::connected_peers::Config as ConnectedPeersConfig;
use crate::create::temporary_bans::TemporaryBans;
use crate::create::transport::build_transport;
use crate::node::Node;
use crate::node_runner::{NodeRunner, NodeRunnerConfig};
use crate::peer_info::PeerInfoProvider;
use crate::request_responses::RequestHandler;
use crate::reserved_peers::Config as ReservedPeersConfig;
use crate::shared::Shared;
use crate::utils::{strip_peer_id, ResizableSemaphore};
use crate::{PeerInfo, PeerInfoConfig};
use backoff::{ExponentialBackoff, SystemClock};
use futures::channel::mpsc;
use libp2p::connection_limits::ConnectionLimits;
use libp2p::gossipsub::{
    Config as GossipsubConfig, ConfigBuilder as GossipsubConfigBuilder,
    Message as GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::Config as IdentifyConfig;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{
    store, KademliaBucketInserts, KademliaConfig, KademliaStoreInserts, ProviderRecord, Record,
};
use libp2p::metrics::Metrics;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmBuilder;
use libp2p::yamux::Config as YamuxConfig;
use libp2p::{identity, Multiaddr, PeerId, StreamProtocol, TransportError};
use libp2p_kad::{Mode, RecordKey};
use parking_lot::Mutex;
use std::borrow::Cow;
use std::iter::Empty;
use std::num::NonZeroUsize;
use std::string::ToString;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, iter};
use subspace_core_primitives::{crypto, Piece};
use thiserror::Error;
use tracing::{debug, error, info};

/// Defines whether connection should be maintained permanently.
pub type ConnectedPeersHandler = Arc<dyn Fn(&PeerInfo) -> bool + Send + Sync + 'static>;

const DEFAULT_NETWORK_PROTOCOL_VERSION: &str = "dev";
const KADEMLIA_PROTOCOL: &str = "/subspace/kad/0.1.0";
const GOSSIPSUB_PROTOCOL_PREFIX: &str = "subspace/gossipsub";
const RESERVED_PEERS_PROTOCOL_NAME: &str = "/subspace/reserved-peers/1.0.0";
const PEER_INFO_PROTOCOL_NAME: &str = "/subspace/peer-info/1.0.0";
const GENERAL_CONNECTED_PEERS_PROTOCOL_LOG_TARGET: &str = "general-connected-peers";
const SPECIAL_CONNECTED_PEERS_PROTOCOL_LOG_TARGET: &str = "special-connected-peers";

// Defines max_negotiating_inbound_streams constant for the swarm.
// It must be set for large plots.
const SWARM_MAX_NEGOTIATING_INBOUND_STREAMS: usize = 100000;
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 80;
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 80;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_INCOMING_CONNECTIONS: u32 = 80;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 80;
// The default maximum connection number to be maintained for the swarm.
const SWARM_TARGET_CONNECTION_NUMBER: u32 = 30;
// Defines a replication factor for Kademlia on get_record operation.
// "Good citizen" supports the network health.
const YAMUX_MAX_STREAMS: usize = 256;
const KADEMLIA_QUERY_TIMEOUT: Duration = Duration::from_secs(40);
const SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER: Option<u32> = Some(2);
// TODO: Consider moving this constant to configuration or removing `Toggle` wrapper when we find a
// use-case for gossipsub protocol.
const ENABLE_GOSSIP_PROTOCOL: bool = false;

/// Base limit for number of concurrent tasks initiated towards Kademlia.
///
/// We restrict this so we can manage outgoing requests a bit better by cancelling low-priority
/// requests, but this value will be boosted depending on number of connected peers.
const KADEMLIA_BASE_CONCURRENT_TASKS: NonZeroUsize = NonZeroUsize::new(15).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 15;
/// Base limit for number of any concurrent tasks except Kademlia.
///
/// We configure total number of streams per connection to 256. Here we assume half of them might be
/// incoming and half outgoing, we also leave a small buffer of streams just in case.
///
/// We restrict this so we don't exceed number of streams for single peer, but this value will be
/// boosted depending on number of connected peers.
const REGULAR_BASE_CONCURRENT_TASKS: NonZeroUsize =
    NonZeroUsize::new(50 - KADEMLIA_BASE_CONCURRENT_TASKS.get()).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 25;

const TEMPORARY_BANS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(10_000).expect("Not zero; qed");
const TEMPORARY_BANS_DEFAULT_BACKOFF_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
const TEMPORARY_BANS_DEFAULT_BACKOFF_RANDOMIZATION_FACTOR: f64 = 0.1;
const TEMPORARY_BANS_DEFAULT_BACKOFF_MULTIPLIER: f64 = 1.5;
const TEMPORARY_BANS_DEFAULT_MAX_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Trait to be implemented on providers of local records
pub trait LocalRecordProvider {
    /// Gets a provider record for key that is stored locally
    fn record(&self, key: &RecordKey) -> Option<ProviderRecord>;
}

impl LocalRecordProvider for () {
    fn record(&self, _key: &RecordKey) -> Option<ProviderRecord> {
        None
    }
}

/// Record store that can't be created, only
pub(crate) struct LocalOnlyRecordStore<LocalRecordProvider> {
    local_records_provider: LocalRecordProvider,
}

impl<LocalRecordProvider> LocalOnlyRecordStore<LocalRecordProvider> {
    fn new(local_records_provider: LocalRecordProvider) -> Self {
        Self {
            local_records_provider,
        }
    }
}

impl<LocalRecordProvider> RecordStore for LocalOnlyRecordStore<LocalRecordProvider>
where
    LocalRecordProvider: self::LocalRecordProvider,
{
    type RecordsIter<'a> = Empty<Cow<'a, Record>> where Self: 'a;
    type ProvidedIter<'a> =  Empty<Cow<'a, ProviderRecord>> where Self: 'a;

    fn get(&self, _key: &RecordKey) -> Option<Cow<'_, Record>> {
        // Not supported
        None
    }

    fn put(&mut self, _record: Record) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn remove(&mut self, _key: &RecordKey) {
        // Not supported
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        // We don't use Kademlia's periodic replication
        iter::empty()
    }

    fn add_provider(&mut self, _record: ProviderRecord) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.local_records_provider
            .record(key)
            .into_iter()
            .collect()
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // We don't use Kademlia's periodic replication
        iter::empty()
    }

    fn remove_provider(&mut self, _key: &RecordKey, _provider: &PeerId) {
        // Not supported
    }
}

/// [`Node`] configuration.
pub struct Config<LocalRecordProvider> {
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
    pub gossipsub: Option<GossipsubConfig>,
    /// Externally provided implementation of the local records provider
    pub local_records_provider: LocalRecordProvider,
    /// Yamux multiplexing configuration.
    pub yamux_config: YamuxConfig,
    /// Should non-global addresses be added to the DHT?
    pub allow_non_global_addresses_in_dht: bool,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    pub initial_random_query_interval: Duration,
    /// A reference to the `NetworkingParametersRegistry` implementation (optional).
    pub networking_parameters_registry: Option<Box<dyn NetworkingParametersRegistry>>,
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
    /// How many temporarily banned unreachable peers to keep in memory.
    pub temporary_bans_cache_size: NonZeroUsize,
    /// Backoff policy for temporary banning of unreachable peers.
    pub temporary_ban_backoff: ExponentialBackoff,
    /// Optional external prometheus metrics. None will disable metrics gathering.
    pub metrics: Option<Metrics>,
    /// Defines protocol version for the network peers. Affects network partition.
    pub protocol_version: String,
    /// Specifies a source for peer information. None disables the protocol.
    pub peer_info_provider: Option<PeerInfoProvider>,
    /// Defines whether we maintain a persistent connection for common peers.
    /// None disables the protocol.
    pub general_connected_peers_handler: Option<ConnectedPeersHandler>,
    /// Defines whether we maintain a persistent connection for special peers.
    /// None disables the protocol.
    pub special_connected_peers_handler: Option<ConnectedPeersHandler>,
    /// Defines target total (in and out) connection number that should be maintained for general peers.
    pub general_target_connections: u32,
    /// Defines target total (in and out) connection number that should be maintained for special peers.
    pub special_target_connections: u32,
    /// Addresses to bootstrap Kademlia network
    pub bootstrap_addresses: Vec<Multiaddr>,
    /// Kademlia mode. None means "automatic mode".
    pub kademlia_mode: Option<Mode>,
    /// Known external addresses to the local peer. The addresses will be added on the swarm start
    /// and enable peer to notify others about its reachable address.
    pub external_addresses: Vec<Multiaddr>,
}

impl<LocalRecordProvider> fmt::Debug for Config<LocalRecordProvider> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").finish()
    }
}

impl Default for Config<()> {
    #[inline]
    fn default() -> Self {
        let ed25519_keypair = identity::ed25519::Keypair::generate();
        let keypair = identity::Keypair::from(ed25519_keypair);

        Self::new(
            DEFAULT_NETWORK_PROTOCOL_VERSION.to_string(),
            keypair,
            (),
            Some(PeerInfoProvider::new_client()),
        )
    }
}

impl<LocalRecordProvider> Config<LocalRecordProvider>
where
    LocalRecordProvider: self::LocalRecordProvider,
{
    /// Creates a new [`Config`].
    pub fn new(
        protocol_version: String,
        keypair: identity::Keypair,
        local_records_provider: LocalRecordProvider,
        peer_info_provider: Option<PeerInfoProvider>,
    ) -> Self {
        let mut kademlia = KademliaConfig::default();
        kademlia
            .set_query_timeout(KADEMLIA_QUERY_TIMEOUT)
            .set_protocol_names(vec![StreamProtocol::try_from_owned(
                KADEMLIA_PROTOCOL.to_owned(),
            )
            .expect("Manual protocol name creation.")])
            .disjoint_query_paths(true)
            .set_max_packet_size(2 * Piece::SIZE)
            .set_kbucket_inserts(KademliaBucketInserts::Manual)
            .set_record_filtering(KademliaStoreInserts::FilterBoth)
            // We don't use records and providers publication.
            .set_provider_record_ttl(None)
            .set_provider_publication_interval(None)
            .set_record_ttl(None)
            .set_replication_interval(None);

        let mut yamux_config = YamuxConfig::default();
        yamux_config.set_max_num_streams(YAMUX_MAX_STREAMS);

        let gossipsub = ENABLE_GOSSIP_PROTOCOL.then(|| {
            GossipsubConfigBuilder::default()
                .protocol_id_prefix(GOSSIPSUB_PROTOCOL_PREFIX)
                // TODO: Do we want message signing?
                .validation_mode(ValidationMode::None)
                // To content-address message, we can take the hash of message and use it as an ID.
                .message_id_fn(|message: &GossipsubMessage| {
                    MessageId::from(crypto::blake2b_256_hash(&message.data))
                })
                .max_transmit_size(2 * 1024 * 1024) // 2MB
                .build()
                .expect("Default config for gossipsub is always correct; qed")
        });

        let protocol_version = format!("/subspace/{}", protocol_version);
        let identify = IdentifyConfig::new(protocol_version.clone(), keypair.public());

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
            local_records_provider,
            allow_non_global_addresses_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
            networking_parameters_registry: None,
            request_response_protocols: Vec::new(),
            yamux_config,
            reserved_peers: Vec::new(),
            max_established_incoming_connections: SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS,
            max_established_outgoing_connections: SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
            max_pending_incoming_connections: SWARM_MAX_PENDING_INCOMING_CONNECTIONS,
            max_pending_outgoing_connections: SWARM_MAX_PENDING_OUTGOING_CONNECTIONS,
            temporary_bans_cache_size: TEMPORARY_BANS_CACHE_SIZE,
            temporary_ban_backoff,
            metrics: None,
            protocol_version,
            peer_info_provider,
            // we don't need to keep additional connections by default
            general_connected_peers_handler: None,
            special_connected_peers_handler: None,
            general_target_connections: SWARM_TARGET_CONNECTION_NUMBER,
            special_target_connections: SWARM_TARGET_CONNECTION_NUMBER,
            bootstrap_addresses: Vec::new(),
            kademlia_mode: Some(Mode::Server),
            external_addresses: Vec::new(),
        }
    }
}

/// Errors that might happen during network creation.
#[derive(Debug, Error)]
pub enum CreationError {
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
pub fn create<LocalRecordProvider>(
    config: Config<LocalRecordProvider>,
) -> Result<(Node, NodeRunner<LocalRecordProvider>), CreationError>
where
    LocalRecordProvider: self::LocalRecordProvider + Send + Sync + 'static,
{
    let Config {
        keypair,
        listen_on,
        listen_on_fallback_to_random_port,
        timeout,
        identify,
        kademlia,
        gossipsub,
        local_records_provider,
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
        temporary_bans_cache_size,
        temporary_ban_backoff,
        metrics,
        protocol_version,
        peer_info_provider,
        general_connected_peers_handler: general_connection_decision_handler,
        special_connected_peers_handler: special_connection_decision_handler,
        general_target_connections,
        special_target_connections,
        bootstrap_addresses,
        kademlia_mode,
        external_addresses,
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

    info!(
        %allow_non_global_addresses_in_dht,
        peer_id = %local_peer_id,
        %protocol_version,
        "DSN instance configured."
    );

    let connection_limits = ConnectionLimits::default()
        .with_max_established_per_peer(SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER)
        .with_max_pending_incoming(Some(max_pending_incoming_connections))
        .with_max_pending_outgoing(Some(max_pending_outgoing_connections))
        .with_max_established_incoming(Some(max_established_incoming_connections))
        .with_max_established_outgoing(Some(max_established_outgoing_connections));

    debug!(?connection_limits, "DSN connection limits set.");

    let behaviour = Behavior::new(BehaviorConfig {
        peer_id: local_peer_id,
        identify,
        kademlia,
        gossipsub,
        record_store: LocalOnlyRecordStore::new(local_records_provider),
        request_response_protocols,
        connection_limits,
        reserved_peers: ReservedPeersConfig {
            reserved_peers: reserved_peers.clone(),
            protocol_name: RESERVED_PEERS_PROTOCOL_NAME,
        },
        peer_info_config: PeerInfoConfig::new(PEER_INFO_PROTOCOL_NAME),
        peer_info_provider,
        general_connected_peers_config: general_connection_decision_handler.as_ref().map(|_| {
            ConnectedPeersConfig {
                log_target: GENERAL_CONNECTED_PEERS_PROTOCOL_LOG_TARGET,
                target_connected_peers: general_target_connections,
                ..ConnectedPeersConfig::default()
            }
        }),
        special_connected_peers_config: special_connection_decision_handler.as_ref().map(|_| {
            ConnectedPeersConfig {
                log_target: SPECIAL_CONNECTED_PEERS_PROTOCOL_LOG_TARGET,
                target_connected_peers: special_target_connections,
                ..ConnectedPeersConfig::default()
            }
        }),
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
                info!("Failed to listen on {addr_string} ({error}), falling back to random port");
                addr.push(Protocol::Tcp(0));
                swarm.listen_on(addr)?;
            }
        }
    }

    // Setup external addresses
    for addr in external_addresses.iter().cloned() {
        info!("DSN external address added: {addr}");
        swarm.add_external_address(addr);
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
    let node_runner =
        NodeRunner::<LocalRecordProvider>::new(NodeRunnerConfig::<LocalRecordProvider> {
            allow_non_global_addresses_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval: initial_random_query_interval,
            networking_parameters_registry: networking_parameters_registry
                .unwrap_or(StubNetworkingParametersManager.boxed()),
            reserved_peers: strip_peer_id(reserved_peers).into_iter().collect(),
            temporary_bans,
            metrics,
            protocol_version,
            general_connection_decision_handler,
            special_connection_decision_handler,
            bootstrap_addresses,
            kademlia_mode,
            external_addresses,
        });

    Ok((node, node_runner))
}
