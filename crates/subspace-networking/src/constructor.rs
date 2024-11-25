pub(crate) mod temporary_bans;
mod transport;

use crate::behavior::persistent_parameters::{KnownPeersRegistry, StubNetworkingParametersManager};
use crate::behavior::{Behavior, BehaviorConfig};
use crate::constructor::temporary_bans::TemporaryBans;
use crate::constructor::transport::build_transport;
use crate::node::Node;
use crate::node_runner::{NodeRunner, NodeRunnerConfig};
use crate::protocols::autonat_wrapper::Config as AutonatWrapperConfig;
use crate::protocols::request_response::request_response_factory::RequestHandler;
use crate::protocols::reserved_peers::Config as ReservedPeersConfig;
use crate::shared::Shared;
use crate::utils::rate_limiter::RateLimiter;
use crate::utils::{strip_peer_id, SubspaceMetrics};
use backoff::{ExponentialBackoff, SystemClock};
use futures::channel::mpsc;
use libp2p::autonat::Config as AutonatConfig;
use libp2p::connection_limits::ConnectionLimits;
use libp2p::gossipsub::{
    Config as GossipsubConfig, ConfigBuilder as GossipsubConfigBuilder,
    Message as GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::Config as IdentifyConfig;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{
    store, BucketInserts, Config as KademliaConfig, Mode, ProviderRecord, Record, RecordKey,
    StoreInserts,
};
use libp2p::metrics::Metrics;
use libp2p::multiaddr::Protocol;
use libp2p::yamux::Config as YamuxConfig;
use libp2p::{identity, Multiaddr, PeerId, StreamProtocol, SwarmBuilder, TransportError};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::borrow::Cow;
use std::iter::Empty;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, iter};
use subspace_core_primitives::hashes;
use subspace_core_primitives::pieces::Piece;
use thiserror::Error;
use tracing::{debug, error, info};

const DEFAULT_NETWORK_PROTOCOL_VERSION: &str = "dev";
const KADEMLIA_PROTOCOL: &str = "/subspace/kad/0.1.0";
const GOSSIPSUB_PROTOCOL_PREFIX: &str = "subspace/gossipsub";

/// Defines max_negotiating_inbound_streams constant for the swarm.
/// It must be set for large plots.
const SWARM_MAX_NEGOTIATING_INBOUND_STREAMS: usize = 100000;
/// How long will connection be allowed to be open without any usage
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 100;
/// The default maximum established incoming connection number for the swarm.
const SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS: u32 = 100;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_INCOMING_CONNECTIONS: u32 = 80;
/// The default maximum pending incoming connection number for the swarm.
const SWARM_MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 80;
const KADEMLIA_QUERY_TIMEOUT: Duration = Duration::from_secs(40);
const SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 3;
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 10;
// TODO: Consider moving this constant to configuration or removing `Toggle` wrapper when we find a
//  use-case for gossipsub protocol.
const ENABLE_GOSSIP_PROTOCOL: bool = false;

const TEMPORARY_BANS_CACHE_SIZE: u32 = 10_000;
const TEMPORARY_BANS_DEFAULT_BACKOFF_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
const TEMPORARY_BANS_DEFAULT_BACKOFF_RANDOMIZATION_FACTOR: f64 = 0.1;
const TEMPORARY_BANS_DEFAULT_BACKOFF_MULTIPLIER: f64 = 1.5;
const TEMPORARY_BANS_DEFAULT_MAX_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// We pause between reserved peers dialing otherwise we could do multiple dials to offline peers
/// wasting resources and producing a ton of log records.
const DIALING_INTERVAL_IN_SECS: Duration = Duration::from_secs(1);

/// Specific YAMUX settings for Subspace applications: additional buffer space for pieces and
/// substream's limit.
///
/// Defines a replication factor for Kademlia on get_record operation.
/// "Good citizen" supports the network health.
const YAMUX_MAX_STREAMS: usize = 256;

/// Max confidence for autonat protocol. Could affect Kademlia mode change.
pub(crate) const AUTONAT_MAX_CONFIDENCE: usize = 3;
/// We set a very long pause before autonat initialization (Duration::Max panics).
const AUTONAT_SERVER_PROBE_DELAY: Duration = Duration::from_secs(3600 * 24 * 365);

/// Defines Kademlia mode
#[derive(Clone, Debug)]
pub enum KademliaMode {
    /// The Kademlia mode is static for the duration of the application.
    Static(Mode),
    /// Kademlia mode will be changed using Autonat protocol when max confidence reached.
    Dynamic,
}

impl KademliaMode {
    /// Returns true if the mode is Dynamic.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic)
    }

    /// Returns true if the mode is Static.
    pub fn is_static(&self) -> bool {
        matches!(self, Self::Static(..))
    }
}

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
    type RecordsIter<'a>
        = Empty<Cow<'a, Record>>
    where
        Self: 'a;
    type ProvidedIter<'a>
        = Empty<Cow<'a, ProviderRecord>>
    where
        Self: 'a;

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
    /// A reference to the `NetworkingParametersRegistry` implementation.
    pub known_peers_registry: Box<dyn KnownPeersRegistry>,
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
    pub temporary_bans_cache_size: u32,
    /// Backoff policy for temporary banning of unreachable peers.
    pub temporary_ban_backoff: ExponentialBackoff,
    /// Optional libp2p prometheus metrics. None will disable metrics gathering.
    pub libp2p_metrics: Option<Metrics>,
    /// Internal prometheus metrics. None will disable metrics gathering.
    pub metrics: Option<SubspaceMetrics>,
    /// Defines protocol version for the network peers. Affects network partition.
    pub protocol_version: String,
    /// Addresses to bootstrap Kademlia network
    pub bootstrap_addresses: Vec<Multiaddr>,
    /// Kademlia mode. The default value is set to Static(Client). The peer won't add its address
    /// to other peers` Kademlia routing table. Changing this behaviour implies that a peer can
    /// provide pieces to others.
    pub kademlia_mode: KademliaMode,
    /// Known external addresses to the local peer. The addresses will be added on the swarm start
    /// and enable peer to notify others about its reachable address.
    pub external_addresses: Vec<Multiaddr>,
}

impl<LocalRecordProvider> fmt::Debug for Config<LocalRecordProvider> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").finish()
    }
}

/// This default can only be used for `dev` networks.
/// Other networks should use `Config::new()` to apply the correct prefix to the protocol version.
impl Default for Config<()> {
    #[inline]
    fn default() -> Self {
        let ed25519_keypair = identity::ed25519::Keypair::generate();
        let keypair = identity::Keypair::from(ed25519_keypair);

        Self::new(
            DEFAULT_NETWORK_PROTOCOL_VERSION.to_string(),
            keypair,
            (),
            None,
        )
    }
}

impl<LocalRecordProvider> Config<LocalRecordProvider>
where
    LocalRecordProvider: self::LocalRecordProvider,
{
    /// Creates a new [`Config`].
    /// Applies a subspace-specific version prefix to the `protocol_version`.
    pub fn new(
        protocol_version: String,
        keypair: identity::Keypair,
        local_records_provider: LocalRecordProvider,
        prometheus_registry: Option<&mut Registry>,
    ) -> Self {
        let (libp2p_metrics, metrics) = prometheus_registry
            .map(|registry| {
                (
                    Some(Metrics::new(registry)),
                    Some(SubspaceMetrics::new(registry)),
                )
            })
            .unwrap_or((None, None));

        let mut kademlia = KademliaConfig::new(
            StreamProtocol::try_from_owned(KADEMLIA_PROTOCOL.to_owned())
                .expect("Manual protocol name creation."),
        );
        kademlia
            .set_query_timeout(KADEMLIA_QUERY_TIMEOUT)
            .disjoint_query_paths(true)
            .set_max_packet_size(2 * Piece::SIZE)
            .set_kbucket_inserts(BucketInserts::Manual)
            .set_record_filtering(StoreInserts::FilterBoth)
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
                    MessageId::from(*hashes::blake3_hash(&message.data))
                })
                .max_transmit_size(2 * 1024 * 1024) // 2MB
                .build()
                .expect("Default config for gossipsub is always correct; qed")
        });

        let protocol_version = format!("/subspace/2/{}", protocol_version);
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
            known_peers_registry: StubNetworkingParametersManager.boxed(),
            request_response_protocols: Vec::new(),
            yamux_config,
            reserved_peers: Vec::new(),
            max_established_incoming_connections: SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS,
            max_established_outgoing_connections: SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
            max_pending_incoming_connections: SWARM_MAX_PENDING_INCOMING_CONNECTIONS,
            max_pending_outgoing_connections: SWARM_MAX_PENDING_OUTGOING_CONNECTIONS,
            temporary_bans_cache_size: TEMPORARY_BANS_CACHE_SIZE,
            temporary_ban_backoff,
            libp2p_metrics,
            metrics,
            protocol_version,
            bootstrap_addresses: Vec::new(),
            kademlia_mode: KademliaMode::Static(Mode::Client),
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
    /// Transport creation error.
    #[error("Transport creation error: {0}")]
    // TODO: Restore `#[from] TransportError` once https://github.com/libp2p/rust-libp2p/issues/4824
    //  is resolved
    TransportCreationError(Box<dyn std::error::Error + Send + Sync>),
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
pub fn construct<LocalRecordProvider>(
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
        known_peers_registry,
        request_response_protocols,
        reserved_peers,
        max_established_incoming_connections,
        max_established_outgoing_connections,
        max_pending_incoming_connections,
        max_pending_outgoing_connections,
        temporary_bans_cache_size,
        temporary_ban_backoff,
        libp2p_metrics,
        metrics,
        protocol_version,
        bootstrap_addresses,
        kademlia_mode,
        external_addresses,
    } = config;
    let local_peer_id = peer_id(&keypair);

    info!(
        %allow_non_global_addresses_in_dht,
        peer_id = %local_peer_id,
        %protocol_version,
        "DSN instance configured."
    );

    let connection_limits = ConnectionLimits::default()
        .with_max_established_per_peer(Some(SWARM_MAX_ESTABLISHED_CONNECTIONS_PER_PEER))
        .with_max_pending_incoming(Some(max_pending_incoming_connections))
        .with_max_pending_outgoing(Some(max_pending_outgoing_connections))
        .with_max_established_incoming(Some(max_established_incoming_connections))
        .with_max_established_outgoing(Some(max_established_outgoing_connections));

    debug!(?connection_limits, "DSN connection limits set.");

    let autonat_boot_delay = if kademlia_mode.is_static() || !external_addresses.is_empty() {
        AUTONAT_SERVER_PROBE_DELAY
    } else {
        AutonatConfig::default().boot_delay
    };

    debug!(
        ?autonat_boot_delay,
        ?kademlia_mode,
        ?external_addresses,
        "Autonat boot delay set."
    );

    let mut behaviour = Behavior::new(BehaviorConfig {
        peer_id: local_peer_id,
        identify,
        kademlia,
        gossipsub,
        record_store: LocalOnlyRecordStore::new(local_records_provider),
        request_response_protocols,
        request_response_max_concurrent_streams: {
            let max_num_connections = max_established_incoming_connections as usize
                + max_established_outgoing_connections as usize;
            max_num_connections * MAX_CONCURRENT_STREAMS_PER_CONNECTION
        },
        connection_limits,
        reserved_peers: ReservedPeersConfig {
            reserved_peers: reserved_peers.clone(),
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        },
        autonat: AutonatWrapperConfig {
            inner_config: AutonatConfig {
                use_connected: true,
                only_global_ips: !config.allow_non_global_addresses_in_dht,
                confidence_max: AUTONAT_MAX_CONFIDENCE,
                boot_delay: autonat_boot_delay,
                ..Default::default()
            },
            local_peer_id,
            servers: bootstrap_addresses.clone(),
        },
    });

    match (kademlia_mode, external_addresses.is_empty()) {
        (KademliaMode::Static(mode), _) => {
            behaviour.kademlia.set_mode(Some(mode));
        }
        (KademliaMode::Dynamic, false) => {
            behaviour.kademlia.set_mode(Some(Mode::Server));
        }
        _ => {
            // Autonat will figure it out
        }
    };

    let temporary_bans = Arc::new(Mutex::new(TemporaryBans::new(
        temporary_bans_cache_size,
        temporary_ban_backoff,
    )));

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(|keypair| {
            Ok(build_transport(
                allow_non_global_addresses_in_dht,
                keypair,
                Arc::clone(&temporary_bans),
                timeout,
                yamux_config,
            )?)
        })
        .map_err(|error| CreationError::TransportCreationError(error.into()))?
        .with_behaviour(move |_keypair| Ok(behaviour))
        .expect("Not fallible; qed")
        .with_swarm_config(|config| {
            config
                .with_max_negotiating_inbound_streams(SWARM_MAX_NEGOTIATING_INBOUND_STREAMS)
                .with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
        })
        .build();

    let is_listening = !listen_on.is_empty();

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

    let rate_limiter = RateLimiter::new(
        max_established_outgoing_connections,
        max_pending_outgoing_connections,
    );

    let shared = Arc::new(Shared::new(local_peer_id, command_sender, rate_limiter));
    let shared_weak = Arc::downgrade(&shared);

    let node = Node::new(shared);
    let node_runner = NodeRunner::new(NodeRunnerConfig {
        allow_non_global_addresses_in_dht,
        is_listening,
        command_receiver,
        swarm,
        shared_weak,
        next_random_query_interval: initial_random_query_interval,
        known_peers_registry,
        reserved_peers: strip_peer_id(reserved_peers).into_iter().collect(),
        temporary_bans,
        libp2p_metrics,
        metrics,
        protocol_version,
        bootstrap_addresses,
    });

    Ok((node, node_runner))
}
