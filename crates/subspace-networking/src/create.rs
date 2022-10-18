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
use libp2p::identify::IdentifyConfig;
use libp2p::kad::{KademliaBucketInserts, KademliaConfig, KademliaStoreInserts};
use libp2p::mplex::MplexConfig;
use libp2p::multiaddr::Protocol;
use libp2p::noise::NoiseConfig;
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::{GenTcpConfig, TokioTcpTransport};
use libp2p::websocket::WsConfig;
use libp2p::yamux::{WindowUpdateMode, YamuxConfig};
use libp2p::{core, identity, noise, Multiaddr, PeerId, Transport, TransportError};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use subspace_core_primitives::crypto;
use thiserror::Error;
use tracing::info;

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
const KADEMLIA_PROVIDER_TTL_IN_SECS: u64 = 86400; /* 1 day */
// Defines a republication interval for item providers in Kademlia network.
const KADEMLIA_PROVIDER_REPUBLICATION_INTERVAL_IN_SECS: u64 = 3600; /* 1 hour */

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
    /// Example: /memory/<port>/p2p/<server_peer_id>/p2p-circuit
    Client(Multiaddr),
}

impl RelayMode {
    /// Defines whether the node has its relay behavior enabled.
    pub fn is_relay_server(&self) -> bool {
        matches!(self, RelayMode::Server)
    }
}

/// [`Node`] configuration.
#[derive(Clone)]
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
    /// Mplex multiplexing configuration.
    pub mplex_config: MplexConfig,
    /// Should non-global addresses be added to the DHT?
    pub allow_non_globals_in_dht: bool,
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
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").finish()
    }
}

impl Config {
    pub fn with_generated_keypair() -> Self {
        Self::with_keypair(identity::sr25519::Keypair::generate())
    }

    pub fn with_keypair(keypair: identity::sr25519::Keypair) -> Self {
        let mut kademlia = KademliaConfig::default();
        kademlia
            .set_protocol_name(KADEMLIA_PROTOCOL)
            // Providers' settings
            .set_provider_record_ttl(Some(Duration::from_secs(KADEMLIA_PROVIDER_TTL_IN_SECS)))
            .set_provider_publication_interval(Some(Duration::from_secs(
                KADEMLIA_PROVIDER_REPUBLICATION_INTERVAL_IN_SECS,
            )))
            // Ignore any puts
            .set_record_filtering(KademliaStoreInserts::FilterBoth)
            .set_kbucket_inserts(KademliaBucketInserts::Manual);

        let mut yamux_config = YamuxConfig::default();
        // Enable proper flow-control: window updates are only sent when buffered data has been
        // consumed.
        yamux_config.set_window_update_mode(WindowUpdateMode::on_read());

        let mplex_config = MplexConfig::default();

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

        let keypair = identity::Keypair::Sr25519(keypair);

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
            allow_non_globals_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
            networking_parameters_registry: BootstrappedNetworkingParameters::default().boxed(),
            request_response_protocols: Vec::new(),
            yamux_config,
            mplex_config,
            reserved_peers: Vec::new(),
            max_established_incoming_connections: SWARM_MAX_ESTABLISHED_INCOMING_CONNECTIONS,
            max_established_outgoing_connections: SWARM_MAX_ESTABLISHED_OUTGOING_CONNECTIONS,
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
        mplex_config,
        allow_non_globals_in_dht,
        initial_random_query_interval,
        networking_parameters_registry,
        request_response_protocols,
        reserved_peers,
        max_established_incoming_connections,
        max_established_outgoing_connections,
    } = config;
    let local_peer_id = keypair.public().to_peer_id();

    let transport = build_transport(&keypair, timeout, yamux_config, mplex_config)?;

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

        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
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

        let node = Node::new(shared);
        let node_runner = NodeRunner::<RecordStore>::new(NodeRunnerConfig::<RecordStore> {
            allow_non_globals_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval: initial_random_query_interval,
            networking_parameters_registry,
            reserved_peers: convert_multiaddresses(reserved_peers).into_iter().collect(),
            max_established_incoming_connections,
            max_established_outgoing_connections,
        });

        Ok((node, node_runner))
    });

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
    mplex_config: MplexConfig,
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
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux_config,
            mplex_config,
        ))
        .timeout(timeout)
        .boxed())
}
