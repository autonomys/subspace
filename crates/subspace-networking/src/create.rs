pub use crate::behavior::custom_record_store::ValueGetter;
use crate::behavior::{Behavior, BehaviorConfig};
use crate::node::Node;
use crate::node_runner::NodeRunner;
use crate::pieces_by_range_handler::{
    ExternalPiecesByRangeRequestHandler, PiecesByRangeRequestHandler,
};
use crate::shared::Shared;
use futures::channel::mpsc;
use futures::{AsyncRead, AsyncWrite};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, MemoryTransport, OrTransport};
use libp2p::dns::TokioDnsConfig;
use libp2p::gossipsub::{
    GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::IdentifyConfig;
use libp2p::kad::{KademliaBucketInserts, KademliaConfig, KademliaStoreInserts};
use libp2p::multiaddr::Protocol;
use libp2p::noise::NoiseConfig;
use libp2p::relay::v2::client::transport::ClientTransport;
use libp2p::relay::v2::client::Client as RelayClient;
use libp2p::relay::v2::relay::Config as RelayConfig;
use libp2p::swarm::{AddressScore, SwarmBuilder};
use libp2p::tcp::TokioTcpConfig;
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
const GOSSIPSUB_PROTOCOL: &str = "/subspace/gossipsub/0.1.0";

/// A helper structure for working with libp2p `relay::Config`. The original structure is not Clone,
/// Send and Sync which is not convenient. `RelayLimitSettings` implements a conversion method to the
/// original `relay::Config` and the default method with the original recommended settings.
#[derive(Clone, Debug)]
pub struct RelayLimitSettings {
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration: Duration,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration: Duration,
    pub max_circuit_bytes: u64,
}

impl Default for RelayLimitSettings {
    fn default() -> Self {
        let default_relay_config = RelayConfig::default();

        Self {
            max_reservations: default_relay_config.max_reservations,
            max_reservations_per_peer: default_relay_config.max_circuits_per_peer,
            reservation_duration: default_relay_config.reservation_duration,
            max_circuits: default_relay_config.max_circuits,
            max_circuits_per_peer: default_relay_config.max_circuits_per_peer,
            max_circuit_duration: default_relay_config.max_circuit_duration,
            max_circuit_bytes: default_relay_config.max_circuit_bytes,
        }
    }
}

impl RelayLimitSettings {
    /// Converts `RelayLimitSettings` to libp2p `relay::Config`.
    pub fn to_relay_config(self) -> RelayConfig {
        RelayConfig {
            max_reservations: self.max_reservations,
            max_reservations_per_peer: self.max_circuits_per_peer,
            reservation_duration: self.reservation_duration,
            reservation_rate_limiters: Vec::new(),
            max_circuits: self.max_circuits,
            max_circuits_per_peer: self.max_circuits_per_peer,
            max_circuit_duration: self.max_circuit_duration,
            max_circuit_bytes: self.max_circuit_bytes,
            circuit_src_rate_limiters: Vec::new(),
        }
    }
}

/// Defines relay circuits configuration for the networking.
#[derive(Clone, Debug)]
pub enum RelayConfiguration {
    /// Relay server configuration. The node will be able to listen on the provided Multiaddr with
    /// adding it as an external address.
    /// Expected format for Multiaddr: /ip4/127.0.0.1/tcp/50000
    /// The relay configuration will be configured with provided RelayLimitSettings.
    /// This option will toggle the relay behaviour (relay server).
    Server(Multiaddr, RelayLimitSettings),

    /// Relay-client configuration in accepting mode (eg.: client behind NAT). It will enable listening
    /// on the provided Multiaddr with registering a circuit reservation.
    /// Expected format for Multiaddr: /ip4/127.0.0.1/tcp/50000/p2p/<server_peer_id>/p2p-circuit
    /// This option will toggle the relay-client behaviour.
    ClientAcceptor(Multiaddr),

    /// Relay-client configuration in requesting mode (a request for a client behind NAT).
    /// It will enable creating a relay circuit.
    /// This option will toggle the relay-client behaviour.
    ClientInitiator,

    /// No relay configuration.
    /// This option will have both relay (server) and relay client behaviour disabled.
    NoRelay,
}

impl Default for RelayConfiguration {
    fn default() -> Self {
        Self::NoRelay
    }
}

impl RelayConfiguration {
    /// Defines whether `self` is configured as a relay client in either ClientInitiator or
    /// ClientAcceptor modes.
    pub fn is_client_enabled(&self) -> bool {
        matches!(
            self,
            RelayConfiguration::ClientInitiator | RelayConfiguration::ClientAcceptor(..)
        )
    }

    /// Extracts `RelayLimitSettings` from the `Server` configuration option. Returns None otherwise.
    pub fn server_relay_settings(&self) -> Option<RelayLimitSettings> {
        if let RelayConfiguration::Server(_, settings) = self {
            return Some(settings.clone());
        }

        None
    }
}

/// [`Node`] configuration.
#[derive(Clone)]
pub struct Config {
    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,
    /// Nodes to connect to on creation, must end with `/p2p/QmFoo` at the end.
    pub bootstrap_nodes: Vec<Multiaddr>,
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
    /// The configuration for the Kademlia behaviour.
    pub gossipsub: GossipsubConfig,
    /// Externally provided implementation of value getter for Kademlia DHT,
    pub value_getter: ValueGetter,
    /// Yamux multiplexing configuration.
    pub yamux_config: YamuxConfig,
    /// Should non-global addresses be added to the DHT?
    pub allow_non_globals_in_dht: bool,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    pub initial_random_query_interval: Duration,
    /// Defines a handler for the pieces-by-range protocol.
    pub pieces_by_range_request_handler: ExternalPiecesByRangeRequestHandler,
    /// Defines relay mode and limit settings.
    pub relay_config: RelayConfiguration,
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
            // Ignore any puts
            .set_record_filtering(KademliaStoreInserts::FilterBoth)
            .set_kbucket_inserts(KademliaBucketInserts::Manual);

        let mut yamux_config = YamuxConfig::default();
        // Enable proper flow-control: window updates are only sent when buffered data has been
        // consumed.
        yamux_config.set_window_update_mode(WindowUpdateMode::on_read());

        let gossipsub = GossipsubConfigBuilder::default()
            .protocol_id_prefix(GOSSIPSUB_PROTOCOL)
            // TODO: Do we want message signing?
            .validation_mode(ValidationMode::None)
            // To content-address message, we can take the hash of message and use it as an ID.
            .message_id_fn(|message: &GossipsubMessage| {
                MessageId::from(crypto::sha256_hash(&message.data))
            })
            .max_transmit_size(2 * 1024 * 1024) // 2MB
            .build()
            .expect("Default config for gossipsub is always correct; qed");

        let keypair = identity::Keypair::Sr25519(keypair);

        let identify = IdentifyConfig::new("ipfs/0.1.0".to_string(), keypair.public());

        Self {
            keypair,
            bootstrap_nodes: vec![],
            listen_on: vec![],
            listen_on_fallback_to_random_port: true,
            timeout: Duration::from_secs(10),
            identify,
            kademlia,
            gossipsub,
            value_getter: Arc::new(|_key| None),
            yamux_config,
            allow_non_globals_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
            pieces_by_range_request_handler: Arc::new(|_| None),
            relay_config: Default::default(),
        }
    }
}

/// Errors that might happen during network creation.
#[derive(Debug, Error)]
pub enum CreationError {
    /// Bad bootstrap address.
    #[error("Bad bootstrap address")]
    BadBootstrapAddress,
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Transport error when attempting to listen on multiaddr.
    #[error("Transport error when attempting to listen on multiaddr: {0}")]
    TransportError(#[from] TransportError<io::Error>),
}

/// Create a new network node and node runner instances.
pub async fn create(
    Config {
        keypair,
        listen_on,
        listen_on_fallback_to_random_port,
        timeout,
        identify,
        kademlia,
        bootstrap_nodes,
        gossipsub,
        value_getter,
        yamux_config,
        allow_non_globals_in_dht,
        initial_random_query_interval,
        pieces_by_range_request_handler,
        relay_config,
    }: Config,
) -> Result<(Node, NodeRunner), CreationError> {
    let local_peer_id = keypair.public().to_peer_id();

    // Create optional relay transport and client.
    let (relay_transport, relay_client) = relay_config
        .is_client_enabled()
        .then(|| {
            let (relay_transport, relay_client) =
                RelayClient::new_transport_and_behaviour(local_peer_id);

            (Some(relay_transport), Some(relay_client))
        })
        .unwrap_or((None, None));

    let transport = build_transport(keypair, timeout, yamux_config, relay_transport).await?;

    let relay_config_for_swarm = relay_config.clone();
    // libp2p uses blocking API, hence we need to create a blocking task.
    let create_swarm_fut = tokio::task::spawn_blocking(move || {
        // Remove `/p2p/QmFoo` from the end of multiaddr and store separately in a tuple
        let bootstrap_nodes = bootstrap_nodes
            .into_iter()
            .map(|mut multiaddr| {
                let peer_id: PeerId = multiaddr
                    .pop()
                    .and_then(|protocol| {
                        if let Protocol::P2p(peer_id) = protocol {
                            Some(peer_id.try_into().ok()?)
                        } else {
                            None
                        }
                    })
                    .ok_or(CreationError::BadBootstrapAddress)?;

                Ok((peer_id, multiaddr))
            })
            .collect::<Result<_, CreationError>>()?;

        let (pieces_by_range_request_handler, pieces_by_range_protocol_config) =
            PiecesByRangeRequestHandler::new(pieces_by_range_request_handler);

        let behaviour = Behavior::new(
            BehaviorConfig {
                peer_id: local_peer_id,
                bootstrap_nodes,
                identify,
                kademlia,
                gossipsub,
                value_getter,
                pieces_by_range_protocol_config,
                pieces_by_range_request_handler: Box::new(pieces_by_range_request_handler),
                relay_config: relay_config_for_swarm.clone(),
            },
            relay_client,
        );

        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

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

        // Setup circuit for the accepting relay client. This will reserve a circuit.
        if let RelayConfiguration::ClientAcceptor(addr) = relay_config_for_swarm.clone() {
            swarm.listen_on(addr)?;
        }

        // Listen on an address and set is as an external address for relay server.
        // Initially a server is not aware of its external addresses.
        if let RelayConfiguration::Server(addr, _) = relay_config_for_swarm {
            swarm.listen_on(addr.clone())?;
            swarm.add_external_address(addr, AddressScore::Infinite);
        }

        Ok::<_, CreationError>(swarm)
    });

    let swarm = create_swarm_fut.await.expect("Swarm future failed.")?;

    let (command_sender, command_receiver) = mpsc::channel(1);

    let shared = Arc::new(Shared::new(local_peer_id, command_sender));

    let node = Node::new(Arc::clone(&shared), relay_config);
    let node_runner = NodeRunner::new(
        allow_non_globals_in_dht,
        command_receiver,
        swarm,
        shared,
        initial_random_query_interval,
    );

    Ok((node, node_runner))
}

// Builds the transport stack that LibP2P will communicate over along with an optional relay client.
async fn build_transport(
    keypair: identity::Keypair,
    timeout: Duration,
    yamux_config: YamuxConfig,
    relay_transport: Option<ClientTransport>,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, CreationError> {
    let transport = {
        let dns_tcp = TokioDnsConfig::system(TokioTcpConfig::new().nodelay(true))?;
        let ws = WsConfig::new(TokioDnsConfig::system(TokioTcpConfig::new().nodelay(true))?);
        let transport = dns_tcp.or_transport(ws);

        // Add MemoryTransport to the chain to enable in-memory relay configurations.
        MemoryTransport::default().or_transport(transport)
    };

    if let Some(relay_transport) = relay_transport {
        let transport = OrTransport::new(relay_transport, transport);
        Ok(upgrade_transport(
            transport,
            &keypair,
            timeout,
            yamux_config,
        ))
    } else {
        Ok(upgrade_transport(
            transport,
            &keypair,
            timeout,
            yamux_config,
        ))
    }
}

// Upgrades a provided transport with a multiplexer and a Noise authenticator.
fn upgrade_transport<Output, Error, Listener, ListenerUpgrade, Dial>(
    transport: impl Transport<
            Output = Output,
            Error = Error,
            Listener = Listener,
            ListenerUpgrade = ListenerUpgrade,
            Dial = Dial,
        > + Send
        + 'static,
    keypair: &identity::Keypair,
    timeout: Duration,
    yamux_config: YamuxConfig,
) -> Boxed<(PeerId, StreamMuxerBox)>
where
    Output: Unpin + Send + AsyncWrite + AsyncRead + 'static,
    Error: Sync + Send + 'static,
    Listener: Send + 'static,
    ListenerUpgrade: Send + 'static,
    Dial: Send + 'static,
{
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");

    transport
        .upgrade(core::upgrade::Version::V1Lazy)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(yamux_config)
        .timeout(timeout)
        .boxed()
}
