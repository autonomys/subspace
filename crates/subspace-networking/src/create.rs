pub use crate::behavior::custom_record_store::ValueGetter;
use crate::behavior::{Behavior, BehaviorConfig};
use crate::node::Node;
use crate::node_runner::NodeRunner;
use crate::pieces_by_range_handler::{
    ExternalPiecesByRangeRequestHandler, PiecesByRangeRequestHandler,
};
use crate::shared::Shared;
use futures::channel::mpsc;
use libp2p::dns::TokioDnsConfig;
use libp2p::gossipsub::{
    GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::identify::IdentifyConfig;
use libp2p::kad::{KademliaBucketInserts, KademliaConfig, KademliaStoreInserts};
use libp2p::multiaddr::Protocol;
use libp2p::noise::NoiseConfig;
use libp2p::swarm::SwarmBuilder;
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
        pieces_by_range_request_handler: request_handler,
    }: Config,
) -> Result<(Node, NodeRunner), CreationError> {
    let local_peer_id = keypair.public().to_peer_id();

    // libp2p uses blocking API, hence we need to create a blocking task.
    let create_swarm_fut = tokio::task::spawn_blocking(move || {
        let transport = {
            let transport = {
                let tcp = TokioTcpConfig::new().nodelay(true);
                let dns_tcp = TokioDnsConfig::system(tcp)?;
                let ws = WsConfig::new(dns_tcp.clone());
                dns_tcp.or_transport(ws)
            };

            let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
                .into_authentic(&keypair)
                .expect("Signing libp2p-noise static DH keypair failed.");

            transport
                .upgrade(core::upgrade::Version::V1Lazy)
                .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
                .multiplex(yamux_config)
                .timeout(timeout)
                .boxed()
        };

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

        let (reqeust_response_handler, request_response) =
            PiecesByRangeRequestHandler::new(request_handler);

        tokio::spawn(async move {
            reqeust_response_handler.run().await;
        });

        let behaviour = Behavior::new(BehaviorConfig {
            peer_id: local_peer_id,
            bootstrap_nodes,
            identify,
            kademlia,
            gossipsub,
            value_getter,
            request_response,
        });

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

        Ok::<_, CreationError>(swarm)
    });

    let swarm = create_swarm_fut.await.expect("Swarm future failed.")?;

    let (command_sender, command_receiver) = mpsc::channel(1);

    let shared = Arc::new(Shared::new(local_peer_id, command_sender));

    let node = Node::new(Arc::clone(&shared));
    let node_runner = NodeRunner::new(
        allow_non_globals_in_dht,
        command_receiver,
        swarm,
        shared,
        initial_random_query_interval,
    );

    Ok((node, node_runner))
}
