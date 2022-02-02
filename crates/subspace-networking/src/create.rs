use crate::behavior::Behaviour;
use crate::node::Node;
use crate::node_runner::NodeRunner;
use crate::shared::Shared;
use futures::channel::mpsc;
use libp2p::dns::TokioDnsConfig;
use libp2p::identify::{Identify, IdentifyConfig};
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaBucketInserts, KademliaConfig};
use libp2p::noise::NoiseConfig;
use libp2p::ping::Ping;
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::TokioTcpConfig;
use libp2p::websocket::WsConfig;
use libp2p::yamux::{WindowUpdateMode, YamuxConfig};
use libp2p::{core, identity, noise, Multiaddr, PeerId, Transport, TransportError};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use thiserror::Error;

const KADEMLIA_PROTOCOL: &[u8] = b"/subspace/kad";

/// [`Node`] configuration.
#[derive(Clone)]
pub struct Config {
    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,
    /// Nodes to connect to on creation.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// List of [`Multiaddr`] on which to listen for incoming connections.
    pub listen_on: Vec<Multiaddr>,
    /// Adds a timeout to the setup and protocol upgrade process for all inbound and outbound
    /// connections established through the transport.
    pub timeout: Duration,
    /// The configuration for the [`Kademlia`] behaviour.
    pub kademlia_config: KademliaConfig,
    /// Yamux multiplexing configuration.
    pub yamux_config: YamuxConfig,
    /// Should non-global addresses be added to the DHT?
    pub allow_non_globals_in_dht: bool,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    pub initial_random_query_interval: Duration,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkConfig").finish()
    }
}

impl Config {
    pub fn new(keypair: identity::ed25519::Keypair) -> Self {
        let mut kademlia_config = KademliaConfig::default();
        kademlia_config
            .set_protocol_name(KADEMLIA_PROTOCOL)
            .set_kbucket_inserts(KademliaBucketInserts::Manual);

        let mut yamux_config = YamuxConfig::default();
        // Enable proper flow-control: window updates are only sent when buffered data has been
        // consumed.
        yamux_config.set_window_update_mode(WindowUpdateMode::on_read());

        Self {
            keypair: identity::Keypair::Ed25519(keypair),
            bootstrap_nodes: vec![],
            listen_on: vec![],
            timeout: Duration::from_secs(10),
            kademlia_config,
            yamux_config,
            allow_non_globals_in_dht: false,
            initial_random_query_interval: Duration::from_secs(1),
        }
    }
}

/// Errors that might happen during network creation.
#[derive(Debug, Error)]
pub enum CreationError {
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
        timeout,
        kademlia_config,
        bootstrap_nodes,
        yamux_config,
        allow_non_globals_in_dht,
        initial_random_query_interval,
    }: Config,
) -> Result<(Node, NodeRunner), CreationError> {
    let permanent_addresses = bootstrap_nodes.clone();
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

        let kademlia = {
            let store = MemoryStore::new(local_peer_id);
            let mut kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

            for (peer_id, address) in bootstrap_nodes {
                kademlia.add_address(&peer_id, address);
            }

            kademlia
        };

        let behaviour = Behaviour {
            kademlia,
            identify: Identify::new(IdentifyConfig::new(
                "/ipfs/0.1.0".to_string(),
                keypair.public(),
            )),
            ping: Ping::default(),
        };

        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        for addr in listen_on {
            swarm.listen_on(addr)?;
        }

        Ok::<_, CreationError>(swarm)
    });

    let swarm = create_swarm_fut.await.unwrap()?;

    let (command_sender, command_receiver) = mpsc::channel(1);

    let shared = Arc::new(Shared::new(local_peer_id, command_sender));

    let node = Node::new(Arc::clone(&shared));
    let node_runner = NodeRunner::new(
        permanent_addresses,
        allow_non_globals_in_dht,
        command_receiver,
        swarm,
        shared,
        initial_random_query_interval,
    );

    Ok((node, node_runner))
}
