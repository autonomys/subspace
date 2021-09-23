// Stuff for Kademlia
use libp2p::kad::{record::store::MemoryStore, Kademlia, KademliaEvent};

// Stuff for defining composed behaviour
use libp2p::NetworkBehaviour;

// Stuff needed to create the swarm
use libp2p::core::{upgrade, Transport};
use libp2p::identity;
use libp2p::mplex;
use libp2p::noise::{Keypair, NoiseConfig, X25519Spec};
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::TokioTcpConfig;
use libp2p::{Multiaddr, PeerId, Swarm};

// Pull imports from the parent module
use super::client::ClientConfig;
use std::str::FromStr;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "ComposedEvent")]
pub(super) struct ComposedBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
}

pub(super) enum ComposedEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

pub(super) fn create_node(config: &ClientConfig) -> (PeerId, Swarm<ComposedBehaviour>) {
    // Generate IDs.
    let key = identity::Keypair::generate_ed25519();
    let peerid = PeerId::from_public_key(key.public());

    let mut swarm = create_swarm(peerid, key);

    if let Some(addr) = &config.listen_addr {
        swarm.listen_on(addr.clone()).unwrap();
    }

    // Connect to bootstrap nodes.
    dial_bootstrap(&mut swarm, &config.bootstrap_nodes);

    (peerid, swarm)
}

fn create_swarm(peerid: PeerId, key: identity::Keypair) -> Swarm<ComposedBehaviour> {
    // Generate NOISE authentication keys.
    let auth_keys = Keypair::<X25519Spec>::new().into_authentic(&key).unwrap();

    // Create secure-TCP transport that uses tokio under the hood.
    let transport = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let behaviour = ComposedBehaviour {
        kademlia: Kademlia::new(peerid, MemoryStore::new(peerid)),
    };

    SwarmBuilder::new(transport, behaviour, peerid)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build()
}

fn dial_bootstrap(swarm: &mut Swarm<ComposedBehaviour>, nodes: &[String]) {
    for node in nodes {
        let parts: Vec<&str> = node.split("/p2p/").collect();
        let addr = Multiaddr::from_str(parts[0]).unwrap();
        let peer = PeerId::from_str(parts[1]).unwrap();
        swarm.behaviour_mut().kademlia.add_address(&peer, addr);
        // swarm.dial_addr(Multiaddr::from_str(node).unwrap()).unwrap();
    }
}
