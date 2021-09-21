// Pull imports from the parent module
use super::client::ClientConfig;
use super::*;
use std::str::FromStr;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
}

pub enum ComposedEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

pub async fn create_node(config: &ClientConfig) -> (PeerId, Swarm<ComposedBehaviour>) {
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

fn dial_bootstrap(swarm: &mut Swarm<ComposedBehaviour>, nodes: &Vec<String>) {
    for node in nodes {
        let parts: Vec<&str> = node.split("/p2p/").collect();
        let addr = Multiaddr::from_str(parts[0]).unwrap();
        let peer = PeerId::from_str(parts[1]).unwrap();
        swarm.behaviour_mut().kademlia.add_address(&peer, addr);
    }
}
