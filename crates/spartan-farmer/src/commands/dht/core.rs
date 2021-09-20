// Pull imports from the parent module
use super::client::ClientConfig;
use super::*;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

pub enum ComposedEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

pub async fn create_bootstrap(config: ClientConfig) -> (PeerId, Swarm<ComposedBehaviour>) {
    // Generate IDs.
    // TODO: Read a RSA private key from disk, to create a bootstrap node's PeerID.
    let private_key: &mut [u8] = &mut config.bootstrap_keys.clone()[0];
    let key = identity::Keypair::rsa_from_pkcs8(private_key).unwrap();
    let peerid = PeerId::from_public_key(key.public());

    let mut swarm = create_swarm(peerid.clone(), key);

    if let Some(addr) = config.listen_addr {
        swarm.listen_on(addr).unwrap();
    }

    (peerid, swarm)
}

pub async fn create_node(config: ClientConfig) -> (PeerId, Swarm<ComposedBehaviour>) {
    // Generate IDs.
    let key = identity::Keypair::generate_ed25519();
    let peerid = PeerId::from_public_key(key.public());

    let mut swarm = create_swarm(peerid.clone(), key);

    // Connect to bootstrap nodes.
    dial_bootstrap(&mut swarm, config.bootstrap_nodes);

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

fn dial_bootstrap(swarm: &mut Swarm<ComposedBehaviour>, nodes: Vec<(Multiaddr, PeerId)>) {
    for node in nodes {
        swarm.behaviour_mut().kademlia.add_address(&node.1, node.0);
    }
}
