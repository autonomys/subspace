// Pull imports from the parent module
use super::*;

const BOOTNODES: [&str; 3] = [
    "/ip4/192.186.0.0/tcp/9997",
    "/ip4/192.186.0.0/tcp/9998",
    "/ip4/192.186.0.0/tcp/9999",
];

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

pub async fn create_swarm(bootstrap: bool) -> Swarm<ComposedBehaviour> {
    // Generate IDs.
    let key = identity::Keypair::generate_ed25519();
    let peerid = PeerId::from_public_key(key.public());

    // Generate NOISE authentication keys.
    let auth_keys = Keypair::<X25519Spec>::new().into_authentic(&key).unwrap();

    // Create secure-TCP transport that uses tokio under the hood.
    let transport = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let behaviour = ComposedBehaviour {
        kademlia: Kademlia::new(peerid.clone(), MemoryStore::new(peerid.clone())),
    };

    let mut swarm = SwarmBuilder::new(transport, behaviour, peerid.clone())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    if bootstrap {
        set_bootstrap(&mut swarm);
    } else {
        dial_bootstrap(&mut swarm);
    }

    swarm
}

fn set_bootstrap(swarm: &mut Swarm<ComposedBehaviour>) {
    info!("I'm a bootstrap node.\n");
    for node in &BOOTNODES {
        let addr: Multiaddr = node.clone().parse().unwrap();
        match swarm.dial_addr(addr.clone()) {
            Err(_) => {
                swarm.listen_on(addr.clone()).unwrap();
                info!("My Peer ID is: {:?}\n", swarm.local_peer_id());
                info!("My address is: {:?}\n", addr);
                break;
            }
            _ => continue,
        }
    }
}

fn dial_bootstrap(swarm: &mut Swarm<ComposedBehaviour>) {
    for node in BOOTNODES {
        let addr: Multiaddr = node.clone().parse().unwrap();
        // swarm.behaviour_mut().kademlia.add_address(addr);
    }
}
