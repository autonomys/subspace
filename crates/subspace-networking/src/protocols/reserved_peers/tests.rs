use crate::protocols::reserved_peers::{Behaviour, Config};
use futures::{select, FutureExt};
use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::core::Transport;
use libp2p::identity::Keypair;
use libp2p::plaintext::Config as PlainTextConfig;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{yamux, Swarm, SwarmBuilder};
use libp2p_swarm_test::SwarmExt;
use std::time::Duration;
use tokio::time::sleep;

const DIALING_INTERVAL_IN_SECS: Duration = Duration::from_secs(1);

#[tokio::test]
async fn test_connection_breaks_after_timeout_without_reservation() {
    let connection_timeout = Duration::from_millis(300);
    let long_delay = Duration::from_millis(1000);

    let identity1 = Keypair::generate_ed25519();
    let mut peer1 = new_ephemeral(
        identity1,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: Vec::new(),
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    let identity2 = Keypair::generate_ed25519();
    let mut peer2 = new_ephemeral(
        identity2,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: Vec::new(),
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    peer1.listen().with_memory_addr_external().await;
    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(long_delay).fuse() => {
                break;
            }
        }
    }

    // Connections should timeout without reservation.
    assert!(!peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test]
async fn test_connection_reservation() {
    let connection_timeout = Duration::from_millis(300);
    let long_delay = Duration::from_millis(1000);

    let identity1 = Keypair::generate_ed25519();
    let identity2 = Keypair::generate_ed25519();

    let peer1_address = format!("/memory/0/p2p/{}", identity1.public().to_peer_id());
    let peer2_address = format!("/memory/0/p2p/{}", identity2.public().to_peer_id());

    let mut peer1 = new_ephemeral(
        identity1,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: vec![peer2_address.parse().unwrap()],
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    let mut peer2 = new_ephemeral(
        identity2,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: vec![peer1_address.parse().unwrap()],
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    peer1.listen().with_memory_addr_external().await;
    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(long_delay).fuse() => {
                break;
            }
        }
    }

    // Connections should be maintained with reservation.
    assert!(peer1.is_connected(peer2.local_peer_id()));
    assert!(peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test]
async fn test_connection_reservation_symmetry() {
    let connection_timeout = Duration::from_millis(300);
    let long_delay = Duration::from_millis(1000);

    let identity1 = Keypair::generate_ed25519();
    let identity2 = Keypair::generate_ed25519();

    let mut peer1 = new_ephemeral(
        identity1,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: vec![],
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    let (peer_1_memory_address, _) = peer1.listen().with_memory_addr_external().await;

    let mut peer2 = new_ephemeral(
        identity2,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: vec![peer_1_memory_address],
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(long_delay).fuse() => {
                break;
            }
        }
    }

    // Both peers should have a reservation for each other.
    assert!(!peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test]
async fn test_reserved_peers_dial_event() {
    let connection_timeout = Duration::from_millis(1300);
    let long_delay = Duration::from_millis(2000);

    let identity1 = Keypair::generate_ed25519();
    let identity2 = Keypair::generate_ed25519();

    let peer2_id = identity2.public().to_peer_id();
    let peer2_address = format!("/memory/0/p2p/{}", peer2_id);

    let mut peer1 = new_ephemeral(
        identity1,
        connection_timeout,
        Behaviour::new(Config {
            reserved_peers: vec![peer2_address.parse().unwrap()],
            dialing_interval: DIALING_INTERVAL_IN_SECS,
        }),
    );

    peer1.listen().with_memory_addr_external().await;

    select! {
        event = peer1.next_swarm_event().fuse() => {
            if let SwarmEvent::Dialing{peer_id, ..} = event{
                assert_eq!(peer_id, Some(peer2_id));
            }
        },
        _ = sleep(long_delay).fuse() => {
            panic!("No reserved peers dialing.");
        }
    }

    // We've received the reserved peer dialing event.
}

fn new_ephemeral<NB: NetworkBehaviour>(
    identity: Keypair,
    connection_timeout: Duration,
    behaviour: NB,
) -> Swarm<NB> {
    SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_other_transport(|identity| {
            MemoryTransport::default()
                .or_transport(libp2p::tcp::tokio::Transport::default())
                .upgrade(Version::V1)
                .authenticate(PlainTextConfig::new(identity))
                .multiplex(yamux::Config::default())
                .timeout(connection_timeout)
                .boxed()
        })
        .unwrap()
        .with_behaviour(move |_keypair| behaviour)
        .unwrap()
        .build()
}
