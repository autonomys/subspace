use crate::protocols::connected_peers::{Behaviour, Config, Event as ConnectedPeersEvent};
use futures::{select, FutureExt};
use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::core::Transport;
use libp2p::plaintext::Config as PlainTextConfig;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{yamux, Swarm, SwarmBuilder};
use libp2p_swarm_test::SwarmExt;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
struct ConnectedPeersInstance;

#[cfg(not(windows))]
const DECISION_TIMEOUT: Duration = Duration::from_millis(300);
#[cfg(not(windows))]
const LONG_DELAY: Duration = Duration::from_millis(1000);

// Windows implementation seems to require greater delays.
#[cfg(windows)]
const DECISION_TIMEOUT: Duration = Duration::from_millis(900);
#[cfg(windows)]
const LONG_DELAY: Duration = Duration::from_millis(3000);

#[tokio::test()]
async fn test_connection_breaks_after_timeout_without_decision() {
    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // Connections should timeout without decisions.
    assert!(!peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test()]
async fn test_connection_decision() {
    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // Connections should be maintained after positive decisions.
    assert!(peer1.is_connected(peer2.local_peer_id()));
    assert!(peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test()]
async fn test_connection_decision_symmetry() {
    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer2.listen().with_memory_addr_external().await;
    peer1.connect(&mut peer2).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), false);

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // Both peers should approve the connection to make it permanent
    assert!(!peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer2.is_connected(peer1.local_peer_id()));
}

#[tokio::test()]
async fn test_new_peer_request() {
    let dialing_interval = DECISION_TIMEOUT;

    let mut peer1 = new_ephemeral(
        dialing_interval,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            dialing_interval,
            target_connected_peers: 1,
            ..Default::default()
        }),
    );

    peer1.listen().with_memory_addr_external().await;

    let waiting_for_event_fut = async {
        while !matches!(
            peer1.next_swarm_event().await,
            SwarmEvent::Behaviour(
                ConnectedPeersEvent::<ConnectedPeersInstance>::NewDialingCandidatesRequested(..)
            )
        ) {
            // Wait for interesting event
        }
    };

    select! {
        _ = waiting_for_event_fut.fuse() => {},
        _ = sleep(LONG_DELAY).fuse() => {
            panic!("No new peers requests");
        }
    }

    // We've received the new peers request when peer cache is empty
}

#[tokio::test()]
async fn test_target_connected_peer_limit_number() {
    let max_connected_peers = 1;

    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers: 1,
            max_connected_peers,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers: 0,
            max_connected_peers,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer3 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers: 0,
            max_connected_peers,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer2.listen().with_memory_addr_external().await;
    peer3.listen().with_memory_addr_external().await;

    peer1.connect(&mut peer2).await;
    peer1.connect(&mut peer3).await;

    peer2.connect(&mut peer3).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer3.local_peer_id(), true);

    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer3.local_peer_id(), true);

    peer3
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);
    peer3
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = peer3.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // We don't maintain with new peers when we have enough connected peers.
    // Peer1 has a slot with peer2
    assert!(peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer1.is_connected(peer3.local_peer_id()));

    // Peer2 has a slot with peer2
    assert!(peer2.is_connected(peer1.local_peer_id()));
    assert!(!peer2.is_connected(peer3.local_peer_id()));

    // Peer3 doesn't have connection slots because "target_connected_peers = 1"
    assert!(!peer3.is_connected(peer1.local_peer_id()));
    assert!(!peer3.is_connected(peer2.local_peer_id()));
}

fn new_ephemeral<NB: NetworkBehaviour>(connection_timeout: Duration, behaviour: NB) -> Swarm<NB> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|keypair| {
            MemoryTransport::default()
                .or_transport(libp2p::tcp::tokio::Transport::default())
                .upgrade(Version::V1)
                .authenticate(PlainTextConfig::new(keypair))
                .multiplex(yamux::Config::default())
                .timeout(connection_timeout)
                .boxed()
        })
        .unwrap()
        .with_behaviour(move |_keypair| behaviour)
        .unwrap()
        .build()
}

#[tokio::test()]
async fn test_connection_type_difference() {
    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers: 0,
            max_connected_peers: 1,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers: 1,
            max_connected_peers: 1,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer1.listen().with_memory_addr_external().await;
    peer2.listen().with_memory_addr_external().await;

    peer1.connect(&mut peer2).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // Peer1 doesn't have enough slots for outgoing connections
    assert!(!peer1.is_connected(peer2.local_peer_id()));
    assert!(!peer2.is_connected(peer1.local_peer_id()));

    peer2.connect(&mut peer1).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = sleep(LONG_DELAY).fuse() => {
                break;
            }
        }
    }

    // Peer2 has enough slots for outgoing connections
    assert!(peer1.is_connected(peer2.local_peer_id()));
    assert!(peer2.is_connected(peer1.local_peer_id()));
}
