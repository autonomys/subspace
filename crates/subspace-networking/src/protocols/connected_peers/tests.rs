use crate::protocols::connected_peers::{Behaviour, Config, Event as ConnectedPeersEvent};
use futures::{select, FutureExt};
use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::core::Transport;
use libp2p::identity::{Keypair, PeerId};
use libp2p::plaintext::PlainText2Config;
use libp2p::swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent};
use libp2p::{yamux, Swarm};
use libp2p_swarm_test::SwarmExt;
use std::time::Duration;
use tokio::sync;

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

#[cfg(not(windows))]
fn get_delay_signal_channel() -> sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        // send a signal after the waiting
        tokio::time::sleep(LONG_DELAY).await;
        tx.send(()).unwrap();
    });

    rx
}

#[cfg(windows)]
fn get_delay_signal_channel() -> sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = sync::mpsc::unbounded_channel::<()>();

    std::thread::spawn(move || {
        std::thread::sleep(LONG_DELAY);
        tx.send(()).unwrap();
    });

    rx
}

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

    peer2.listen().await;
    peer1.connect(&mut peer2).await;

    let mut delay_signal = get_delay_signal_channel();

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = delay_signal.recv().fuse() => {
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

    peer2.listen().await;
    peer1.connect(&mut peer2).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), true);

    let mut delay_signal = get_delay_signal_channel();

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = delay_signal.recv().fuse() => {
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

    peer2.listen().await;
    peer1.connect(&mut peer2).await;

    peer1
        .behaviour_mut()
        .update_keep_alive_status(*peer2.local_peer_id(), true);
    peer2
        .behaviour_mut()
        .update_keep_alive_status(*peer1.local_peer_id(), false);

    let mut delay_signal = get_delay_signal_channel();

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = delay_signal.recv().fuse() => {
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
            ..Default::default()
        }),
    );

    peer1.listen().await;

    let mut delay_signal = get_delay_signal_channel();

    loop {
        select! {
            event = peer1.next_swarm_event().fuse() => {
                if matches!(event, SwarmEvent::Behaviour(ConnectedPeersEvent::<ConnectedPeersInstance>::NewDialingCandidatesRequested(..))){
                    break;
                }
            },
            _ = delay_signal.recv().fuse() => {
                panic!("No new peers requests.");
            }
        }
    }

    // We've received the new peers request when we don't have enough connected peers.
}

#[tokio::test()]
async fn test_target_connected_peer_limit_number() {
    let target_connected_peers = 1;

    let mut peer1 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            decision_timeout: DECISION_TIMEOUT,
            target_connected_peers,
            ..Default::default()
        }),
    );

    let mut peer2 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    let mut peer3 = new_ephemeral(
        DECISION_TIMEOUT,
        Behaviour::<ConnectedPeersInstance>::new(Config {
            target_connected_peers,
            decision_timeout: DECISION_TIMEOUT,
            ..Default::default()
        }),
    );

    peer2.listen().await;
    peer3.listen().await;

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

    let mut delay_signal = get_delay_signal_channel();

    loop {
        select! {
            _ = peer1.next_swarm_event().fuse() => {},
            _ = peer2.next_swarm_event().fuse() => {},
            _ = peer3.next_swarm_event().fuse() => {},
            _ = delay_signal.recv().fuse() => {
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
    let identity = Keypair::generate_ed25519();
    let peer_id = PeerId::from(identity.public());

    let transport = MemoryTransport::default()
        .or_transport(libp2p::tcp::tokio::Transport::default())
        .upgrade(Version::V1)
        .authenticate(PlainText2Config {
            local_public_key: identity.public(),
        })
        .multiplex(yamux::Config::default())
        .timeout(connection_timeout)
        .boxed();

    SwarmBuilder::without_executor(transport, behaviour, peer_id).build()
}
