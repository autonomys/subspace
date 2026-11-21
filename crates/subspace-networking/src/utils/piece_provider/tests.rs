use crate::protocols::request_response::handlers::cached_piece_by_index::{
    CachedPieceByIndexRequest, CachedPieceByIndexRequestHandler, CachedPieceByIndexResponse,
    ClosestPeers, PieceResult,
};
use crate::utils::multihash::ToMultihash;
use crate::utils::piece_provider::{KnownClosestPeers, NoPieceValidator, PieceProvider};
use crate::{Config, KademliaMode, Node, construct};
use async_lock::Semaphore;
use futures::channel::oneshot;
use libp2p::kad::{K_VALUE, KBucketKey, Mode};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::iter;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::pieces::{Piece, PieceIndex};

fn address(port: u16) -> Multiaddr {
    Multiaddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST)).with(Protocol::Tcp(port))
}

/// Starts a node in the background and returns it together with its `/p2p` address
async fn start_node(config: Config) -> (Node, Multiaddr) {
    let (node, mut node_runner) = construct(config).unwrap();

    let (address_sender, address_receiver) = oneshot::channel();
    let on_new_listener_handler = node.on_new_listener(Arc::new({
        let address_sender = Mutex::new(Some(address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_)))
                && let Some(address_sender) = address_sender.lock().take()
            {
                address_sender.send(address.clone()).unwrap();
            }
        }
    }));

    tokio::spawn(async move {
        node_runner.run().await;
    });

    let address = address_receiver.await.unwrap().with_p2p(node.id()).unwrap();
    drop(on_new_listener_handler);

    (node, address)
}

/// Starts a server node that responds to cached piece requests with `result`
async fn start_server(result: PieceResult) -> (Node, Multiaddr) {
    start_node(Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        kademlia_mode: KademliaMode::Static(Mode::Server),
        request_response_protocols: vec![CachedPieceByIndexRequestHandler::create(
            move |_, _: CachedPieceByIndexRequest| {
                let result = result.clone();

                async move {
                    Some(CachedPieceByIndexResponse {
                        result,
                        cached_pieces: Vec::new(),
                    })
                }
            },
        )],
        ..Config::default()
    })
    .await
}

/// Starts a client node bootstrapped from `server_address` and waits for it to be identified as a
/// server
async fn start_client(server_address: Multiaddr) -> PieceProvider<NoPieceValidator> {
    let (node, _address) = start_node(Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        bootstrap_addresses: vec![server_address],
        request_response_protocols: vec![CachedPieceByIndexRequestHandler::create(|_, _| async {
            None
        })],
        ..Config::default()
    })
    .await;

    tokio::time::timeout(Duration::from_secs(10), async {
        while node.connected_servers().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    PieceProvider::new(node, NoPieceValidator, Arc::new(Semaphore::new(1)))
}

#[tokio::test]
async fn get_piece_from_cache() {
    let piece_index = PieceIndex::ZERO;
    let piece = Piece::default();

    let (_server, server_address) = start_server(PieceResult::Piece(piece.clone())).await;
    let piece_provider = start_client(server_address).await;

    assert_eq!(
        piece_provider.get_piece_from_cache(piece_index).await,
        Some(piece)
    );
}

#[tokio::test]
async fn get_piece_from_cache_through_closest_peers() {
    let piece_index = PieceIndex::ZERO;
    let piece = Piece::default();

    let (holder, holder_address) = start_server(PieceResult::Piece(piece.clone())).await;
    let (_referrer, referrer_address) = start_server(PieceResult::ClosestPeers(
        ClosestPeers::from(vec![(holder.id(), vec![holder_address])]),
    ))
    .await;
    let piece_provider = start_client(referrer_address).await;

    assert_eq!(
        piece_provider.get_piece_from_cache(piece_index).await,
        Some(piece)
    );
}

#[test]
fn known_closest_peers_keeps_closest() {
    let local_peer_id = PeerId::random();
    let key = KBucketKey::from(PieceIndex::from(42).to_multihash());
    let mut known_closest_peers = KnownClosestPeers::new(key);

    let mut peer_ids = iter::repeat_with(PeerId::random)
        .take(K_VALUE.get() * 3)
        .collect::<Vec<_>>();
    for &peer_id in &peer_ids {
        known_closest_peers.add_peer(&local_peer_id, peer_id, vec![address(1)]);
    }

    peer_ids.sort_by_key(|peer_id| KBucketKey::from(*peer_id).distance(&key));
    assert_eq!(
        known_closest_peers
            .iter()
            .map(|(peer_id, _addresses)| *peer_id)
            .collect::<Vec<_>>(),
        peer_ids[..K_VALUE.get()]
    );
}

#[test]
fn known_closest_peers_ignores_local_and_without_addresses() {
    let local_peer_id = PeerId::random();
    let key = KBucketKey::from(PieceIndex::from(42).to_multihash());
    let mut known_closest_peers = KnownClosestPeers::new(key);

    known_closest_peers.add_peer(&local_peer_id, local_peer_id, vec![address(1)]);
    known_closest_peers.add_peer(&local_peer_id, PeerId::random(), Vec::new());

    assert_eq!(known_closest_peers.iter().count(), 0);
}

#[test]
fn known_closest_peers_merges_addresses() {
    let local_peer_id = PeerId::random();
    let peer_id = PeerId::random();
    let key = KBucketKey::from(PieceIndex::from(42).to_multihash());
    let mut known_closest_peers = KnownClosestPeers::new(key);

    known_closest_peers.add_peer(&local_peer_id, peer_id, vec![address(1), address(2)]);
    known_closest_peers.add_peer(&local_peer_id, peer_id, vec![address(2), address(3)]);

    assert_eq!(
        known_closest_peers.iter().collect::<Vec<_>>(),
        [(&peer_id, &vec![address(1), address(2), address(3)])]
    );
}
