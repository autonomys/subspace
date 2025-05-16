use super::persistent_parameters::remove_known_peer_addresses_internal;
use crate::behavior::persistent_parameters::{append_p2p_suffix, remove_p2p_suffix};
use crate::protocols::request_response::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
use crate::{Config, KnownPeersManager, KnownPeersManagerConfig, KnownPeersRegistry};
use futures::channel::oneshot;
use futures::future::pending;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use schnellru::{ByLength, LruMap};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_address_timed_removal_from_known_peers_cache() {
    // Cache initialization
    let peer_id = PeerId::random();
    let addr1 = Multiaddr::empty().with(Protocol::Memory(0));
    let addr2 = Multiaddr::empty().with(Protocol::Memory(1));
    let addresses = vec![addr1.clone(), addr2.clone()];
    let expiration = Duration::from_nanos(1);
    let expiration_kademlia = Duration::from_nanos(1);

    let mut peers_cache = LruMap::new(ByLength::new(100));
    let mut addresses_cache = LruMap::new(ByLength::new(100));

    for addr in addresses.clone() {
        addresses_cache.insert(addr, None);
    }

    peers_cache.insert(peer_id, addresses_cache);

    //Precondition-check
    assert_eq!(peers_cache.len(), 1);
    let addresses_from_cache = peers_cache.get(&peer_id).expect("PeerId present");
    assert_eq!(addresses_from_cache.len(), 2);
    assert!(addresses_from_cache
        .peek(&addr1)
        .expect("Address present")
        .is_none());
    assert!(addresses_from_cache
        .peek(&addr2)
        .expect("Address present")
        .is_none());

    let removed_addresses = remove_known_peer_addresses_internal(
        &mut peers_cache,
        peer_id,
        addresses.clone(),
        expiration,
        expiration_kademlia,
    );

    // Check after the first run (set the first failure time)
    assert_eq!(peers_cache.len(), 1);
    assert_eq!(removed_addresses.len(), 0);
    let addresses_from_cache = peers_cache.get(&peer_id).expect("PeerId present");
    assert_eq!(addresses_from_cache.len(), 2);
    assert!(addresses_from_cache
        .peek(&addr1)
        .expect("Address present")
        .is_some());
    assert!(addresses_from_cache
        .peek(&addr2)
        .expect("Address present")
        .is_some());

    let removed_addresses = remove_known_peer_addresses_internal(
        &mut peers_cache,
        peer_id,
        addresses,
        expiration,
        expiration_kademlia,
    );

    // Check after the second run (clean cache)
    assert_eq!(peers_cache.len(), 0);
    assert_eq!(removed_addresses.len(), 2);
}

#[tokio::test]
async fn test_different_removal_timing_from_known_peers_cache() {
    // Cache initialization
    let peer_id = PeerId::random();
    let addr = Multiaddr::empty().with(Protocol::Memory(0));

    let expiration = Duration::from_secs(3);
    let expiration_kademlia = Duration::from_secs(1);

    let mut peers_cache = LruMap::new(ByLength::new(100));
    let mut addresses_cache = LruMap::new(ByLength::new(100));

    let addresses = vec![addr.clone()];
    addresses_cache.insert(addr, None);
    peers_cache.insert(peer_id, addresses_cache);

    //Precondition-check
    assert_eq!(peers_cache.len(), 1);

    let removed_addresses = remove_known_peer_addresses_internal(
        &mut peers_cache,
        peer_id,
        addresses.clone(),
        expiration,
        expiration_kademlia,
    );

    // Check after the first run (set the first failure time)
    assert_eq!(peers_cache.len(), 1);
    assert_eq!(removed_addresses.len(), 0);

    sleep(expiration_kademlia).await;

    let removed_addresses = remove_known_peer_addresses_internal(
        &mut peers_cache,
        peer_id,
        addresses.clone(),
        expiration,
        expiration_kademlia,
    );

    // Check after the second run (Kademlia event only)
    assert_eq!(peers_cache.len(), 1);
    assert_eq!(removed_addresses.len(), 1);

    sleep(expiration).await;

    let removed_addresses = remove_known_peer_addresses_internal(
        &mut peers_cache,
        peer_id,
        addresses,
        expiration,
        expiration_kademlia,
    );

    // Check after the third run (Kademlia event and clean cache)
    assert_eq!(peers_cache.len(), 0);
    assert_eq!(removed_addresses.len(), 1);
}

#[derive(Default)]
struct FuturePolledTwice {
    counter: u8,
}

impl Future for FuturePolledTwice {
    type Output = u8;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.counter >= 1 {
            Poll::Ready(self.counter)
        } else {
            self.get_mut().counter += 1;

            Poll::Pending
        }
    }
}

#[derive(Encode, Decode)]
struct ExampleRequest;

impl GenericRequest for ExampleRequest {
    const PROTOCOL_NAME: &'static str = "/example";
    const LOG_TARGET: &'static str = "example_request";
    type Response = ExampleResponse;
}

#[derive(Encode, Decode, Debug)]
struct ExampleResponse {
    counter: u8,
}

#[tokio::test]
async fn test_async_handler_works_with_pending_internal_future() {
    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(
            |_, _example_request| async {
                let fut = FuturePolledTwice::default();

                Some(ExampleResponse { counter: fut.await })
            },
        )],
        ..Config::default()
    };
    let (node_1, mut node_runner_1) = crate::construct(config_1).unwrap();

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_)))
                && let Some(node_1_address_sender) = node_1_address_sender.lock().take() {
                    node_1_address_sender.send(address.clone()).unwrap();
                }
        }
    }));

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for first node to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let bootstrap_addresses = vec![node_1_addr.with(Protocol::P2p(node_1.id()))];
    let config_2 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(
            |_, _| async { None },
        )],
        bootstrap_addresses,
        ..Config::default()
    };

    let (node_2, mut node_runner_2) = crate::construct(config_2).unwrap();

    tokio::spawn({
        let node = node_2.clone();

        async move {
            let _ = node.bootstrap().await;

            pending::<()>().await;
        }
    });

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    let resp = node_2
        .send_generic_request(node_1.id(), Vec::new(), ExampleRequest)
        .await
        .unwrap();

    assert_eq!(resp.counter, 1);
}

#[tokio::test]
async fn test_address_p2p_prefix_removal() {
    let short_addr: Multiaddr = "/ip4/127.0.0.1/tcp/50000".parse().unwrap();
    let long_addr: Multiaddr =
        "/ip4/127.0.0.1/tcp/50000/p2p/12D3KooWGAjyJAZNNsHu8sV6MP6mXHzNXFQbadjVBFUr5deTiom2"
            .parse()
            .unwrap();

    assert_eq!(remove_p2p_suffix(long_addr.clone()), short_addr);
    assert_eq!(remove_p2p_suffix(short_addr.clone()), short_addr);
}

#[tokio::test]
async fn test_address_p2p_prefix_addition() {
    let peer_id = PeerId::from_str("12D3KooWGAjyJAZNNsHu8sV6MP6mXHzNXFQbadjVBFUr5deTiom2").unwrap();
    let short_addr: Multiaddr = "/ip4/127.0.0.1/tcp/50000".parse().unwrap();
    let long_addr: Multiaddr =
        "/ip4/127.0.0.1/tcp/50000/p2p/12D3KooWGAjyJAZNNsHu8sV6MP6mXHzNXFQbadjVBFUr5deTiom2"
            .parse()
            .unwrap();

    assert_eq!(append_p2p_suffix(peer_id, long_addr.clone()), long_addr);
    assert_eq!(append_p2p_suffix(peer_id, short_addr.clone()), long_addr);
}

#[tokio::test]
async fn test_known_peers_removal_address_after_specified_interval() {
    let config = KnownPeersManagerConfig {
        enable_known_peers_source: false,
        cache_size: 100,
        ignore_peer_list: Default::default(),
        path: None,
        failed_address_cache_removal_interval: Duration::from_millis(100),
        ..Default::default()
    };
    let mut known_peers = KnownPeersManager::new(config).unwrap();
    let peer_id = PeerId::random();
    let mut address = Multiaddr::empty();
    address.push(Protocol::Tcp(10));

    known_peers
        .add_known_peer(peer_id, vec![address.clone()])
        .await;

    // We added address successfully.
    assert!(known_peers.contains_address(&peer_id, &address));

    known_peers
        .remove_known_peer_addresses(peer_id, vec![address.clone()])
        .await;

    // We didn't remove address instantly.
    assert!(known_peers.contains_address(&peer_id, &address));

    sleep(Duration::from_millis(110)).await;

    known_peers
        .remove_known_peer_addresses(peer_id, vec![address.clone()])
        .await;

    // We removed address after the configured interval.
    assert!(!known_peers.contains_address(&peer_id, &address));
}
