use super::persistent_parameters::remove_known_peer_addresses_internal;
use crate::behavior::provider_storage::{instant_to_micros, micros_to_instant};
use crate::{BootstrappedNetworkingParameters, Config, GenericRequest, GenericRequestHandler};
use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

#[tokio::test()]
async fn test_address_timed_removal_from_known_peers_cache() {
    // Cache initialization
    let peer_id = PeerId::random();
    let addr1 = Multiaddr::empty().with(Protocol::Memory(0));
    let addr2 = Multiaddr::empty().with(Protocol::Memory(1));
    let addresses = vec![addr1.clone(), addr2.clone()];
    let expiration = chrono::Duration::nanoseconds(1);

    let mut peers_cache = LruCache::new(NonZeroUsize::new(100).unwrap());
    let mut addresses_cache = LruCache::new(NonZeroUsize::new(100).unwrap());

    for addr in addresses.clone() {
        addresses_cache.push(addr, None);
    }

    peers_cache.push(peer_id, addresses_cache);

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

    remove_known_peer_addresses_internal(&mut peers_cache, peer_id, addresses.clone(), expiration);

    // Check after the first run (set the first failure time)
    assert_eq!(peers_cache.len(), 1);
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

    remove_known_peer_addresses_internal(&mut peers_cache, peer_id, addresses, expiration);

    // Check after the second run (clean cache)
    assert_eq!(peers_cache.len(), 0);
}

#[test]
fn instant_conversion() {
    let inst1 = Instant::now();
    let ms = instant_to_micros(inst1);
    let inst2 = micros_to_instant(ms).unwrap();

    assert!(inst1.saturating_duration_since(inst2) < Duration::from_millis(1));
    assert!(inst2.saturating_duration_since(inst1) < Duration::from_millis(1));
}

#[test]
fn instant_conversion_edge_cases() {
    assert!(micros_to_instant(u64::MAX).is_none());
    assert!(micros_to_instant(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
            * 2
    )
    .is_none());
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
        request_response_protocols: vec![GenericRequestHandler::create(
            |_, &ExampleRequest| async {
                let fut = FuturePolledTwice::default();

                Some(ExampleResponse { counter: fut.await })
            },
        )],
        ..Config::default()
    };
    let (node_1, mut node_runner_1) = crate::create(config_1).unwrap();

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(node_1_address_sender) = node_1_address_sender.lock().take() {
                    node_1_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for first node to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let config_2 = Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(vec![
            node_1_addr.with(Protocol::P2p(node_1.id().into()))
        ])
        .boxed(),
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(
            |_, _| async { None },
        )],
        ..Config::default()
    };

    let (node_2, mut node_runner_2) = crate::create(config_2).unwrap();

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    node_2.wait_for_connected_peers().await.unwrap();

    let resp = node_2
        .send_generic_request(node_1.id(), ExampleRequest)
        .await
        .unwrap();

    assert_eq!(resp.counter, 1);
}
