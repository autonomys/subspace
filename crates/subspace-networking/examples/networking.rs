// TODO: Remove
#![allow(
    clippy::needless_return,
    reason = "https://github.com/rust-lang/rust-clippy/issues/13458"
)]
#![feature(type_changing_struct_update)]

use futures::channel::oneshot;
use futures::StreamExt;
use libp2p::gossipsub::Sha256Topic;
use libp2p::multiaddr::Protocol;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::Config;

const TOPIC: &str = "Foo";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        ..Config::default()
    };
    let (node_1, mut node_runner_1) = subspace_networking::construct(config_1).unwrap();

    println!("Node 1 ID is {}", node_1.id());

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

    let mut subscription = node_1.subscribe(Sha256Topic::new(TOPIC)).await.unwrap();

    let bootstrap_addresses = vec![node_1_addr.with(Protocol::P2p(node_1.id()))];
    let config_2 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        bootstrap_addresses,
        ..Config::default()
    };

    let (node_2, mut node_runner_2) = subspace_networking::construct(config_2).unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        node_2
            .publish(Sha256Topic::new(TOPIC), "hello".to_string().into_bytes())
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let message = subscription.next().await.unwrap();
    println!("Got message: {}", String::from_utf8_lossy(&message));

    tokio::time::sleep(Duration::from_secs(5)).await;
}
