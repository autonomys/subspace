use env_logger::Env;
use futures::channel::mpsc;
use futures::StreamExt;
use libp2p::gossipsub::Sha256Topic;
use libp2p::multiaddr::Protocol;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::Sha256Hash;
use subspace_networking::Config;

const TOPIC: &str = "Foo";

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        value_getter: Arc::new(|key| {
            // Return the reversed digest as a value
            Some(key.digest().iter().copied().rev().collect())
        }),
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };
    let (node_1, node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    println!("Node 1 ID is {}", node_1.id());

    let (node_1_addresses_sender, mut node_1_addresses_receiver) = mpsc::unbounded();
    node_1
        .on_new_listener(Arc::new(move |address| {
            node_1_addresses_sender
                .unbounded_send(address.clone())
                .unwrap();
        }))
        .detach();

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    let mut subscription = node_1.subscribe(Sha256Topic::new(TOPIC)).await.unwrap();

    let config_2 = Config {
        bootstrap_nodes: vec![node_1_addresses_receiver
            .next()
            .await
            .unwrap()
            .with(Protocol::P2p(node_1.id().into()))],
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_2, node_runner_2) = subspace_networking::create(config_2).await.unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let key = subspace_networking::multimess::create_piece_multihash(&Sha256Hash::default(), 1);
    println!("Get value result for:");
    println!("Key: {key:?}");
    let result = node_2.get_value(key).await;
    println!("Value: {result:?}");

    tokio::spawn(async move {
        node_2
            .publish(Sha256Topic::new(TOPIC), "hello".to_string().into_bytes())
            .await
            .unwrap();
    });

    let message = subscription.next().await.unwrap();
    println!("Got message: {}", String::from_utf8_lossy(&message));

    tokio::time::sleep(Duration::from_secs(5)).await;
}
