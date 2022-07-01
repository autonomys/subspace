use env_logger::Env;
use futures::StreamExt;
use libp2p::gossipsub::Sha256Topic;
use libp2p::Multiaddr;
use std::time::Duration;
use subspace_networking::{Config, RelayConfiguration};

const TOPIC: &str = "Foo";

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    // NODE 1 - Relay
    let node_1_addr: Multiaddr = "/ip4/127.0.0.1/tcp/50000".parse().unwrap();
    let config_1 = Config {
        listen_on: vec![node_1_addr.clone()],
        allow_non_globals_in_dht: true,
        relay_config: RelayConfiguration::default_server_configuration(),
        ..Config::with_generated_keypair()
    };

    let (node_1, node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    println!("Node 1 (relay) ID is {}", node_1.id());

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // NODE 2 - Server

    let config_2 = Config {
        allow_non_globals_in_dht: true,
        relay_config: node_1
            .configure_relay_client()
            .expect("Relay Server should be configured."),
        ..Config::with_generated_keypair()
    };
    let (node_2, node_runner_2) = subspace_networking::create(config_2).await.unwrap();

    println!("Node 2 (server) ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    let mut subscription = node_2.subscribe(Sha256Topic::new(TOPIC)).await.unwrap();

    // NODE 3 - requester

    let config_3 = Config {
        bootstrap_nodes: vec![format!(
            "{}/p2p/{}/p2p-circuit/p2p/{}",
            node_1_addr.clone(),
            node_1.id(),
            node_2.id()
        )
        .try_into()
        .unwrap()],
        allow_non_globals_in_dht: true,
        relay_config: RelayConfiguration::ClientInitiator,
        ..Config::with_generated_keypair()
    };

    let (node_3, node_runner_3) = subspace_networking::create(config_3).await.unwrap();

    println!("Node 3 (requester) ID is {}", node_3.id());

    tokio::spawn(async move {
        node_runner_3.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        node_3
            .publish(Sha256Topic::new(TOPIC), "hello".to_string().into_bytes())
            .await
            .unwrap();
    });

    let message = subscription.next().await.unwrap();
    println!("Got message: {}", String::from_utf8_lossy(&message));

    tokio::time::sleep(Duration::from_secs(3)).await;
}
