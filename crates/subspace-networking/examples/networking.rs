use libp2p::identity::ed25519::Keypair;
use std::time::Duration;
use subspace_networking::{Config, Node};

#[tokio::main]
async fn main() {
    let mut config_1 = Config::new(Keypair::generate());
    config_1
        .listen_on
        .push("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    let (node_1, mut node_runner_1) = Node::create(config_1).await.unwrap();
    let node_1_id = node_1.id();

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut config_2 = Config::new(Keypair::generate());
    config_2
        .listen_on
        .push("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    config_2.bootstrap_nodes = node_1
        .addresses()
        .into_iter()
        .map(|address| ((node_1_id, address)))
        .collect();

    let (node_2, mut node_runner_2) = Node::create(config_2).await.unwrap();

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
}
