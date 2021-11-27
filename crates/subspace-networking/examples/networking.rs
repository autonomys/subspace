use libp2p::identity::ed25519::Keypair;
use std::time::Duration;
use subspace_networking::{Config, Node};

#[tokio::main]
async fn main() {
    let mut config = Config::new(Keypair::generate());
    config.listen_on.push("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    let network = Node::create(config).unwrap();

    tokio::time::sleep(Duration::from_secs(5)).await;
}
