use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Code;
use libp2p::PeerId;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{crypto, PieceIndexHash, U256};
use subspace_networking::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Relay node
    let config_1 = Config {
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (relay_node, mut relay_node_runner) = subspace_networking::create(config_1).await.unwrap();

    println!("Relay Node ID is {}", relay_node.id());

    let (relay_node_address_sender, relay_node_address_receiver) = oneshot::channel();
    let on_new_listener_handler = relay_node.on_new_listener(Arc::new({
        let relay_node_address_sender = Mutex::new(Some(relay_node_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(relay_node_address_sender) = relay_node_address_sender.lock().take() {
                    relay_node_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn(async move {
        relay_node_runner.run().await;
    });

    // Wait for relay to know its address
    let relay_node_addr = relay_node_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let mut bootstrap_nodes = Vec::new();
    let mut expected_node_id = PeerId::random();

    const TOTAL_NODE_COUNT: usize = 100;
    const EXPECTED_NODE_INDEX: usize = 75;

    let mut nodes = Vec::with_capacity(TOTAL_NODE_COUNT);
    for i in 0..TOTAL_NODE_COUNT {
        let config = Config {
            bootstrap_nodes: bootstrap_nodes.clone(),
            allow_non_globals_in_dht: true,
            ..Config::with_generated_keypair()
        };
        let (node, mut node_runner) = relay_node.spawn(config).await.unwrap();

        println!("Node {} ID is {}", i, node.id());

        tokio::spawn(async move {
            node_runner.run().await;
        });

        tokio::time::sleep(Duration::from_millis(40)).await;

        let address = relay_node_addr
            .clone()
            .with(Protocol::P2p(relay_node.id().into()))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(node.id().into()));

        bootstrap_nodes.push(address);

        if i == EXPECTED_NODE_INDEX {
            expected_node_id = node.id();
        }

        nodes.push(node);
    }

    // Debug:
    // println!("Bootstrap NODES: {:?}", bootstrap_nodes);

    let config = Config {
        bootstrap_nodes,
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node, mut node_runner) = subspace_networking::create(config).await.unwrap();

    println!("Source Node ID is {}", node.id());
    println!("Expected Peer ID:{}", expected_node_id);

    tokio::spawn(async move {
        node_runner.run().await;
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let hashed_peer_id = PieceIndexHash::from(crypto::sha256_hash(&expected_node_id.to_bytes()));
    let key = libp2p::multihash::MultihashDigest::digest(
        &Code::Identity,
        &U256::from(hashed_peer_id).to_be_bytes(),
    );
    let peer_id = node.get_closest_peers(key).await.unwrap()[0];
    assert_eq!(peer_id, expected_node_id);

    println!("Exiting..");
}
