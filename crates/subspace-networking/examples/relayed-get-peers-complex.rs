use crate::identity::sr25519::Keypair;
use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use libp2p::multihash::{Code, MultihashDigest};
use libp2p::{identity, PeerId};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::{BootstrappedNetworkingParameters, Config};

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
    let mut expected_kaypair = Keypair::generate();

    const TOTAL_NODE_COUNT: usize = 100;
    const EXPECTED_NODE_INDEX: usize = 75;

    let mut nodes = Vec::with_capacity(TOTAL_NODE_COUNT);
    for i in 0..TOTAL_NODE_COUNT {
        let keypair = Keypair::generate();
        let config = Config {
            networking_parameters_registry: BootstrappedNetworkingParameters::new(
                bootstrap_nodes.clone(),
            )
            .boxed(),
            allow_non_globals_in_dht: true,
            ..Config::with_keypair(keypair.clone())
        };

        let (node, mut node_runner) = relay_node.spawn(config).await.unwrap();

        println!("Node {} ID is {}", i, node.id());

        if i == EXPECTED_NODE_INDEX {
            expected_node_id = node.id();
            expected_kaypair = keypair;
        }

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
        networking_parameters_registry: BootstrappedNetworkingParameters::new(
            bootstrap_nodes.clone(),
        )
        .boxed(),
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

    // Prepare multihash to look for in Kademlia
    let key = Code::Identity.digest(&expected_kaypair.public().encode());

    let peer_id = *node
        .get_closest_peers(key)
        .await
        .expect("get_closest_peers must return peers")
        .first()
        .expect("get_closest_peers returned zero peers");

    assert_eq!(peer_id, expected_node_id);
    println!("Expected Peer ID received.");

    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("Exiting..");
}
