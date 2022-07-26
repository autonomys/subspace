use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use libp2p::PeerId;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::{Config, NetworkingParametersManager};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut bootstrap_nodes = Vec::new();
    let mut expected_node_id = PeerId::random();

    const TOTAL_NODE_COUNT: usize = 100;
    const EXPECTED_NODE_INDEX: usize = 75;

    let mut nodes = Vec::with_capacity(TOTAL_NODE_COUNT);
    for i in 0..TOTAL_NODE_COUNT {
        let config = Config {
            bootstrap_nodes: bootstrap_nodes.clone(),
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_globals_in_dht: true,
            ..Config::with_generated_keypair()
        };
        let (node, mut node_runner) = subspace_networking::create(config).await.unwrap();

        println!("Node {} ID is {}", i, node.id());

        let (node_address_sender, node_address_receiver) = oneshot::channel();
        let _handler = node.on_new_listener(Arc::new({
            let node_address_sender = Mutex::new(Some(node_address_sender));

            move |address| {
                if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                    if let Some(node_address_sender) = node_address_sender.lock().take() {
                        node_address_sender.send(address.clone()).unwrap();
                    }
                }
            }
        }));

        tokio::spawn(async move {
            node_runner.run().await;
        });

        // Wait for node to know its address
        let node_addr = node_address_receiver.await.unwrap();

        tokio::time::sleep(Duration::from_millis(40)).await;

        let address = node_addr.with(Protocol::P2p(node.id().into()));

        bootstrap_nodes.push(address);

        if i == EXPECTED_NODE_INDEX {
            expected_node_id = node.id();
        }
        nodes.push(node);
    }

    let db_path = std::env::temp_dir()
        .join("subspace_example_networking_params_db")
        .into_boxed_path();

    println!(
        "Networking parameters database path used (the app creates DB on the first run): {:?}",
        db_path
    );

    let config = Config {
        bootstrap_nodes,
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        networking_parameters_registry: NetworkingParametersManager::new(db_path.as_ref())
            .unwrap()
            .boxed(),
        ..Config::with_generated_keypair()
    };

    let (node, mut node_runner) = subspace_networking::create(config).await.unwrap();

    println!("Source Node ID is {}", node.id());
    println!("Expected Peer ID:{}", expected_node_id);

    tokio::spawn(async move {
        node_runner.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let peers = node
        .get_closest_peers(expected_node_id.into())
        .await
        .unwrap();

    println!("Received closest peers: {:?}", peers);

    let peer_id = peers.first().unwrap();
    assert_eq!(*peer_id, expected_node_id);

    tokio::time::sleep(Duration::from_secs(12)).await;

    println!("Exiting..");
}
