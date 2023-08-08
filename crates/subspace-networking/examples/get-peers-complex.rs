use futures::channel::oneshot;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::PeerId;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::utils::multihash::Multihash;
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
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_global_addresses_in_dht: true,
            bootstrap_addresses: bootstrap_nodes.clone(),
            ..Config::default()
        };

        let (node, mut node_runner) = subspace_networking::create(config).unwrap();

        println!("Node {} ID is {}", i, node.id());

        if i == EXPECTED_NODE_INDEX {
            expected_node_id = node.id();
        }

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

        let address = node_addr.with(Protocol::P2p(node.id()));

        bootstrap_nodes.push(address);

        nodes.push(node);
    }

    let file_path = std::env::temp_dir()
        .join("subspace_example_networking_params.bin")
        .into_boxed_path();

    println!(
        "Networking parameters database path used (the app creates file on the first run): \
        {file_path:?}"
    );

    let config = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        networking_parameters_registry: Some(
            NetworkingParametersManager::new(file_path.as_ref(), Default::default())
                .unwrap()
                .boxed(),
        ),
        bootstrap_addresses: bootstrap_nodes,
        ..Config::default()
    };

    let (node, mut node_runner) = subspace_networking::create(config).unwrap();

    println!("Source Node ID is {}", node.id());
    println!("Expected Peer ID:{expected_node_id}");

    tokio::spawn(async move {
        node_runner.run().await;
    });

    // Prepare multihash to look for in Kademlia
    let key = Multihash::from(node.id());

    let peers = node
        .get_closest_peers(key)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;

    // Uncomment on debugging:
    // println!("Received closest peers: {:?}", peers);

    let peer_id = peers
        .first()
        .expect("get_closest_peers must return non-empty set.");
    assert_eq!(peer_id, &expected_node_id);
    println!("Expected Peer ID received.");

    tokio::time::sleep(Duration::from_secs(120)).await;

    println!("Exiting..");
}
