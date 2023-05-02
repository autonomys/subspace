use futures::channel::oneshot;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PieceIndex, PieceIndexHash};
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_announcement::announce_piece;
use subspace_networking::{BootstrappedNetworkingParameters, Config};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut bootstrap_nodes = Vec::new();

    const TOTAL_NODE_COUNT: usize = 30;

    let mut nodes = Vec::with_capacity(TOTAL_NODE_COUNT);
    for i in 0..TOTAL_NODE_COUNT {
        let config = Config {
            networking_parameters_registry: BootstrappedNetworkingParameters::new(
                bootstrap_nodes.clone(),
            )
            .boxed(),
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_global_addresses_in_dht: true,
            ..Config::default()
        };

        let (node, mut node_runner) = subspace_networking::create(config).unwrap();

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

        nodes.push(node);
    }

    let config = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(
            bootstrap_nodes.clone(),
        )
        .boxed(),
        ..Config::default()
    };

    let (node, mut node_runner) = subspace_networking::create(config).unwrap();

    tokio::spawn(async move {
        node_runner.run().await;
    });

    node.wait_for_connected_peers().await.unwrap();

    let piece_index = PieceIndex::ONE;
    let piece_index_hash = PieceIndexHash::from(piece_index);
    let key = piece_index_hash.to_multihash();

    announce_piece(piece_index, &node).await.unwrap();

    println!("Node announced key: {key:?}");

    tokio::time::sleep(Duration::from_secs(15)).await;

    let some_node = nodes.first().unwrap();
    let providers_result = match some_node.get_providers(key).await {
        Ok(stream) => Ok(stream.collect::<Vec<_>>().await),
        Err(error) => Err(error),
    };

    println!("Some Node get_piece_providers result: {providers_result:?}");

    tokio::time::sleep(Duration::from_secs(20)).await;

    let providers_result = match some_node.get_providers(key).await {
        Ok(stream) => Ok(stream.collect::<Vec<_>>().await),
        Err(error) => Err(error),
    };

    println!("Some Node get_piece_providers result: {providers_result:?}");

    println!("Exiting..");
}
