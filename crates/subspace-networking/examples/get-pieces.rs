use env_logger::Env;
use futures::channel::mpsc;
use futures::StreamExt;
use libp2p::{build_multiaddr, multiaddr, multihash::Multihash, Multiaddr};
use std::time::Duration;
use std::{str::FromStr, sync::Arc};
use subspace_core_primitives::{PieceIndexHash, SHA256_HASH_SIZE};
use subspace_networking::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        value_getter: Arc::new(|_| None),
        //TODO:
        bootstrap_nodes: vec![Multiaddr::from_str(
            "/ip4/192.168.1.215/tcp/10001/p2p/12D3KooWBWJzbLjFej9o86XhwJBXVuqFBfs2VWi6tYARkVoQjy9a",
        )
        .unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };
    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    println!("Node 1 ID is {}", node_1.id());

    let (node_1_addresses_sender, mut _node_1_addresses_receiver) = mpsc::unbounded();
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

    // TODO: correct node_id parsing
    let node_id_bytes = node_1.id().to_bytes();
    let multihash = Multihash::from_bytes(&node_id_bytes).unwrap();
    //let piece_index_hash = PieceIndexHash(node_id_bytes.as_slice()[0..SHA256_HASH_SIZE].try_into().unwrap());

    let stream_future = node_1.get_pieces_by_range(multihash.clone(), multihash);
    if let Ok(mut stream) = stream_future.await {
        while let Some(value) = stream.next().await {
            println!("Piece found: {:?}", value);
        }
    } else {
        println!("Stream error");
    }

    tokio::time::sleep(Duration::from_secs(3)).await;
}
