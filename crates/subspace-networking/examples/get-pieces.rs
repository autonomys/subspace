use futures::channel::mpsc;
use futures::StreamExt;
use libp2p::Multiaddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{crypto, U256};
use subspace_networking::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        value_getter: Arc::new(|_| None),
        //TODO: command
        bootstrap_nodes: vec![
            Multiaddr::from_str(
            "/ip4/192.168.1.215/tcp/10001/p2p/12D3KooWCShS9xyPw1tgpjEjUML9CTtY8J5Uy2MMKUFsUDui9u56",
        )
        .unwrap(),
            Multiaddr::from_str(
            "/ip4/192.168.1.215/tcp/10002/p2p/12D3KooWPwfKhaCqPPKFEN9qFxiP9z8VWW7AXV3NoemoC68QK6t9",
        ).unwrap()
        ],
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
    //let node_id_bytes = node_1.id().to_bytes();
    let raw_hashed_peer_id = crypto::sha256_hash(&node_1.id().to_bytes());
    let hashed_peer_id = U256::from_big_endian(&raw_hashed_peer_id);

    // let multihash = Multihash::from_bytes(&node_id_bytes).unwrap();
    // println!("Hash len: {:?}", multihash.digest().len());
    //let piece_index_hash = PieceIndexHash(node_id_bytes.as_slice()[0..SHA256_HASH_SIZE].try_into().unwrap());

    let stream_future = node_1.get_pieces_by_range(hashed_peer_id, hashed_peer_id);
    if let Ok(mut stream) = stream_future.await {
        while let Some(value) = stream.next().await {
            println!("Piece found: {:?}", value);
        }
    } else {
        println!("Stream error");
    }

    tokio::time::sleep(Duration::from_secs(3)).await;
}
