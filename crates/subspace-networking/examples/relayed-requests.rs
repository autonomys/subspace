use env_logger::Env;
use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndexHash};
use subspace_networking::{Config, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    // NODE 1 - Relay
    let config_1 = Config {
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    println!("Node 1 (relay) ID is {}", node_1.id());

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(node_1_address_sender) = node_1_address_sender.lock().take() {
                    node_1_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for relay to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    // NODE 2 - Server

    let config_2 = Config {
        allow_non_globals_in_dht: true,
        pieces_by_range_request_handler: Arc::new(|req| {
            println!("Request handler for request: {:?}", req);

            let piece_bytes: Vec<u8> = Piece::default().into();
            let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
            let pieces = PiecesToPlot {
                piece_indexes: vec![1],
                pieces: flat_pieces,
            };

            Some(PiecesByRangeResponse {
                pieces,
                next_piece_index_hash: None,
            })
        }),
        ..Config::with_generated_keypair()
    };
    let (node_2, mut node_runner_2) = node_1.spawn(config_2).await.unwrap();

    println!("Node 2 (server) ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    // NODE 3 - requester

    let config_3 = Config {
        bootstrap_nodes: vec![node_1_addr
            .with(Protocol::P2p(node_1.id().into()))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(node_2.id().into()))],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_3, mut node_runner_3) = subspace_networking::create(config_3).await.unwrap();

    println!("Node 3 (requester) ID is {}", node_3.id());

    tokio::spawn(async move {
        node_runner_3.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        node_3
            .send_pieces_by_range_request(
                node_2.id(),
                PiecesByRangeRequest {
                    from: PieceIndexHash([1u8; 32]),
                    to: PieceIndexHash([1u8; 32]),
                },
            )
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_secs(3)).await;
}
