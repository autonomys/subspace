use env_logger::Env;
use futures::channel::mpsc;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndexHash};
use subspace_networking::{Config, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        value_getter: Arc::new(|key| {
            // Return the reversed digest as a value
            Some(key.digest().iter().copied().rev().collect())
        }),
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
    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    println!("Node 1 ID is {}", node_1.id());

    let (node_1_addresses_sender, mut node_1_addresses_receiver) = mpsc::unbounded();
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

    let config_2 = Config {
        bootstrap_nodes: vec![node_1_addresses_receiver
            .next()
            .await
            .unwrap()
            .with(Protocol::P2p(node_1.id().into()))],
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_2, mut node_runner_2) = subspace_networking::create(config_2).await.unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        node_2
            .send_pieces_by_range_request(
                node_1.id(),
                PiecesByRangeRequest {
                    from: PieceIndexHash([1u8; 32]),
                    to: PieceIndexHash([1u8; 32]),
                },
            )
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
}
