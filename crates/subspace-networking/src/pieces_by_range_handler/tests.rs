use crate::{Config, PiecesByRangeRequest, PiecesByRangeResponse};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use libp2p::multiaddr::Protocol;
use std::sync::Arc;
use subspace_core_primitives::{crypto, FlatPieces, Piece, PieceIndexHash, PiecesToPlot};

#[tokio::test]
async fn pieces_by_range_protocol_smoke() {
    let request = PiecesByRangeRequest {
        from: PieceIndexHash([1u8; 32]),
        to: PieceIndexHash([1u8; 32]),
        next_piece_hash_index: None,
    };

    let piece_bytes: Vec<u8> = Piece::default().into();
    let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
    let pieces = PiecesToPlot {
        piece_indexes: vec![1],
        pieces: flat_pieces,
    };

    let response = PiecesByRangeResponse {
        pieces,
        next_piece_hash_index: None,
    };

    let expected_request = request.clone();
    let expected_response = response.clone();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        pieces_by_range_request_handler: Arc::new(move |req| {
            assert_eq!(*req, expected_request);

            Some(expected_response.clone())
        }),
        ..Config::with_generated_keypair()
    };
    let (node_1, node_runner_1) = crate::create(config_1).await.unwrap();

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

    let (node_2, node_runner_2) = crate::create(config_2).await.unwrap();
    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    let (mut result_sender, mut result_receiver) = mpsc::unbounded();
    tokio::spawn(async move {
        let resp = node_2
            .send_pieces_by_range_request(node_1.id(), request)
            .await
            .unwrap();

        result_sender.send(resp).await.unwrap();
    });

    let resp = result_receiver.next().await.unwrap();
    assert_eq!(resp, response);
}

#[tokio::test]
async fn get_pieces_by_range_smoke() {
    let piece_bytes: Vec<u8> = Piece::default().into();
    let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
    let pieces = PiecesToPlot {
        piece_indexes: vec![1],
        pieces: flat_pieces,
    };

    let expected_data = pieces.clone();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        pieces_by_range_request_handler: Arc::new(move |_| {
            Some(PiecesByRangeResponse {
                pieces: pieces.clone(),
                next_piece_hash_index: None,
            })
        }),
        ..Config::with_generated_keypair()
    };
    let (node_1, node_runner_1) = crate::create(config_1).await.unwrap();

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

    let (node_2, node_runner_2) = crate::create(config_2).await.unwrap();
    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    let hashed_peer_id = PieceIndexHash(crypto::sha256_hash(&node_1.id().to_bytes()));

    let mut stream = node_2
        .get_pieces_by_range(hashed_peer_id, hashed_peer_id)
        .await
        .unwrap();

    let result = stream.next().await;

    assert_eq!(result.unwrap(), expected_data);
}
