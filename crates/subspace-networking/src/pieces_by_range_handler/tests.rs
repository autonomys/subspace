use crate::{Config, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use libp2p::multiaddr::Protocol;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use subspace_core_primitives::{crypto, FlatPieces, Piece, PieceIndexHash};

#[tokio::test]
async fn pieces_by_range_protocol_smoke() {
    let request = PiecesByRangeRequest {
        from: PieceIndexHash([1u8; 32]),
        to: PieceIndexHash([1u8; 32]),
    };

    let piece_bytes: Vec<u8> = Piece::default().into();
    let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
    let pieces = PiecesToPlot {
        piece_indexes: vec![1],
        pieces: flat_pieces,
    };

    let response = PiecesByRangeResponse {
        pieces,
        next_piece_index_hash: None,
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
    let piece_index_from = PieceIndexHash(crypto::sha256_hash(b"from"));
    let piece_index_continue = PieceIndexHash(crypto::sha256_hash(b"continue"));
    let piece_index_end = PieceIndexHash(crypto::sha256_hash(b"end"));

    fn get_pieces_to_plot_mock(seed: u8) -> PiecesToPlot {
        let piece_bytes: Vec<u8> = [seed; 4096].to_vec();
        let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();

        PiecesToPlot {
            piece_indexes: vec![1],
            pieces: flat_pieces,
        }
    }

    static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

    let expected_data = vec![get_pieces_to_plot_mock(0), get_pieces_to_plot_mock(1)];
    let response_data = expected_data.clone();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        pieces_by_range_request_handler: Arc::new(move |req| {
            let request_index = REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);

            // Only two responses
            if request_index == 2 {
                return None;
            }

            if request_index == 0 {
                Some(PiecesByRangeResponse {
                    pieces: response_data[request_index].clone(),
                    next_piece_index_hash: Some(piece_index_continue),
                })
            } else {
                // New request starts from from the previous response.
                assert_eq!(req.from, piece_index_continue);

                Some(PiecesByRangeResponse {
                    pieces: response_data[request_index].clone(),
                    next_piece_index_hash: None,
                })
            }
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

    let mut stream = node_2
        .get_pieces_by_range(piece_index_from, piece_index_end)
        .await
        .unwrap();

    let mut result = Vec::new();
    while let Some(piece_plot) = stream.next().await {
        result.push(piece_plot);
    }

    assert_eq!(result, expected_data);
}
