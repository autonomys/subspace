use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::{identity, Multiaddr, PeerId};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndexHash};
use subspace_networking::{
    Config, PiecesByRangeResponse, PiecesToPlot, RelayConfiguration, RelayLimitSettings,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let relay_server_address = Multiaddr::empty().with(Protocol::Memory(1_000_000_000));

    // Relay node
    let relay_node_addr: Multiaddr = "/ip4/127.0.0.1/tcp/50000".parse().unwrap();
    let config_1 = Config {
        listen_on: vec![relay_node_addr.clone()],
        allow_non_globals_in_dht: true,
        relay_config: RelayConfiguration::Server(relay_server_address.clone(), relay_config()),
        ..Config::with_generated_keypair()
    };

    let (relay_node, relay_node_runner) = subspace_networking::create(config_1).await.unwrap();

    println!("Relay Node ID is {}", relay_node.id());

    tokio::spawn(async move {
        relay_node_runner.run().await;
    });

    let mut bootstrap_nodes = Vec::new();
    let mut expected_node_id = PeerId::random();

    const TOTAL_NODE_COUNT: usize = 100;
    const EXPECTED_NODE_INDEX: usize = 75;

    let expected_response = {
        let piece_bytes: Vec<u8> = Piece::default().into();
        let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
        let pieces = PiecesToPlot {
            piece_indexes: vec![1],
            pieces: flat_pieces,
        };

        PiecesByRangeResponse {
            pieces,
            next_piece_index_hash: None,
        }
    };

    for i in 0..TOTAL_NODE_COUNT {
        let local_response = expected_response.clone();
        let config = Config {
            bootstrap_nodes: bootstrap_nodes.clone(),
            allow_non_globals_in_dht: true,
            pieces_by_range_request_handler: Arc::new(move |_| {
                if i != EXPECTED_NODE_INDEX {
                    return None;
                }

                println!("Sending response from Node Index {}... ", i);

                std::thread::sleep(Duration::from_secs(1));
                Some(local_response.clone())
            }),
            relay_config: relay_node
                .configure_relay_client()
                .expect("Server should be configured."),
            ..Config::with_generated_keypair()
        };
        let (node, node_runner) = subspace_networking::create(config).await.unwrap();

        println!("Node {} ID is {}", i, node.id());

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
    }

    // Debug:
    // println!("Bootstrap NODES: {:?}", bootstrap_nodes);

    let config = Config {
        bootstrap_nodes,
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        relay_config: RelayConfiguration::ClientInitiator,
        ..Config::with_generated_keypair()
    };

    let (node, node_runner) = subspace_networking::create(config).await.unwrap();

    println!("Source Node ID is {}", node.id());
    println!("Expected Peer ID:{}", expected_node_id);

    tokio::spawn(async move {
        node_runner.run().await;
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let encoding = expected_node_id.as_ref().digest();
    let public_key = identity::PublicKey::from_protobuf_encoding(encoding)
        .expect("Invalid public key from PeerId.");
    let peer_id_public_key = if let identity::PublicKey::Sr25519(pk) = public_key {
        pk.encode()
    } else {
        panic!("Expected PublicKey::Sr25519")
    };

    // create a range from expected peer's public key
    let from = {
        let mut buf = peer_id_public_key;
        buf[16] = 0;
        PieceIndexHash(buf)
    };
    let to = {
        let mut buf = peer_id_public_key;
        buf[16] = 50;
        PieceIndexHash(buf)
    };

    let stream_future = node.get_pieces_by_range(from, to);
    let mut stream = stream_future.await.unwrap();
    if let Some(value) = stream.next().await {
        if value != expected_response.pieces {
            panic!("UNEXPECTED RESPONSE")
        }

        println!("Received expected response.");
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Exiting..");
}

fn relay_config() -> RelayLimitSettings {
    RelayLimitSettings {
        max_reservations: 128000,
        max_reservations_per_peer: 128000,
        reservation_duration: Duration::from_secs(60 * 60),
        max_circuits: 128000,
        max_circuits_per_peer: 128000,
        max_circuit_duration: Duration::from_secs(2 * 60),
        max_circuit_bytes: 1 << 27,
    }
}
