use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::{
    BootstrappedNetworkingParameters, Config, GenericRequest, GenericRequestHandler, RelayMode,
};

#[derive(Encode, Decode)]
struct ExampleRequest;

impl GenericRequest for ExampleRequest {
    const PROTOCOL_NAME: &'static str = "/example";
    const LOG_TARGET: &'static str = "example_request";
    type Response = ExampleResponse;
}

#[derive(Encode, Decode, Debug)]
struct ExampleResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // NODE 1 - Relay
    let config_1 = Config {
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        relay_mode: RelayMode::Server,
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
        request_response_protocols: vec![GenericRequestHandler::create(|&ExampleRequest| {
            println!("Example request handler");
            Some(ExampleResponse)
        })],
        ..Config::with_generated_keypair()
    };
    let (node_2, mut node_runner_2) = node_1.spawn(config_2).await.unwrap();

    println!("Node 2 (server) ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    // NODE 3 - requester

    let config_3 = Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(vec![node_1_addr
            .with(Protocol::P2p(node_1.id().into()))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(node_2.id().into()))])
        .boxed(),
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(|_| None)],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_3, mut node_runner_3) = subspace_networking::create(config_3).await.unwrap();

    println!("Node 3 (requester) ID is {}", node_3.id());

    tokio::spawn(async move {
        node_runner_3.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let result = node_3
        .send_generic_request(node_2.id(), ExampleRequest)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("Received {:?}", result)
}
