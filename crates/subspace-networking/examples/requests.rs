use futures::channel::oneshot;
use libp2p::multiaddr::Protocol;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::protocols::request_response::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
use subspace_networking::Config;
use tokio::time::sleep;

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

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(
            |_, _example_request| async {
                sleep(Duration::from_secs(2)).await;

                println!("Request handler for request");
                Some(ExampleResponse)
            },
        )],
        ..Config::default()
    };
    let (node_1, mut node_runner_1) = subspace_networking::construct(config_1).unwrap();

    println!("Node 1 ID is {}", node_1.id());

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

    // Wait for first node to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let bootstrap_addresses = vec![node_1_addr.with(Protocol::P2p(node_1.id()))];
    let config_2 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        request_response_protocols: vec![GenericRequestHandler::<ExampleRequest>::create(
            |_, _| async { None },
        )],
        bootstrap_addresses,
        ..Config::default()
    };

    let (node_2, mut node_runner_2) = subspace_networking::construct(config_2).unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        let resp = node_2
            .send_generic_request(node_1.id(), Vec::new(), ExampleRequest)
            .await
            .unwrap();

        println!("Response: {resp:?}");
    });

    tokio::time::sleep(Duration::from_secs(3)).await;
}
