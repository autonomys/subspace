#![feature(type_changing_struct_update)]

use futures::channel::oneshot;
use futures::StreamExt;
use libp2p::gossipsub::Sha256Topic;
use libp2p::multiaddr::Protocol;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::Blake2b256Hash;
use subspace_networking::{
    BootstrappedNetworkingParameters, Config, CustomRecordStore, GetOnlyRecordStorage,
    MemoryProviderStorage,
};

const TOPIC: &str = "Foo";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_1 = Config::<CustomRecordStore<GetOnlyRecordStorage, MemoryProviderStorage>> {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        record_store: CustomRecordStore::new(
            GetOnlyRecordStorage::new(Arc::new(|key| {
                // Return the reversed digest as a value
                Some(key.digest().iter().copied().rev().collect())
            })),
            MemoryProviderStorage::default(),
        ),
        allow_non_global_addresses_in_dht: true,
        ..Config::with_generated_keypair()
    };
    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

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

    let mut subscription = node_1.subscribe(Sha256Topic::new(TOPIC)).await.unwrap();

    let config_2 = Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(vec![
            node_1_addr.with(Protocol::P2p(node_1.id().into()))
        ])
        .boxed(),
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        ..Config::with_generated_keypair()
    };

    let (node_2, mut node_runner_2) = subspace_networking::create(config_2).await.unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let key = subspace_networking::utils::multihash::create_multihash_by_piece(
        &Blake2b256Hash::default(),
        1,
    );
    println!("Get value result for:");
    println!("Key: {key:?}");
    let result = node_2.get_value(key).await.unwrap().next().await;
    println!("Value: {result:?}");

    tokio::spawn(async move {
        node_2
            .publish(Sha256Topic::new(TOPIC), "hello".to_string().into_bytes())
            .await
            .unwrap();
    });

    let message = subscription.next().await.unwrap();
    println!("Got message: {}", String::from_utf8_lossy(&message));

    tokio::time::sleep(Duration::from_secs(5)).await;
}
