use futures::channel::oneshot;
use futures::{FutureExt, StreamExt, select};
use libp2p::PeerId;
use libp2p::metrics::Metrics;
use libp2p::multiaddr::Protocol;
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::time::Duration;
use subspace_metrics::{RegistryAdapter, start_prometheus_metrics_server};
use subspace_networking::utils::shutdown_signal;
use subspace_networking::{Config, Node};
use subspace_process::init_logger;
use tokio::time::sleep;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    init_logger();
    let mut metric_registry = Registry::default();
    let metrics = Metrics::new(&mut metric_registry);

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: true,
        libp2p_metrics: Some(metrics),
        ..Config::default()
    };
    let (node_1, mut node_runner_1) = subspace_networking::construct(config_1).unwrap();

    // Init prometheus
    let prometheus_metrics_server_address = "127.0.0.1:63000".parse().unwrap();

    match start_prometheus_metrics_server(
        vec![prometheus_metrics_server_address],
        RegistryAdapter::PrometheusClient(metric_registry),
    ) {
        Err(err) => {
            error!(
                ?prometheus_metrics_server_address,
                ?err,
                "Prometheus metrics server failed to start."
            );

            return;
        }
        Ok(prometheus_task) => {
            tokio::task::spawn(prometheus_task);
        }
    }

    println!("Node 1 ID is {}", node_1.id());

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_)))
                && let Some(node_1_address_sender) = node_1_address_sender.lock().take()
            {
                node_1_address_sender.send(address.clone()).unwrap();
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
        bootstrap_addresses,
        ..Config::default()
    };

    let (node_2, mut node_runner_2) = subspace_networking::construct(config_2).unwrap();

    println!("Node 2 ID is {}", node_2.id());

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    // Create networking activity to observe.
    loop {
        select! {
            _ = get_peer(node_1.id(), node_2.clone()).fuse() => {},
            _ = shutdown_signal("metrics example").fuse() => {
                info!("Exiting...");
                return;
            }
        }
    }
}

async fn get_peer(peer_id: PeerId, node: Node) {
    let peer_id = node
        .get_closest_peers(peer_id.into())
        .await
        .unwrap()
        .next()
        .await
        .unwrap();

    info!("Got peer {}", peer_id);
    sleep(Duration::from_secs(2)).await;
}
