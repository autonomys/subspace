#![warn(missing_docs)]
//! This Rust module serves as a bridge between two different Prometheus metrics libraries
//! used within our frameworks — Substrate and Libp2p.
//! The module exposes a web server endpoint at "/metrics" that outputs metrics in Prometheus
//! format. It adapts metrics from either or both of the following libraries:
//! - Official Rust Prometheus client (registry aliased as Libp2pMetricsRegistry)
//! - TiKV's Prometheus client (registry aliased as SubstrateMetricsRegistry)

use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{get, App, HttpResponse, HttpServer};
use parking_lot::Mutex;
use prometheus::{Encoder, Registry as SubstrateMetricsRegistry, TextEncoder};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry as Libp2pMetricsRegistry;
use std::error::Error;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{error, info, warn};

/// An metrics registry adapter for Libp2p and Substrate frameworks.
/// It specifies which metrics registry or registries are in use.
pub enum RegistryAdapter {
    /// Uses only the Libp2p metrics registry.
    Libp2p(Arc<Mutex<Libp2pMetricsRegistry>>),
    /// Uses only the Substrate metrics registry.
    Substrate(Arc<Mutex<SubstrateMetricsRegistry>>),
    /// We use both Substrate and Libp2p metrics registries.
    Both(
        Arc<Mutex<Libp2pMetricsRegistry>>,
        Arc<Mutex<SubstrateMetricsRegistry>>,
    ),
}

#[get("/metrics")]
async fn metrics(registry: Data<RegistryAdapter>) -> Result<HttpResponse, Box<dyn Error>> {
    let encoded_metrics = match registry.get_ref() {
        RegistryAdapter::Libp2p(libp2p_registry) => {
            let mut encoded = String::new();
            encode(&mut encoded, libp2p_registry.lock().deref())?;

            encoded
        }
        RegistryAdapter::Substrate(substrate_registry) => {
            let encoder = TextEncoder::new();
            let mut encoded = String::new();
            unsafe {
                encoder.encode(
                    &substrate_registry.lock().deref().gather(),
                    &mut encoded.as_mut_vec(),
                )?;
            }
            encoded
        }
        RegistryAdapter::Both(libp2p_registry, substrate_registry) => {
            // We combine outputs of both metrics registries in one string.
            let mut libp2p_encoded = String::new();
            encode(&mut libp2p_encoded, libp2p_registry.lock().deref())?;

            let encoder = TextEncoder::new();
            let mut substrate_encoded = String::new();
            unsafe {
                encoder.encode(
                    &substrate_registry.lock().deref().gather(),
                    &mut substrate_encoded.as_mut_vec(),
                )?;
            }

            // libp2p string contains #EOF, order is important here.
            substrate_encoded + &libp2p_encoded
        }
    };

    let resp = HttpResponse::build(StatusCode::OK).body(encoded_metrics);

    Ok(resp)
}

/// Start prometheus metrics server on the provided address.
pub fn start_prometheus_metrics_server(
    mut endpoints: Vec<SocketAddr>,
    registry: RegistryAdapter,
) -> std::io::Result<impl Future<Output = std::io::Result<()>>> {
    let data = Data::new(registry);

    let app_factory = move || App::new().app_data(data.clone()).service(metrics);
    let result = HttpServer::new(app_factory.clone())
        .workers(2)
        .bind(endpoints.as_slice());

    let server = match result {
        Ok(server) => server,
        Err(error) => {
            if error.kind() != ErrorKind::AddrInUse {
                error!(?error, "Failed to start metrics server.");

                return Err(error);
            }

            // Trying to recover from "address in use" error.
            warn!(
                ?error,
                "Failed to start metrics server. Falling back to the random port...",
            );

            endpoints.iter_mut().for_each(|endpoint| {
                endpoint.set_port(0);
            });

            let result = HttpServer::new(app_factory)
                .workers(2)
                .bind(endpoints.as_slice());

            match result {
                Ok(server) => server,
                Err(error) => {
                    error!(?error, "Failed to start metrics server on the random port.");

                    return Err(error);
                }
            }
        }
    };

    info!(endpoints = ?server.addrs(), "Metrics server started.",);

    Ok(server.run())
}
