#![warn(missing_docs)]
//! This Rust module serves as a bridge between two different Prometheus metrics libraries
//! used: `prometheus-client` (official library) and TiKV's `prometheus` client (used by Substrate).
//! The module exposes a web server endpoint at "/metrics" that outputs metrics in Prometheus
//! format. It adapts metrics from either or both of those libraries.

use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{App, HttpResponse, HttpServer, get};
use prometheus::{Registry as SubstrateRegistry, TextEncoder};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry as PrometheusClientRegistry;
use std::error::Error;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use tracing::{error, info, warn};

/// Metrics registry adapter for prometheus-client and Substrate frameworks.
/// It specifies which metrics registry or registries are in use.
pub enum RegistryAdapter {
    /// Uses only the prometheus-client metrics registry.
    PrometheusClient(PrometheusClientRegistry),
    /// Uses only the Substrate metrics registry.
    Substrate(SubstrateRegistry),
    /// We use both Substrate and prometheus-client metrics registries.
    Both(PrometheusClientRegistry, SubstrateRegistry),
}

#[get("/metrics")]
async fn metrics(registry: Data<RegistryAdapter>) -> Result<HttpResponse, Box<dyn Error>> {
    let mut encoded_metrics = String::new();

    match &**registry {
        RegistryAdapter::PrometheusClient(libp2p_registry) => {
            encode(&mut encoded_metrics, libp2p_registry)?;
        }
        RegistryAdapter::Substrate(substrate_registry) => {
            TextEncoder::new().encode_utf8(&substrate_registry.gather(), &mut encoded_metrics)?;
        }
        RegistryAdapter::Both(libp2p_registry, substrate_registry) => {
            // We combine outputs of both metrics registries in one string.
            TextEncoder::new().encode_utf8(&substrate_registry.gather(), &mut encoded_metrics)?;
            // prometheus-client string contains #EOF, order is important here
            encode(&mut encoded_metrics, libp2p_registry)?;
        }
    }

    let resp = HttpResponse::build(StatusCode::OK)
        .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
        .body(encoded_metrics);

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
