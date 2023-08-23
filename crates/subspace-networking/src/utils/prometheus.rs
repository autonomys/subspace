use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{get, App, HttpResponse, HttpServer};
use parking_lot::Mutex;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

type SharedRegistry = Arc<Mutex<Registry>>;

#[get("/metrics")]
async fn metrics(registry: Data<SharedRegistry>) -> Result<HttpResponse, Box<dyn Error>> {
    let mut encoded = String::new();
    encode(&mut encoded, &registry.lock())?;

    let resp = HttpResponse::build(StatusCode::OK).body(encoded);

    Ok(resp)
}

/// Start prometheus metrics server on the provided address.
pub fn start_prometheus_metrics_server(
    endpoints: Vec<SocketAddr>,
    registry: Registry,
) -> std::io::Result<impl Future<Output = std::io::Result<()>>> {
    let shared_registry = Arc::new(Mutex::new(registry));
    let data = Data::new(shared_registry);

    info!(?endpoints, "Starting metrics server...",);

    Ok(
        HttpServer::new(move || App::new().app_data(data.clone()).service(metrics))
            .bind(endpoints.as_slice())?
            .run(),
    )
}
