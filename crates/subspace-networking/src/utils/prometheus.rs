use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{get, App, HttpResponse, HttpServer};
use parking_lot::Mutex;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use tracing::{error, info};

type SharedRegistry = Arc<Mutex<Registry>>;

#[get("/metrics")]
async fn metrics(registry: Data<SharedRegistry>) -> Result<HttpResponse, Box<dyn Error>> {
    let mut encoded = String::new();
    encode(&mut encoded, &registry.lock())?;

    let resp = HttpResponse::build(StatusCode::OK).body(encoded);

    Ok(resp)
}

/// Start prometheus metrics server on the provided address.
pub async fn start_prometheus_metrics_server(
    address: SocketAddr,
    registry: Registry,
) -> std::io::Result<()> {
    let shared_registry = Arc::new(Mutex::new(registry));
    let data = Data::new(shared_registry);

    info!("Starting metrics server on {} ...", address);

    let server = HttpServer::new(move || App::new().app_data(data.clone()).service(metrics))
        .bind(address)?
        .run();

    // Actix-web will reuse existing tokio runtime.
    let runtime = tokio::runtime::Runtime::new()?;

    // We need a dedicated thread because actix-web App is !Send and won't work with tokio.
    // TODO: This is not cancellable, it should be though
    thread::spawn(move || {
        if let Err(err) = runtime.block_on(server) {
            error!(
                ?err,
                "block_on returns an error for prometheus metrics server"
            )
        }
    });

    Ok(())
}
