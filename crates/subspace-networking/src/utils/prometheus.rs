use futures::future::{ready, Ready};
use hyper::http::StatusCode;
use hyper::service::Service;
use hyper::{Body, Method, Request, Response, Server};
use parking_lot::Mutex;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{error, info, warn};

// Start prometheus metrics server on the provided address.
pub(crate) async fn start_prometheus_metrics_server(
    addr: SocketAddr,
    registry: Registry,
) -> Result<(), std::io::Error> {
    let server = Server::bind(&addr).serve(MakeMetricService::new(registry));

    info!(
        "Prometheus metrics server started on http://{}/metrics",
        server.local_addr()
    );

    if let Err(e) = server.await {
        error!("server error: {}", e);
    }

    Ok(())
}

struct MetricService {
    registry: Arc<Mutex<Registry>>,
}

type SharedRegistry = Arc<Mutex<Registry>>;

impl MetricService {
    fn get_registry(&mut self) -> SharedRegistry {
        Arc::clone(&self.registry)
    }
    fn respond_with_metrics(&mut self) -> Result<Response<Body>, Box<dyn Error>> {
        let mut encoded: Vec<u8> = Vec::new();
        let reg = self.get_registry();
        encode(&mut encoded, &reg.lock())?;

        let metrics_content_type = "application/openmetrics-text;charset=utf-8;version=1.0.0";

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, metrics_content_type)
            .body(Body::from(encoded))?;

        Ok(resp)
    }
    fn respond_with_404_not_found(&mut self) -> Result<Response<Body>, Box<dyn Error>> {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found. Try server:[port]/metrics"))?;

        Ok(resp)
    }
}

impl Service<Request<Body>> for MetricService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let req_path = req.uri().path();
        let req_method = req.method();
        let response_result = if (req_method == Method::GET) && (req_path == "/metrics") {
            // Encode and serve metrics from registry.
            self.respond_with_metrics()
        } else {
            self.respond_with_404_not_found()
        };

        match response_result {
            Ok(response) => ready(Ok(response)),
            Err(err) => {
                warn!(?err, "Can't create metrics response.");

                ready(Ok(Response::new(Body::empty())))
            }
        }
    }
}

struct MakeMetricService {
    registry: SharedRegistry,
}

impl MakeMetricService {
    pub fn new(registry: Registry) -> MakeMetricService {
        MakeMetricService {
            registry: Arc::new(Mutex::new(registry)),
        }
    }
}

impl<T> Service<T> for MakeMetricService {
    type Response = MetricService;
    type Error = hyper::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: T) -> Self::Future {
        let registry = self.registry.clone();
        ready(Ok(MetricService { registry }))
    }
}
