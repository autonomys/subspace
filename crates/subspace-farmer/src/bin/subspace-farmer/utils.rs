use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::{Registry, Unit};
use subspace_farmer::single_disk_farm::farming::AuditEvent;
use tokio::signal;

#[derive(Debug, Clone)]
pub(crate) struct FarmerMetrics {
    // Type comment: we need (String, String) instead of just String for farm_id because of
    // trait definition within prometheus_client library.
    audit: Family<Vec<(String, String)>, Histogram>,
}

impl FarmerMetrics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("subspace_farmer");

        let audit: Family<_, _> =
            Family::new_with_constructor(|| Histogram::new(exponential_buckets(0.0001, 2.0, 15)));

        sub_registry.register_with_unit("audit", "Audit time", Unit::Seconds, audit.clone());

        Self { audit }
    }

    pub(crate) fn observe_audit_event(&self, event: &AuditEvent) {
        self.audit
            .get_or_create(&vec![(event.farm_id.to_string(), Default::default())])
            .observe(event.duration);
    }
}

pub(crate) fn raise_fd_limit() {
    match fdlimit::raise_fd_limit() {
        Ok(fdlimit::Outcome::LimitRaised { from, to }) => {
            tracing::debug!(
                "Increased file descriptor limit from previous (most likely soft) limit {} to \
                new (most likely hard) limit {}",
                from,
                to
            );
        }
        Ok(fdlimit::Outcome::Unsupported) => {
            // Unsupported platform (non-Linux)
        }
        Err(error) => {
            tracing::warn!(
                "Failed to increase file descriptor limit for the process due to an error: {}.",
                error
            );
        }
    }
}

#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use futures::FutureExt;
    use std::pin::pin;

    futures::future::select(
        pin!(signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGINT, shutting down farmer...");
            }),),
        pin!(signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGTERM, shutting down farmer...");
            }),),
    )
    .await;
}

#[cfg(not(unix))]
pub(crate) async fn shutdown_signal() {
    signal::ctrl_c()
        .await
        .expect("Setting signal handlers must never fail");

    tracing::info!("Received Ctrl+C, shutting down farmer...");
}
