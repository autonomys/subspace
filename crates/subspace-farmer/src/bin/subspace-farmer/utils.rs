use tokio::signal;

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
            // Unsupported platform (a platform other than Linux or macOS)
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
