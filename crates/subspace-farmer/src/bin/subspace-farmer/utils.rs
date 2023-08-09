use tokio::signal;

pub(crate) fn raise_fd_limit() {
    match std::panic::catch_unwind(fdlimit::raise_fd_limit) {
        Ok(Some(limit)) => {
            tracing::info!("Increase file limit from soft to hard (limit is {limit})")
        }
        Ok(None) => tracing::debug!("Failed to increase file limit"),
        Err(err) => {
            let err = if let Some(err) = err.downcast_ref::<&str>() {
                *err
            } else if let Some(err) = err.downcast_ref::<String>() {
                err
            } else {
                unreachable!("Should be unreachable as `fdlimit` uses panic macro, which should return either `&str` or `String`.")
            };
            tracing::warn!("Failed to increase file limit: {err}")
        }
    }
}
#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use futures::FutureExt;

    futures::future::select(
        Box::pin(
            signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Setting signal handlers must never fail")
                .recv()
                .map(|_| {
                    tracing::info!("Received SIGINT, shutting down farmer...");
                }),
        ),
        Box::pin(
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Setting signal handlers must never fail")
                .recv()
                .map(|_| {
                    tracing::info!("Received SIGTERM, shutting down farmer...");
                }),
        ),
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
