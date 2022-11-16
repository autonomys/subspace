use std::path::PathBuf;
use tokio::signal;

pub(crate) fn default_base_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("Can't find local data directory, needs to be specified explicitly")
        .join("subspace-farmer")
}

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

pub(crate) const DB_OVERHEAD_PERCENT: u64 = 92;

pub(crate) fn get_usable_plot_space(allocated_space: u64) -> u64 {
    // TODO: Should account for database overhead of various additional databases.
    //  For now assume 92% will go for plot itself
    allocated_space * DB_OVERHEAD_PERCENT / 100
}

pub(crate) fn get_required_plot_space_with_overhead(allocated_space: u64) -> u64 {
    // TODO: Should account for database overhead of various additional databases.
    //  For now assume 92% will go for plot itself
    allocated_space * 100 / DB_OVERHEAD_PERCENT
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
