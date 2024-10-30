//! Gateway subcommands.

pub(crate) mod run;

use crate::commands::run::RunOptions;
use clap::Parser;
use std::panic;
use std::process::exit;
use tokio::signal;
use tracing::level_filters::LevelFilter;
use tracing::{debug, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Commands for working with a gateway.
#[derive(Debug, Parser)]
#[clap(about, version)]
pub enum Command {
    /// Run data gateway
    Run(RunOptions),
    // TODO: subcommand to run various benchmarks
}

/// Install a panic handler which exits on panics, rather than unwinding. Unwinding can hang the
/// tokio runtime waiting for stuck tasks or threads.
pub(crate) fn set_exit_on_panic() {
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));
}

pub(crate) fn init_logger() {
    // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214, also on
    //  Windows terminal doesn't support the same colors as bash does
    let enable_color = if cfg!(windows) {
        false
    } else {
        supports_color::on(supports_color::Stream::Stderr).is_some()
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer().with_ansi(enable_color).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .init();
}

pub(crate) fn raise_fd_limit() {
    match fdlimit::raise_fd_limit() {
        Ok(fdlimit::Outcome::LimitRaised { from, to }) => {
            debug!(
                "Increased file descriptor limit from previous (most likely soft) limit {} to \
                new (most likely hard) limit {}",
                from, to
            );
        }
        Ok(fdlimit::Outcome::Unsupported) => {
            // Unsupported platform (a platform other than Linux or macOS)
        }
        Err(error) => {
            warn!(
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
                tracing::info!("Received SIGINT, shutting down gateway...");
            }),),
        pin!(signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGTERM, shutting down gateway...");
            }),),
    )
    .await;
}

#[cfg(not(unix))]
pub(crate) async fn shutdown_signal() {
    signal::ctrl_c()
        .await
        .expect("Setting signal handlers must never fail");

    tracing::info!("Received Ctrl+C, shutting down gateway...");
}
