//! Gateway subcommands.

pub(crate) mod run;

use crate::commands::run::RunOptions;
use clap::Parser;
use std::process::exit;
use std::time::Duration;
use std::{panic, process, thread};
use tokio::runtime::{Handle, Runtime};
use tokio::signal;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// The amount of time we wait for tasks to finish when shutting down.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// When shutting down, the amount of extra time we wait for async task dumps to complete, or the
/// user to trace the process, before exiting.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Spawns a thread which forces a shutdown after [`SHUTDOWN_TIMEOUT`], if an async task is
/// blocking. If a second Ctrl-C is received, the thread will force a shut down immediately.
///
/// If compiled with `--cfg tokio_unstable,tokio_taskdump`, logs backtraces of the async tasks
/// blocking shutdown on `runtime_handle`.
///
/// When `tokio::main()` returns, the runtime will be dropped. A dropped runtime can wait forever for
/// all async tasks to reach an await point, or all blocking tasks to finish. If the runtime is
/// dropped before the timeout, the underlying `main()` function will return, and the `exit()` in
/// this spawned thread will never be called.
#[cfg_attr(
    not(all(tokio_unstable, tokio_taskdump)),
    expect(unused_variables, reason = "handle only used in some configs")
)]
pub fn spawn_shutdown_watchdog(runtime_handle: Handle) {
    // TODO: replace tokio::main with runtime::Builder, and call Runtime::shutdown_timeout()
    // instead of sleep() and exit()

    thread::spawn(move || {
        // Shut down immediately if we get a second Ctrl-C.
        //
        // A tokio runtime that's shutting down will cancel pending futures, so we need to
        // wait for ctrl_c() on a separate runtime.
        thread::spawn(|| {
            debug!("waiting for a second shutdown signal");
            Runtime::new()
                .expect("creating a runtime to wait for shutdown signal failed")
                .block_on(async {
                    let _ = shutdown_signal().await;
                    info!("second shutdown signal received, shutting down immediately");
                    exit(1);
                });
        });

        debug!(?SHUTDOWN_TIMEOUT, "waiting for tokio runtime to shut down");
        thread::sleep(SHUTDOWN_TIMEOUT);

        // Force a shutdown if a task is blocking.
        error!(?SHUTDOWN_TIMEOUT, "shutdown timed out, forcing an exit");
        info!(
            "run `flamegraph --pid {}` or similar to generate a stack dump",
            process::id()
        );

        // Log all the async tasks and spawn_blocking() tasks that are still running.
        //
        // A tokio runtime that's shutting down will cancel a dump at its first await
        // point, so we need to call dump() on a separate runtime.
        #[cfg(all(tokio_unstable, tokio_taskdump))]
        thread::spawn(move || {
            use tracing::warn;

            error!(
                ?SHUTDOWN_TIMEOUT,
                "shutdown timed out, trying to dump blocking tasks"
            );
            Runtime::new()
                .expect("creating a runtime to dump blocking tasks failed")
                .block_on(async move {
                    for (task_number, task) in handle.dump().await.tasks().iter().enumerate() {
                        let trace = task.trace();
                        warn!(task_number, trace, "blocking task backtrace");
                    }
                });
        });

        // Give the log messages time to flush, and any dumps time to finish.
        thread::sleep(TRACE_TIMEOUT);
        exit(1);
    });
}
