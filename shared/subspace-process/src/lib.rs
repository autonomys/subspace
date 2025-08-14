use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::{Either, FusedFuture};
use std::fmt::Display;
use std::future::Future;
use std::ops::Deref;
use std::pin::{Pin, pin};
use std::process::exit;
use std::task::{Context, Poll};
use std::{io, panic, thread};
use tokio::runtime::Handle;
use tokio::{signal, task};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

#[cfg(test)]
mod tests;

pub fn init_logger() {
    // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214, also on
    //  Windows terminal doesn't support the same colors as bash does
    let enable_color = if cfg!(windows) {
        false
    } else {
        supports_color::on(supports_color::Stream::Stderr).is_some()
    };

    let res = tracing_subscriber::registry()
        .with(
            fmt::layer().with_ansi(enable_color).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .try_init();

    if let Err(e) = res {
        // In production, this might be a bug in the logging setup.
        // In some tests, it is expected.
        eprintln!(
            "Failed to initialize logger: {e}. \
            This is expected when running nexttest test functions under `cargo test`."
        );
    }
}

/// Joins async join handle on drop.
/// This future is fused, and will return `Poll::Pending` if polled after completion.
#[derive(Debug)]
pub struct AsyncJoinOnDrop<T> {
    handle: Option<task::JoinHandle<T>>,
    abort_on_drop: bool,
}

impl<T> Drop for AsyncJoinOnDrop<T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.abort_on_drop {
                handle.abort();
            }

            if !handle.is_finished() {
                task::block_in_place(move || {
                    let _ = Handle::current().block_on(handle);
                });
            }
        }
    }
}

impl<T> AsyncJoinOnDrop<T> {
    /// Create new instance.
    #[inline]
    pub fn new(handle: task::JoinHandle<T>, abort_on_drop: bool) -> Self {
        Self {
            handle: Some(handle),
            abort_on_drop,
        }
    }
}

impl<T> FusedFuture for AsyncJoinOnDrop<T> {
    fn is_terminated(&self) -> bool {
        self.handle.is_none()
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(handle) = self.handle.as_mut() {
            let result = Pin::new(handle).poll(cx);
            if result.is_ready() {
                // Drop the handle, because if we poll it again, it will panic.
                self.handle.take();
            }
            result
        } else {
            Poll::Pending
        }
    }
}

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    #[inline]
    fn drop(&mut self) {
        self.0
            .take()
            .expect("Always called exactly once; qed")
            .join()
            .expect("Panic if background thread panicked");
    }
}

impl JoinOnDrop {
    // Create new instance
    #[inline]
    pub(crate) fn new(handle: thread::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Deref for JoinOnDrop {
    type Target = thread::JoinHandle<()>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Only dropped in Drop impl; qed")
    }
}

/// Runs future on a dedicated thread with the specified name. Will block on drop until background
/// thread with future is stopped, ensuring nothing is left in memory.
///
/// Some OSes (like Linux) truncate thread names at 15 characters due to kernel limits.
pub fn run_future_in_dedicated_thread<CreateFut, Fut, T>(
    create_future: CreateFut,
    thread_name: String,
) -> io::Result<impl Future<Output = Result<T, Canceled>> + Send>
where
    CreateFut: (FnOnce() -> Fut) + Send + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel();
    let handle = Handle::current();
    let join_handle = thread::Builder::new().name(thread_name).spawn(move || {
        let _tokio_handle_guard = handle.enter();

        let future = pin!(create_future());

        let result = match handle.block_on(futures::future::select(future, drop_rx)) {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                // Outer future was dropped, nothing left to do
                return;
            }
        };
        if let Err(_error) = result_tx.send(result) {
            debug!(
                thread_name = ?thread::current().name(),
                "Future finished, but receiver was already dropped",
            );
        }
    })?;
    // Ensure thread will not be left hanging forever
    let join_on_drop = JoinOnDrop::new(join_handle);

    Ok(async move {
        let result = result_rx.await;
        drop(drop_tx);
        drop(join_on_drop);
        result
    })
}

/// Wait for the process to receive a shutdown signal, and log the supplied process kind.
#[cfg(unix)]
pub async fn shutdown_signal(process_kind: impl Display) {
    use futures::FutureExt;
    use std::pin::pin;

    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Setting signal handlers must never fail");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Setting signal handlers must never fail");

    futures::future::select(
        pin!(sigint.recv().map(|_| {
            info!("Received SIGINT, shutting down {process_kind}...");
        }),),
        pin!(sigterm.recv().map(|_| {
            info!("Received SIGTERM, shutting down {process_kind}...");
        }),),
    )
    .await;
}

/// Wait for the process to receive a shutdown signal, and log the supplied process kind.
#[cfg(not(unix))]
pub async fn shutdown_signal(process_kind: impl Display) {
    signal::ctrl_c()
        .await
        .expect("Setting signal handlers must never fail");

    info!("Received Ctrl+C, shutting down {process_kind}...");
}

/// Raise the file descriptor limit for the process to the maximum possible value.
pub fn raise_fd_limit() {
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

/// Install a panic handler which exits on panics, rather than unwinding. Unwinding can hang the
/// tokio runtime waiting for stuck tasks or threads.
pub fn set_exit_on_panic() {
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));
}
