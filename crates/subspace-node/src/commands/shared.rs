use clap::Parser;
use sc_cli::{Error, Signals};
use sc_keystore::LocalKeystore;
use sp_core::crypto::{ExposeSecret, SecretString};
use sp_core::sr25519::Pair;
use sp_core::Pair as PairT;
use sp_domains::KEY_TYPE;
use sp_keystore::Keystore;
use std::path::PathBuf;
use std::process::{self, exit};
use std::time::Duration;
use std::{panic, thread};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, error, info};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// The amount of time we wait for tasks to finish when shutting down.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// When shutting down, the amount of extra time we wait for async task dumps to complete, or the
/// user to trace the process, before exiting.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(15);

/// Options used for keystore
#[derive(Debug, Parser)]
pub(super) struct KeystoreOptions {
    /// Use interactive shell for entering the password used by the keystore.
    #[arg(long, conflicts_with_all = &["keystore_password", "keystore_password_filename"])]
    pub(super) keystore_password_interactive: bool,
    /// Password used by the keystore. This allows appending an extra user-defined secret to the
    /// seed.
    #[arg(long, conflicts_with_all = &["keystore_password_interactive", "keystore_password_filename"])]
    pub(super) keystore_password: Option<SecretString>,
    /// File that contains the password used by the keystore.
    #[arg(long, conflicts_with_all = &["keystore_password_interactive", "keystore_password"])]
    pub(super) keystore_password_filename: Option<PathBuf>,
}

pub(super) fn derive_keypair(
    suri: &SecretString,
    password: &Option<SecretString>,
) -> Result<Pair, Error> {
    let keypair_result = Pair::from_string(
        suri.expose_secret(),
        password
            .as_ref()
            .map(|password| password.expose_secret().as_str()),
    );

    keypair_result.map_err(|err| Error::Input(format!("Invalid password {:?}", err)))
}

pub(super) fn store_key_in_keystore(
    keystore_path: PathBuf,
    suri: &SecretString,
    password: Option<SecretString>,
) -> Result<(), Error> {
    let keypair = derive_keypair(suri, &password)?;

    LocalKeystore::open(keystore_path, password)?
        .insert(KEY_TYPE, suri.expose_secret(), &keypair.public())
        .map_err(|()| Error::Application("Failed to insert key into keystore".to_string().into()))
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

pub(super) fn init_logger() {
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
                    let signals = Signals::capture()
                        .expect("creating a future to wait for shutdown signal failed");
                    let _ = signals.future().await;
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
