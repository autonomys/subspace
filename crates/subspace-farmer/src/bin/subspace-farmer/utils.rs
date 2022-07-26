use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

type OnExitHandler = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct SignalHandler {
    on_exit: Arc<Mutex<Vec<OnExitHandler>>>,
}

impl SignalHandler {
    pub fn new() -> Self {
        let on_exit = Arc::default();
        let me = Self {
            on_exit: Arc::clone(&on_exit),
        };
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await?;
            tracing::info!("Received Cntrl-C signal. Stopping the farmer...");
            for future in std::mem::take(&mut *on_exit.lock().await) {
                future.await;
            }
            Ok::<_, std::io::Error>(())
        });
        me
    }

    pub async fn on_exit(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.on_exit.lock().await.push(Box::pin(future));
    }
}

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

pub(crate) fn get_usable_plot_space(allocated_space: u64) -> u64 {
    // TODO: Should account for database overhead of various additional databases.
    //  For now assume 92% will go for plot itself
    allocated_space * 92 / 100
}
