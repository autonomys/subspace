pub mod archival_storage_pieces;
pub mod farmer_piece_cache;
pub mod farmer_piece_getter;
pub mod farmer_provider_storage;
pub mod node_piece_getter;
pub mod parity_db_store;
pub mod piece_cache;
pub mod piece_validator;
pub mod readers_and_pieces;
#[cfg(test)]
mod tests;

use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::Either;
use std::future::Future;
use std::ops::Deref;
use std::{io, thread};
use tokio::runtime::Handle;
use tracing::debug;

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
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

/// Runs future on a dedicated thread with the specified name, will block on drop until background
/// thread with future is stopped too, ensuring nothing is left in memory
pub fn run_future_in_dedicated_thread<Fut, T>(
    future: Fut,
    thread_name: String,
) -> io::Result<impl Future<Output = Result<T, Canceled>> + Send>
where
    Fut: Future<Output = T> + Unpin + Send + 'static,
    T: Send + 'static,
{
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel();
    let handle = Handle::current();
    let join_handle = thread::Builder::new().name(thread_name).spawn(move || {
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
