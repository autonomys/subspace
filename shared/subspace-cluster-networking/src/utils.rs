use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::runtime::Handle;
use tokio::task;

/// Joins async join handle on drop
pub struct AsyncJoinOnDrop<T> {
    handle: Option<task::JoinHandle<T>>,
    abort_on_drop: bool,
}

impl<T> Drop for AsyncJoinOnDrop<T> {
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
    pub fn new(handle: task::JoinHandle<T>, abort_on_drop: bool) -> Self {
        Self {
            handle: Some(handle),
            abort_on_drop,
        }
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(
            self.handle
                .as_mut()
                .expect("Only dropped in Drop impl; qed"),
        )
        .poll(cx)
    }
}
