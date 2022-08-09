use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Abort Tokio task on drop
#[derive(Debug)]
pub(crate) struct AbortingJoinHandle<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for AbortingJoinHandle<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> AbortingJoinHandle<T> {
    pub(crate) fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }
}

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<std::thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        self.0
            .take()
            .expect("Always called exactly once; qed")
            .join()
            .expect("DSN archiving must not panic");
    }
}

impl JoinOnDrop {
    pub(crate) fn new(handle: std::thread::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Deref for JoinOnDrop {
    type Target = std::thread::JoinHandle<()>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Only dropped in Drop impl; qed")
    }
}

pub(crate) struct CallOnDrop<F>(Option<F>)
where
    F: FnOnce() + Send + 'static;

impl<F> Drop for CallOnDrop<F>
where
    F: FnOnce() + Send + 'static,
{
    fn drop(&mut self) {
        let callback = self.0.take().expect("Only removed on drop; qed");
        callback();
    }
}

impl<F> CallOnDrop<F>
where
    F: FnOnce() + Send + 'static,
{
    pub(crate) fn new(callback: F) -> Self {
        Self(Some(callback))
    }
}

pub(crate) fn get_plot_sizes(usable_space: u64, max_plot_size: u64) -> Vec<u64> {
    let plot_sizes = std::iter::repeat(max_plot_size).take((usable_space / max_plot_size) as usize);
    // TODO: Remove restriction for >50% of max plot size for last plot once it no longer causes
    //  performance issues
    if usable_space / max_plot_size == 0 || usable_space % max_plot_size > max_plot_size / 2 {
        plot_sizes
            .chain(std::iter::once(usable_space % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    }
}
