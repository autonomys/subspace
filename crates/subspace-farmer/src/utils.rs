use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::{JoinError, JoinHandle};

/// Abort Tokio task on drop
#[derive(Debug)]
pub(crate) struct AbortingJoinHandle<T>(JoinHandle<T>);

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for AbortingJoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> AbortingJoinHandle<T> {
    pub(crate) fn new(handle: JoinHandle<T>) -> Self {
        Self(handle)
    }
}

pub(crate) fn get_plot_sizes(allocated_space: u64, max_plot_size: u64) -> Vec<u64> {
    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    //  less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases.
    //  For now assume 92% will go for plot itself
    let usable_space_for_plots = allocated_space * 92 / 100;

    let plot_sizes =
        std::iter::repeat(max_plot_size).take((usable_space_for_plots / max_plot_size) as usize);
    if usable_space_for_plots / max_plot_size == 0
        || usable_space_for_plots % max_plot_size > max_plot_size / 2
    {
        plot_sizes
            .chain(std::iter::once(usable_space_for_plots % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    }
}
