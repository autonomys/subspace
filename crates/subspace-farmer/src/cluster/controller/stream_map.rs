//! A stream map that keeps track of futures that are currently being processed for each `Index`.

use futures::stream::FusedStream;
use futures::{FutureExt, Stream, StreamExt};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::StreamMap as TokioStreamMap;

type TaskFuture<'a, R> = Pin<Box<dyn Future<Output = R> + 'a>>;
type TaskStream<'a, R> = Pin<Box<dyn Stream<Item = R> + Unpin + 'a>>;

/// A StreamMap that keeps track of futures that are currently being processed for each `index`.
pub(super) struct StreamMap<'a, Index, R> {
    in_progress: TokioStreamMap<Index, TaskStream<'a, R>>,
    queue: HashMap<Index, VecDeque<TaskFuture<'a, R>>>,
}

impl<Index, R> Default for StreamMap<'_, Index, R> {
    fn default() -> Self {
        Self {
            in_progress: TokioStreamMap::default(),
            queue: HashMap::default(),
        }
    }
}

impl<'a, Index, R: 'a> StreamMap<'a, Index, R>
where
    Index: Eq + Hash + Copy + Unpin,
{
    /// When pushing a new task, it first checks if there is already a future for the given `index` in `in_progress`.
    ///   - If there is, the task is added to `queue`.
    ///   - If not, the task is directly added to `in_progress`.
    pub(super) fn push(&mut self, index: Index, fut: TaskFuture<'a, R>) {
        if self.in_progress.contains_key(&index) {
            let queue = self.queue.entry(index).or_default();
            queue.push_back(fut);
        } else {
            self.in_progress
                .insert(index, Box::pin(fut.into_stream()) as _);
        }
    }

    /// Skip the task if there is already a future for the given `index` in `in_progress`.
    /// Returns `true` if the task is added to `in_progress`, `false` otherwise.
    pub(super) fn add_if_not_in_progress(&mut self, index: Index, fut: TaskFuture<'a, R>) -> bool {
        if self.in_progress.contains_key(&index) {
            false
        } else {
            self.in_progress
                .insert(index, Box::pin(fut.into_stream()) as _);
            true
        }
    }

    /// Polls the next entry in `in_progress` and moves the next task from `queue` to `in_progress` if there is any.
    /// If there are no more tasks to execute, returns `None`.
    fn poll_next_entry(&mut self, cx: &mut Context<'_>) -> Poll<Option<(Index, R)>> {
        if let Some((index, res)) = std::task::ready!(self.in_progress.poll_next_unpin(cx)) {
            // Current task completed, remove from in_progress queue and check for more tasks
            self.in_progress.remove(&index);
            self.process_queue(index);
            Poll::Ready(Some((index, res)))
        } else {
            // No more tasks to execute
            assert!(self.queue.is_empty());
            Poll::Ready(None)
        }
    }

    /// Process the next task from the tasks queue for the given `index`
    fn process_queue(&mut self, index: Index) {
        if let Entry::Occupied(mut next_entry) = self.queue.entry(index) {
            let task_queue = next_entry.get_mut();
            if let Some(fut) = task_queue.pop_front() {
                self.in_progress
                    .insert(index, Box::pin(fut.into_stream()) as _);
            }

            // Remove the index from the map if there are no more tasks
            if task_queue.is_empty() {
                next_entry.remove();
            }
        }
    }
}

impl<'a, Index, R: 'a> Stream for StreamMap<'a, Index, R>
where
    Index: Eq + Hash + Copy + Unpin,
{
    type Item = (Index, R);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.poll_next_entry(cx)
    }
}

impl<'a, Index, R: 'a> FusedStream for StreamMap<'a, Index, R>
where
    Index: Eq + Hash + Copy + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.in_progress.is_empty() && self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::controller::stream_map::StreamMap;
    use futures::StreamExt;
    use futures::stream::FusedStream;
    use std::task::Context;

    fn assert_is_terminated<'a, R: 'a>(stream_map: &StreamMap<'a, u16, R>) {
        assert!(stream_map.in_progress.is_empty());
        assert!(stream_map.queue.is_empty());
        assert!(stream_map.is_terminated());
    }

    #[test]
    fn test_stream_map_default() {
        let stream_map = StreamMap::<u16, ()>::default();
        assert_is_terminated(&stream_map);
    }

    #[test]
    fn test_stream_map_push() {
        let mut stream_map = StreamMap::default();

        let index = 1;
        let fut = Box::pin(async {});
        stream_map.push(index, fut);
        assert!(stream_map.queue.is_empty());
        assert!(stream_map.in_progress.contains_key(&index));
        assert!(!stream_map.is_terminated());
    }

    #[test]
    fn test_stream_map_add_if_not_in_progress() {
        let mut stream_map = StreamMap::default();

        let index = 1;
        let fut1 = Box::pin(async {});
        let fut2 = Box::pin(async {});
        assert!(stream_map.add_if_not_in_progress(index, fut1));
        assert!(!stream_map.add_if_not_in_progress(index, fut2));
    }

    #[test]
    fn test_stream_map_poll_next_entry() {
        let mut stream_map = StreamMap::default();

        let fut = Box::pin(async {});
        stream_map.push(0, fut);

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let poll_result = stream_map.poll_next_entry(&mut cx);
        assert!(poll_result.is_ready());
        assert_is_terminated(&stream_map);
    }

    #[tokio::test]
    async fn test_stream_map_stream() {
        let mut stream_map = StreamMap::default();

        let fut00 = Box::pin(async { 0x00 });
        stream_map.push(0, fut00);

        let next_item = stream_map.next().await;
        assert_eq!(next_item, Some((0, 0x00)));
        assert_is_terminated(&stream_map);

        let fut11 = Box::pin(async { 0x11 });
        let fut12 = Box::pin(async { 0x12 });
        let fut13 = Box::pin(async { 0x13 });
        let fut21 = Box::pin(async {
            // Yield the current task three times to ensure that fut22 is polled last.
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            0x21
        });
        let fut22 = Box::pin(async { 0x22 });

        // Push 2 futs into the same farm index 1, expect fut11 to be polled first,
        // fut12 should push into the in_progress queue and wait for fut11 to finish
        stream_map.push(1, fut11);
        stream_map.push(1, fut12);
        assert!(!stream_map.is_terminated());
        assert_eq!(stream_map.in_progress.len(), 1);
        assert!(stream_map.in_progress.contains_key(&1));
        assert_eq!(stream_map.queue.len(), 1);

        // Push fut22 into farm index 2, we have 2 in progress futures now
        stream_map.push(2, fut21);
        assert_eq!(stream_map.in_progress.len(), 2);
        assert!(stream_map.in_progress.contains_key(&2));
        assert_eq!(stream_map.queue.len(), 1);

        // Push fut22 into farm index 2, in-progress queue length should not change,
        // but the queue should have 2 entries now
        stream_map.push(2, fut22);
        assert_eq!(stream_map.in_progress.len(), 2);
        assert_eq!(stream_map.queue.len(), 2);
        assert_eq!(stream_map.queue[&2].len(), 1);

        // Push fut13 into farm index 1, fut13 should be polled after fut11 and fut12
        stream_map.push(1, fut13);
        assert!(!stream_map.is_terminated());
        assert!(stream_map.in_progress.contains_key(&1));
        assert_eq!(stream_map.in_progress.len(), 2);
        assert_eq!(stream_map.queue[&1].len(), 2);

        // Poll the next item in the stream, fut11 should be polled first,
        // fut12 should be pushed into the in-progress queue
        let next_item = stream_map.next().await;
        assert!(!stream_map.is_terminated());
        assert_eq!(next_item.unwrap(), (1, 0x11));
        assert!(stream_map.in_progress.contains_key(&1));
        assert!(stream_map.in_progress.contains_key(&2));
        assert_eq!(stream_map.in_progress.len(), 2);
        assert_eq!(stream_map.queue[&1].len(), 1);

        // Here, fut12 and fut 13 should be polled before fut21 because fut21 has a yield point.
        // Fut13 should be pushed into the in_progress queue.
        // There are no more futures waiting to be polled in farm index 1, so the farm index 1
        // should be removed from the queue map.
        let next_item = stream_map.next().await;
        assert!(!stream_map.is_terminated());
        assert_eq!(next_item.unwrap(), (1, 0x12));
        assert_eq!(stream_map.in_progress.len(), 2);
        assert!(stream_map.in_progress.contains_key(&1));
        assert!(stream_map.in_progress.contains_key(&2));
        assert!(!stream_map.queue.contains_key(&1));

        // Poll the next item in the stream, fut13 should be polled next.
        // For now, all futures in farm index 1 have been polled, so farm index 1 should be removed
        // from the in-progress queue.
        let next_item = stream_map.next().await;
        assert!(!stream_map.is_terminated());
        assert_eq!(next_item.unwrap(), (1, 0x13));
        assert_eq!(stream_map.in_progress.len(), 1);
        assert!(!stream_map.in_progress.contains_key(&1));
        assert!(stream_map.in_progress.contains_key(&2));
        assert!(!stream_map.queue.contains_key(&1));
        assert_eq!(stream_map.queue[&2].len(), 1);

        // We hope futures with the same index are polled in the order they are pushed,
        // so fut21 should be polled next.
        // fut22 should be pushed into the in-progress queue.
        // There are no more futures waiting to be polled in farm index 2, so the farm index 2
        // should be removed from the queue map.
        let next_item = stream_map.next().await;
        assert!(!stream_map.is_terminated());
        assert_eq!(next_item.unwrap(), (2, 0x21));
        assert_eq!(stream_map.in_progress.len(), 1);
        assert!(!stream_map.in_progress.contains_key(&1));
        assert!(stream_map.in_progress.contains_key(&2));
        assert!(!stream_map.queue.contains_key(&1));
        assert!(!stream_map.queue.contains_key(&2));

        // Poll the next item in the stream, fut22 should be polled next.
        // For now, all futures in farm index 2 have been polled, so farm index 2 should be removed
        // from the in-progress queue.
        // Finally, the stream should be terminated.
        let next_item = stream_map.next().await;
        assert_eq!(next_item, Some((2, 0x22)));
        assert_is_terminated(&stream_map);
    }
}
