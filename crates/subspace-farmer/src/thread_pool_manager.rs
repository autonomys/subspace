use event_listener::Event;
use parking_lot::Mutex;
use rayon::{ThreadPool, ThreadPoolBuildError};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;

/// A wrapper around thread pool pair for plotting purposes
#[derive(Debug)]
pub struct PlottingThreadPoolPair {
    pub plotting: ThreadPool,
    pub replotting: ThreadPool,
}

#[derive(Debug)]
struct Inner {
    thread_pool_pairs: Vec<PlottingThreadPoolPair>,
}

/// Wrapper around [`PlottingThreadPoolPair`] that on `Drop` will return thread pool back into corresponding
/// [`PlottingThreadPoolManager`].
#[derive(Debug)]
#[must_use]
pub struct PlottingThreadPoolsGuard {
    inner: Arc<(Mutex<Inner>, Event)>,
    thread_pool_pair: Option<PlottingThreadPoolPair>,
}

impl Deref for PlottingThreadPoolsGuard {
    type Target = PlottingThreadPoolPair;

    fn deref(&self) -> &Self::Target {
        self.thread_pool_pair
            .as_ref()
            .expect("Value exists until `Drop`; qed")
    }
}

impl Drop for PlottingThreadPoolsGuard {
    fn drop(&mut self) {
        let (mutex, event) = &*self.inner;
        mutex.lock().thread_pool_pairs.push(
            self.thread_pool_pair
                .take()
                .expect("Happens only once in `Drop`; qed"),
        );
        event.notify_additional(1);
    }
}

/// Plotting thread pool manager.
///
/// This abstraction wraps a set of thread pool pairs and allows to use them one at a time.
///
/// Each pair contains one thread pool for plotting purposes and one for replotting, this is because
/// they'll share the same set of CPU cores in most cases and wit would be inefficient to use them
/// concurrently.
///
/// For example on machine with 64 logical cores and 4 NUMA nodes it would be recommended to create
/// 4 thread pools with 16 threads each plotting thread pool and 8 threads in each replotting thread
/// pool, which would mean work done within thread pool is tied to CPU cores dedicated for that
/// thread pool.
#[derive(Debug, Clone)]
pub struct PlottingThreadPoolManager {
    inner: Arc<(Mutex<Inner>, Event)>,
    thread_pool_pairs: NonZeroUsize,
}

impl PlottingThreadPoolManager {
    /// Create new thread pool manager by instantiating `thread_pools` thread pools using
    /// `create_thread_pool`.
    ///
    /// `create_thread_pool` takes one argument `thread_pool_index`.
    pub fn new<C>(
        create_thread_pools: C,
        thread_pool_pairs: NonZeroUsize,
    ) -> Result<Self, ThreadPoolBuildError>
    where
        C: FnMut(usize) -> Result<PlottingThreadPoolPair, ThreadPoolBuildError>,
    {
        let inner = Inner {
            thread_pool_pairs: (0..thread_pool_pairs.get())
                .map(create_thread_pools)
                .collect::<Result<Vec<_>, _>>()?,
        };

        Ok(Self {
            inner: Arc::new((Mutex::new(inner), Event::new())),
            thread_pool_pairs,
        })
    }

    /// How many thread pool pairs are being managed here
    pub fn thread_pool_pairs(&self) -> NonZeroUsize {
        self.thread_pool_pairs
    }

    /// Get one of inner thread pool pairs, will wait until one is available if needed
    pub async fn get_thread_pools(&self) -> PlottingThreadPoolsGuard {
        let (mutex, event) = &*self.inner;

        let thread_pool_pair = loop {
            let listener = event.listen();

            if let Some(thread_pool_pair) = mutex.lock().thread_pool_pairs.pop() {
                drop(listener);
                // It is possible that we got here because there was the last free pair available
                // and in the meantime listener received notification. Just in case that was the
                // case, notify one more listener (if there is any) to make sure all available
                // thread pools are utilized when there is demand for them.
                event.notify(1);
                break thread_pool_pair;
            }

            listener.await;
        };

        PlottingThreadPoolsGuard {
            inner: Arc::clone(&self.inner),
            thread_pool_pair: Some(thread_pool_pair),
        }
    }
}
