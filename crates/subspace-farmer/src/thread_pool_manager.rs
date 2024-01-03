use parking_lot::{Condvar, Mutex};
use rayon::{ThreadPool, ThreadPoolBuildError};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug)]
struct Inner {
    thread_pools: Vec<ThreadPool>,
}

/// Wrapper around [`ThreadPool`] that on `Drop` will return thread pool back into corresponding
/// [`ThreadPoolManager`].
#[derive(Debug)]
pub struct ThreadPoolGuard {
    inner: Arc<(Mutex<Inner>, Condvar)>,
    thread_pool: Option<ThreadPool>,
}

impl Deref for ThreadPoolGuard {
    type Target = ThreadPool;

    fn deref(&self) -> &Self::Target {
        self.thread_pool
            .as_ref()
            .expect("Value exists until `Drop`; qed")
    }
}

impl Drop for ThreadPoolGuard {
    fn drop(&mut self) {
        let (mutex, cvar) = &*self.inner;
        let mut inner = mutex.lock();
        inner.thread_pools.push(
            self.thread_pool
                .take()
                .expect("Happens only once in `Drop`; qed"),
        );
        cvar.notify_one();
    }
}

/// Thread pool manager.
///
/// This abstraction wraps a set of thread pools and allows to use them one at a time.
///
/// For example on machine with 64 logical cores and 4 NUMA nodes it would be recommended to create
/// 4 thread pools with 16 threads each, which would mean work done within thread pool is tied to
/// that thread pool.
#[derive(Debug, Clone)]
pub struct ThreadPoolManager {
    inner: Arc<(Mutex<Inner>, Condvar)>,
}

impl ThreadPoolManager {
    /// Create new thread pool manager by instantiating `thread_pools` thread pools using
    /// `create_thread_pool`.
    ///
    /// `create_thread_pool` takes one argument `thread_pool_index`.
    pub fn new<C>(
        create_thread_pool: C,
        thread_pools: NonZeroUsize,
    ) -> Result<Self, ThreadPoolBuildError>
    where
        C: FnMut(usize) -> Result<ThreadPool, ThreadPoolBuildError>,
    {
        let inner = Inner {
            thread_pools: (0..thread_pools.get())
                .map(create_thread_pool)
                .collect::<Result<Vec<_>, _>>()?,
        };

        Ok(Self {
            inner: Arc::new((Mutex::new(inner), Condvar::new())),
        })
    }

    /// Get one of inner thread pools, will block until one is available if needed
    #[must_use]
    pub fn get_thread_pool(&self) -> ThreadPoolGuard {
        let (mutex, cvar) = &*self.inner;
        let mut inner = mutex.lock();

        let thread_pool = inner.thread_pools.pop().unwrap_or_else(|| {
            cvar.wait(&mut inner);

            inner.thread_pools.pop().expect(
                "Guaranteed by parking_lot's API to happen when thread pool is inserted; qed",
            )
        });

        ThreadPoolGuard {
            inner: Arc::clone(&self.inner),
            thread_pool: Some(thread_pool),
        }
    }
}
